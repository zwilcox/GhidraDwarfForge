#!/usr/bin/env python3
"""Compare installed production digests with Python and GNU tools on owned copies.

This tests bytes/checksums, not an attachment transaction or stable file identity.
The optional sparse >2 GiB input is removed after testing, including on failure.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlparse
import zlib


REPOSITORY = Path(__file__).resolve().parents[3]
TOOLS = {
    "x86_64": "objcopy",
    "aarch64": "aarch64-linux-gnu-objcopy",
    "arm32": "arm-linux-gnueabihf-objcopy",
    "mips32be": "mips-linux-gnu-objcopy",
    "mips32le": "mipsel-linux-gnu-objcopy",
}
ELF_PROFILES = {
    "x86_64": (2, 1, 62),
    "aarch64": (2, 1, 183),
    "arm32": (1, 1, 40),
    "mips32be": (1, 2, 8),
    "mips32le": (1, 1, 8),
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def python_digests(path):
    sha = hashlib.sha256()
    crc = 0
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            sha.update(chunk)
            crc = zlib.crc32(chunk, crc)
            count += len(chunk)
    return {"sha256": sha.hexdigest(), "crc32": f"{crc:08x}", "bytes": count}


def run(command, prefix, *, timeout=180):
    result = subprocess.run([str(part) for part in command], capture_output=True,
                            text=True, timeout=timeout)
    prefix.with_suffix(".command.json").write_text(json.dumps(list(map(str, command))))
    prefix.with_suffix(".stdout").write_text(result.stdout)
    prefix.with_suffix(".stderr").write_text(result.stderr)
    require(result.returncode == 0, f"command failed ({result.returncode}): {prefix}")
    require(not result.stderr, f"unexpected stderr: {prefix}")
    return result.stdout


def java_digests(paths, jar, classes, prefix):
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp",
                  os.pathsep.join([str(jar), str(classes)]),
                  "ghidradwarfforge.output.FileDigestsProbe", *paths], prefix)
    lines = output.splitlines()
    require(len(lines) == 3 + len(paths), "unexpected digest adapter output")
    require(lines[0].startswith("digest-class-source="), "missing production class origin")
    origin = urlparse(lines[0].split("=", 1)[1])
    require(origin.scheme == "file" and Path(unquote(origin.path)).resolve() == jar,
            "digest helper was not loaded from the installed JAR")
    require(lines[1].startswith("java-version="), "missing Java version")
    require(lines[2].startswith("max-heap=") and
            int(lines[2].split("=", 1)[1]) <= 64 * 1024 * 1024, "unbounded Java heap")
    results = []
    for index, line in enumerate(lines[3:]):
        match = re.fullmatch(r"digest=(\d+) sha256=([0-9a-f]{64}) "
                             r"crc32=([0-9a-f]{8}) bytes=(\d+)", line)
        require(match is not None and int(match[1]) == index, "invalid digest record")
        results.append({"sha256": match[2], "crc32": match[3], "bytes": int(match[4])})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=TOOLS)
    parser.add_argument("--fixture-root", type=Path, default=REPOSITORY / "build/fixtures")
    parser.add_argument("--export-logs", type=Path,
                        default=REPOSITORY / "build/test-results/headless-symbol-export")
    parser.add_argument("--large", action="store_true")
    args = parser.parse_args()
    result_root = REPOSITORY / "build/test-results/file-digests"
    result_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f"{args.target}.", dir=result_root))
    print(f"file-digests-results={work}", flush=True)
    jars = list((args.module / "lib").glob("GhidraDwarfForge.jar"))
    require(len(jars) == 1, "missing installed production JAR")
    jar = jars[0].resolve(strict=True)
    classes = work / "classes"
    classes.mkdir()
    jar_hash = python_digests(jar)
    run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", jar, "-d", classes,
         REPOSITORY / "src/test/java/ghidradwarfforge/output/FileDigestsProbe.java"],
        work / "compile")
    objcopy = TOOLS[args.target]
    run([objcopy, "--version"], work / "objcopy-version")
    fixture = args.fixture_root.resolve(strict=True) / args.target
    paths = [fixture / f"semantic.{role}.{suffix}"
             for role in ("exec", "pie", "exec.no-build-id")
             for suffix in ("stripped", "ghidra-forge.dbg", "ghidra-forge.dbg.c")]
    expected = [python_digests(path) for path in paths]
    mtimes = [path.stat().st_mtime_ns for path in paths]
    require(java_digests(paths, jar, classes, work / "first") == expected,
            "Java/Python digest mismatch")
    require(java_digests(paths, jar, classes, work / "repeat") == expected,
            "repeat digest mismatch")
    cases = []
    export_reports = []
    for index, role in enumerate(("exec", "pie", "exec.no-build-id")):
        original, sidecar = paths[index * 3:index * 3 + 2]
        log = args.export_logs / f"{args.target}.{role}.log"
        # Later regression helpers reuse the primary log names. Retain the
        # exact report generation whose paths/hashes this oracle checks.
        transcript_bytes = log.read_bytes()
        retained_log = work / f"{role}.export.log"
        retained_log.write_bytes(transcript_bytes)
        transcript = transcript_bytes.decode("utf-8", errors="strict")
        export_reports.append({"role": role, "source_log": str(log),
            "retained_log": str(retained_log),
            "sha256": hashlib.sha256(transcript_bytes).hexdigest()})
        reports = [json.JSONDecoder().raw_decode(line.split("GhidraDwarfForge report: ", 1)[1])[0]
                   for line in transcript.splitlines() if "GhidraDwarfForge report: " in line]
        require(len(reports) == 1 and reports[0]["status"] in ("SUCCESS", "PARTIAL") and
                reports[0]["failure"] is None, "missing successful production report")
        production_script = args.module.resolve() / "ghidra_scripts/GhidraDwarfForge.java"
        require(transcript.count("SCRIPT: " + str(production_script)) == 1,
                "report did not use the installed production script")
        for offset, name in enumerate(("input", "output", "source")):
            artifacts = reports[0]["artifacts"]
            require(Path(artifacts[name + "Path"]) == paths[index * 3 + offset] and
                    artifacts[name + "Sha256"] == expected[index * 3 + offset]["sha256"],
                    "production report path/SHA differs from independently observed artifact")
        case = work / role
        case.mkdir()
        private_debug = case / "private forge.debug"
        shutil.copyfile(sidecar, private_debug)
        attached = case / "attached.elf"
        run([objcopy, f"--add-gnu-debuglink={private_debug}", original, attached],
            case / "objcopy-attach")
        attached_before = python_digests(attached)
        raw = case / "debuglink.bin"
        run([objcopy, f"--dump-section=.gnu_debuglink={raw}", attached,
             case / "dump-copy.elf"], case / "objcopy-dump")
        with original.open("rb") as stream:
            ident = stream.read(20)
        require(ident[:4] == b"\x7fELF" and ident[4] in (1, 2) and ident[5] in (1, 2),
                "invalid original ELF identity")
        order = "little" if ident[5] == 1 else "big"
        require((ident[4], ident[5], int.from_bytes(ident[18:20], order)) ==
                ELF_PROFILES[args.target], "fixture ELF identity does not match target label")
        name = private_debug.name.encode("utf-8") + b"\0"
        crc = int(expected[index * 3 + 1]["crc32"], 16)
        payload = name + bytes((-len(name)) % 4) + crc.to_bytes(4, order)
        require(raw.read_bytes() == payload, "GNU debuglink payload/CRC mismatch")
        require(python_digests(attached) == attached_before, "dump changed attached copy")
        require(python_digests(private_debug) == expected[index * 3 + 1],
                "GNU tool changed private sidecar")
        cases.append({"role": role, "elf_class": ident[4], "byte_order": order,
                      "sidecar": expected[index * 3 + 1], "gnu_payload_hex": payload.hex()})
    require([python_digests(path) for path in paths] == expected, "fixture bytes changed")
    require([path.stat().st_mtime_ns for path in paths] == mtimes, "fixture mtimes changed")
    large_result = None
    if args.large:
        large = work / "large.sparse"
        length = (1 << 31) + 131139
        markers = {0: b"begin\x00\xff", 65535: b"buffer boundary", (1 << 31) - 17: b"signed32",
                   (1 << 31) + 65536: b"above32", length - 6: b"tail\xff\x01"}
        try:
            with large.open("xb") as stream:
                stream.truncate(length)
                for offset, marker in markers.items():
                    stream.seek(offset)
                    stream.write(marker)
            before = large.stat()
            oracle = python_digests(large)
            require(oracle["bytes"] == length and length > (1 << 31), "wrong large input size")
            (work / "large-layout.json").write_text(json.dumps({"length": length,
                "markers": {str(k): v.hex() for k, v in markers.items()},
                "allocated_blocks": getattr(before, "st_blocks", None)}, indent=4) + "\n")
            require(java_digests([large], jar, classes, work / "large-first") == [oracle],
                    "large Java/Python digest mismatch")
            require(java_digests([large], jar, classes, work / "large-repeat") == [oracle],
                    "large repeated digest mismatch")
            sha_output = run(["sha256sum", large], work / "large-gnu-sha256")
            require(sha_output.split()[0] == oracle["sha256"], "GNU SHA-256 mismatch")
            require(python_digests(large) == oracle and large.stat().st_mtime_ns == before.st_mtime_ns,
                    "large input changed")
            large_result = oracle
        finally:
            large.unlink(missing_ok=True)
    require(python_digests(jar) == jar_hash, "installed JAR changed")
    (work / "result.json").write_text(json.dumps({"status": "PASS", "target": args.target,
        "jar": str(jar), "jar_digests": jar_hash, "cases": cases, "inputs": list(map(str, paths)),
        "input_digests": expected, "large": large_result, "export_reports": export_reports,
        "scope": "observed bytes only; no identity, snapshot or attachment transaction"},
        indent=4) + "\n")
    print(f"file-digests-{args.target}=PASS", flush=True)


if __name__ == "__main__":
    main()

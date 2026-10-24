#!/usr/bin/env python3
"""Read current export reports through the installed helper, without attaching files."""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlparse


REPOSITORY = Path(__file__).resolve().parents[3]
PROFILES = {
    "x86_64": ("x86_64", 64, "LITTLE_ENDIAN", 2, 1, 62),
    "aarch64": ("aarch64", 64, "LITTLE_ENDIAN", 2, 1, 183),
    "arm32": ("arm", 32, "LITTLE_ENDIAN", 1, 1, 40),
    "mips32be": ("mips", 32, "BIG_ENDIAN", 1, 2, 8),
    "mips32le": ("mipsel", 32, "LITTLE_ENDIAN", 1, 1, 8),
}
GSON_SHA256 = "c96d60551331a196dac54b745aa642cd078ef89b6f267146b705f2c2cbef052d"
CARDINALITIES = {
    "functionsFailed": "failedFunctions", "functionsSkipped": "skippedFunctions",
    "omittedLocationRanges": "omittedLocations", "unsupportedConstructs": "unsupportedConstructs",
    "diagnostics": "diagnostics",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def snapshot(path):
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mtime_ns": path.stat().st_mtime_ns}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate decoded JSON key")
        result[key] = value
    return result


def integer(value):
    require(re.fullmatch(r"0|[1-9][0-9]*", value) is not None, "noncanonical report integer")
    return int(value)


def forbidden_number(value):
    raise AssertionError("unexpected floating/nonfinite report value: " + value)


DECODER = json.JSONDecoder(object_pairs_hook=unique_object, parse_int=integer,
                           parse_float=forbidden_number, parse_constant=forbidden_number)


def claims(report):
    require(report["schemaVersion"] == 1 and report["status"] in ("SUCCESS", "PARTIAL"),
            "not a completed current report")
    require(report["failure"] is None and report["validation"] == {"status": "NOT_RUN"},
            "unexpected failure or validator attestation")
    require("functionStaticVariables" in report["counts"], "unsupported historical shape")
    for count, inventory in CARDINALITIES.items():
        require(report["counts"][count] == len(report[inventory]), "report cardinality mismatch")
    partial = any(report[inventory] for inventory in CARDINALITIES.values())
    require(report["status"] == ("PARTIAL" if partial else "SUCCESS"), "report status mismatch")
    return {"schemaVersion": report["schemaVersion"], "status": report["status"],
            "target": report["target"], "artifacts": report["artifacts"],
            "counts": report["counts"], "validationStatus": report["validation"]["status"],
            "libdwarfVersion": report["native"]["libdwarfVersion"]}


def run(command, prefix):
    Path(str(prefix) + ".command.json").write_text(json.dumps(list(map(str, command))))
    try:
        result = subprocess.run(list(map(str, command)), text=True, capture_output=True,
                                timeout=45, env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired as failure:
        for name, output in (("stdout", failure.stdout), ("stderr", failure.stderr)):
            data = output if isinstance(output, bytes) else (output or "").encode("utf-8")
            Path(str(prefix) + "." + name).write_bytes(data)
        Path(str(prefix) + ".timeout").write_text("Command exceeded 45 seconds\n")
        raise
    Path(str(prefix) + ".stdout").write_text(result.stdout)
    Path(str(prefix) + ".stderr").write_text(result.stderr)
    require(result.returncode == 0, f"command failed ({result.returncode}): {prefix}")
    require(not result.stderr, f"unexpected diagnostic: {prefix}")
    return result.stdout


def probe(paths, jar, gson, classes, prefix, expected=None):
    before = {str(path): snapshot(path) for path in paths}
    arguments = paths if expected is not None else ["--expect-rejection", *paths]
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp",
                  os.pathsep.join(map(str, (jar, gson, classes))),
                  "ghidradwarfforge.output.ExportReportClaimsProbe", *arguments], prefix)
    require({str(path): snapshot(path) for path in paths} == before, "reader changed a report")
    lines = output.splitlines()
    require(len(lines) == 4 + len(paths), "unexpected report adapter output")
    for index, (name, archive) in enumerate((("claims", jar), ("gson", gson))):
        require(lines[index].startswith(name + "-class-source="), "missing class origin")
        origin = urlparse(lines[index].split("=", 1)[1])
        require(origin.scheme == "file" and Path(unquote(origin.path)).resolve() == archive,
                "helper/dependency was not loaded from its installed JAR")
    require(re.fullmatch(r"java-version=21(?:[.+-].*)?", lines[2]) is not None,
            "reader oracle requires actual Java 21")
    require(lines[3].startswith("max-heap=") and int(lines[3].split("=", 1)[1]) <= 64 * 1024 * 1024,
            "unbounded reader heap")
    if expected is not None:
        require(all(line.startswith("claims-base64=") for line in lines[4:]), "missing returned claims")
        observed = [DECODER.decode(base64.b64decode(line.split("=", 1)[1], validate=True)
                    .decode("utf-8", errors="strict")) for line in lines[4:]]
        require(observed == expected, "reported claims changed during reading")
        return None
    diagnostics = []
    for line in lines[4:]:
        match = re.fullmatch(r"rejected=([A-Za-z0-9_.$]+) diagnostic=([A-Za-z0-9+/=]+) terminal=([A-Z-]+)", line)
        require(match is not None, "malformed report returned completed claims")
        diagnostic = base64.b64decode(match[2], validate=True).decode("utf-8", errors="strict")
        require(diagnostic.strip(), "empty rejection diagnostic")
        diagnostics.append({"exception": match[1], "message": diagnostic, "terminal_status": match[3]})
    return diagnostics


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=PROFILES)
    parser.add_argument("--producer-module", type=Path,
                        help="explicit earlier exporter installation for retained-report regression")
    parser.add_argument("--fixture-root", type=Path, default=REPOSITORY / "build/fixtures")
    parser.add_argument("--export-logs", type=Path,
                        default=REPOSITORY / "build/test-results/headless-symbol-export")
    args = parser.parse_args()
    module = args.module.resolve(strict=True)
    producer = (args.producer_module or args.module).resolve(strict=True)
    jar = (module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    producer_jar = (producer / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    gson = (module.parent.parent / "Framework/Generic/lib/gson-2.9.0.jar").resolve(strict=True)
    require(snapshot(gson)["sha256"] == GSON_SHA256, "unexpected supplied Gson revision")
    result_root = REPOSITORY / "build/test-results/export-report-claims"
    result_root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=args.target + ".", dir=result_root))
    print(f"export-report-claims-results={work}", flush=True)
    classes = work / "classes"
    classes.mkdir()
    run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp",
         os.pathsep.join(map(str, (jar, gson))), "-d", classes,
         REPOSITORY / "src/test/java/ghidradwarfforge/output/ExportReportClaimsProbe.java"],
        work / "compile")
    protected = {str(path): snapshot(path) for path in (jar, producer_jar, gson)}
    reports, expected, sources, retained_artifacts = [], [], [], []
    fixture = args.fixture_root.resolve(strict=True) / args.target
    for role in ("exec", "pie", "exec.no-build-id"):
        log = args.export_logs / f"{args.target}.{role}.log"
        transcript_bytes = log.read_bytes()
        retained_log = work / (role + ".export.log")
        retained_log.write_bytes(transcript_bytes)
        transcript = transcript_bytes.decode("utf-8", errors="strict")
        script = producer / "ghidra_scripts/GhidraDwarfForge.java"
        require(transcript.count("SCRIPT: " + str(script)) == 1,
                "report did not use the stated installed production script")
        bodies = [line.split("GhidraDwarfForge report: ", 1)[1]
                  for line in transcript.splitlines() if "GhidraDwarfForge report: " in line]
        require(len(bodies) == 1, "expected one production report")
        report, end = DECODER.raw_decode(bodies[0])
        require(bodies[0][end:].strip() == "(GhidraScript)", "unexpected transcript suffix")
        profile = PROFILES[args.target]
        require(report["target"] == dict(zip(("architecture", "addressBits", "byteOrder"), profile[:3])),
                "report target profile mismatch")
        raw = bodies[0][:end].encode("utf-8", errors="strict")
        destination = work / (role + ".json")
        destination.write_bytes(raw)
        reports.append(destination)
        expected.append(claims(report))
        for name, suffix in (("input", "stripped"), ("output", "ghidra-forge.dbg"),
                             ("source", "ghidra-forge.dbg.c")):
            path = fixture / f"semantic.{role}.{suffix}"
            before = snapshot(path)
            protected[str(path)] = before
            retained = work / f"{role}.{name}.bytes"
            shutil.copyfile(path, retained)
            retained_snapshot = snapshot(retained)
            require(retained_snapshot["sha256"] == before["sha256"], "retained fixture differs")
            retained_artifacts.append({"original": str(path), "retained": str(retained),
                                       "snapshot": retained_snapshot})
            require(report["artifacts"][name + "Path"] == str(path) and
                    report["artifacts"][name + "Sha256"].lower() == before["sha256"],
                    "source report is not bound to the stated fixture")
            if name == "input":
                with path.open("rb") as stream:
                    ident = stream.read(20)
                require(len(ident) == 20 and ident[:4] == b"\x7fELF" and
                        (ident[4], ident[5]) == profile[3:5], "fixture class/order mismatch")
                require(int.from_bytes(ident[18:20], "little" if ident[5] == 1 else "big") == profile[5],
                        "fixture machine mismatch")
        protected[str(log)] = snapshot(log)
        protected[str(script)] = snapshot(script)
        sources.append({"role": role, "log": str(log), "log_snapshot": snapshot(log),
                        "retained_log": str(retained_log), "retained_log_snapshot": snapshot(retained_log),
                        "report": str(destination), "report_snapshot": snapshot(destination)})
    probe(reports, jar, gson, classes, work / "first", expected)
    probe(reports, jar, gson, classes, work / "repeat", expected)

    base = DECODER.decode(reports[0].read_text())
    positives, positive_claims = [], []
    # A FIFO without a writer would block an accidental artifact open. The
    # operation reads only the JSON file; foreign and nonexistent paths remain text.
    fifo = work / "artifact-must-not-be-opened.fifo"
    os.mkfifo(fifo, 0o600)
    try:
        opaque = copy.deepcopy(base)
        opaque["artifacts"].update(inputPath=str(fifo),
            outputPath="C:\\absent\\\u00e9\\..\\literal \U0001f642.dbg",
            sourcePath=str(work / "absent-parent/../missing source.dbg.c"),
            inputSha256="A" * 64, outputSha256="B" * 64, sourceSha256="C" * 64)
        reordered = dict(reversed(list(opaque.items())))
        reordered["counts"] = dict(reversed(list(reordered["counts"].items())))
        for name, value in (("opaque-paths", opaque), ("reordered", reordered)):
            path = work / (name + ".json")
            path.write_bytes(encoded(value))
            positives.append(path)
            positive_claims.append(claims(value))
        probe(positives, jar, gson, classes, work / "opaque-claims", positive_claims)
        require(fifo.is_fifo() and not (work / "absent-parent").exists(), "referenced artifact changed")
    finally:
        # The evidence uploader must never try to read a retained FIFO.
        fifo.unlink(missing_ok=True)

    negatives = {}
    raw = encoded(base)
    negatives["duplicate-root"] = raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1', 1)
    negatives["escaped-duplicate-key"] = raw.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schema\\u0056ersion":1', 1)
    negatives["decimal-integer"] = raw.replace(b'"schemaVersion":1', b'"schemaVersion":1.0', 1)
    negatives["quoted-integer"] = raw.replace(b'"schemaVersion":1', b'"schemaVersion":"1"', 1)
    negatives["uppercase-null"] = raw.replace(b'"failure":null', b'"failure":NULL', 1)
    negatives["trailing-root"] = raw + b' {}'
    negatives["utf8-bom"] = b'\xef\xbb\xbf' + raw
    negatives["malformed-utf8"] = raw.replace(b'"status":', b'"\xffstatus":', 1)
    for name, value in (("raw-newline", b'"bad\nname"'), ("raw-control", b'"bad\x01name"'),
                        ("unpaired-surrogate", b'"bad\\ud800name"'),
                        ("escaped-apostrophe", b'"bad\\\'name"')):
        negatives[name] = raw.replace(b'"architecture":"' + base["target"]["architecture"].encode() + b'"',
                                      b'"architecture":' + value, 1)
    mutations = {
        "unknown-schema": lambda value: value.update(schemaVersion=2),
        "missing-static-count": lambda value: value["counts"].pop("functionStaticVariables"),
        "unknown-field": lambda value: value["target"].update(unrecognized=1),
        "null-target": lambda value: value.update(target=None),
        "wrong-cardinality": lambda value: value["counts"].update(diagnostics=len(value["diagnostics"]) + 1),
        "false-validator-claim": lambda value: value["validation"].update(status="PASSED"),
        "invalid-hash": lambda value: value["artifacts"].update(inputSha256="x" * 64),
    }
    for name, mutate in mutations.items():
        changed = copy.deepcopy(base)
        mutate(changed)
        negatives[name] = encoded(changed)
    for status in ("CANCELLED", "FATAL"):
        terminal = copy.deepcopy(base)
        terminal.update(status=status, target=None, artifacts=None, counts=None,
                        native={"libdwarfVersion": None}, failure={"type": "fixture", "message": "fixture"})
        for key in ("sections", *CARDINALITIES.values()):
            terminal[key] = []
        negatives[status.lower() + "-no-claims"] = encoded(terminal)
        terminal["failure"] = None
        negatives[status.lower() + "-malformed-terminal"] = encoded(terminal)
    paths = []
    for name, data in negatives.items():
        require(data != raw, "negative mutation did not change its input: " + name)
        path = work / (name + ".json")
        path.write_bytes(data)
        paths.append(path)
    rejections = probe(paths, jar, gson, classes, work / "rejections")
    rejected = dict(zip(negatives, rejections))
    for status in ("CANCELLED", "FATAL"):
        result = rejected[status.lower() + "-no-claims"]
        require(result["exception"] == "ghidradwarfforge.output.ExportReportClaims$TerminalReportException" and
                result["terminal_status"] == status, "valid terminal report did not get typed no-claims rejection")
        malformed = rejected[status.lower() + "-malformed-terminal"]
        require(malformed["exception"] != "ghidradwarfforge.output.ExportReportClaims$TerminalReportException" and
                malformed["terminal_status"] == "-", "malformed terminal was treated as structurally valid")
    for name in ("missing-static-count", "unknown-schema"):
        require(rejected[name]["exception"] ==
                "ghidradwarfforge.output.ExportReportClaims$UnsupportedReportShapeException",
                "unsupported historical shape/version was not distinguished")
    require({name: snapshot(Path(name)) for name in protected} == protected,
            "reader/oracle changed protected bytes or mtimes")
    require(all(snapshot(Path(item["retained"])) == item["snapshot"] for item in retained_artifacts),
            "retained fixture evidence changed")
    (work / "result.json").write_text(json.dumps({"status": "PASS", "target": args.target,
        "reader_module": str(module), "producer_module": str(producer),
        "same_reader_export_installation": module == producer,
        "fifo_no_open_control": {"path": str(fifo), "removed": not fifo.exists()},
        "protected": protected, "sources": sources, "retained_artifacts": retained_artifacts,
        "preservation_scope": "before/after this oracle; later regression steps may reuse fixture/log paths",
        "opaque_positive_cases": len(positives),
        "rejections": rejected,
        "scope": "reported claims only; no artifact access, identity or attachment eligibility"}, indent=4) + "\n")
    print(f"export-report-claims-{args.target}=PASS", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Compare installed build-ID observations with GNU tools on owned fixture copies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
from urllib.parse import unquote, urlparse


REPOSITORY = Path(__file__).resolve().parents[3]
PROFILES = {
    "x86_64": (2, 1, 62, "objcopy"),
    "aarch64": (2, 1, 183, "aarch64-linux-gnu-objcopy"),
    "arm32": (1, 1, 40, "arm-linux-gnueabihf-objcopy"),
    "mips32be": (1, 2, 8, "mips-linux-gnu-objcopy"),
    "mips32le": (1, 1, 8, "mipsel-linux-gnu-objcopy"),
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def snapshot(path):
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mtime_ns": path.stat().st_mtime_ns}


def run(command, prefix, *, warning=False):
    result = subprocess.run(list(map(str, command)), text=True, capture_output=True, timeout=90,
                            env={**os.environ, "LC_ALL": "C"})
    Path(str(prefix) + ".command.json").write_text(json.dumps(list(map(str, command))))
    Path(str(prefix) + ".stdout").write_text(result.stdout)
    Path(str(prefix) + ".stderr").write_text(result.stderr)
    require(result.returncode == 0, f"command failed ({result.returncode}): {prefix}")
    if warning:
        require("Warning:" in result.stderr, f"GNU did not diagnose malformed notes: {prefix}")
    else:
        require(not result.stderr, f"unexpected diagnostic: {prefix}")
    return result.stdout


def gnu_ids(path, prefix, *, warning=False):
    output = run(["readelf", "-n", path], prefix, warning=warning)
    return re.findall(r"Build ID: ([0-9a-f]+)", output)


def sections(data):
    """Locate ordinary source-built fixture sections, independently of note parsing."""
    require(data[:4] == b"\x7fELF" and data[4] in (1, 2) and data[5] in (1, 2), "invalid ELF")
    wide = data[4] == 2
    order = "<" if data[5] == 1 else ">"
    offset = struct.unpack_from(order + ("Q" if wide else "I"), data, 40 if wide else 32)[0]
    stride, count, names = struct.unpack_from(order + "HHH", data, 58 if wide else 46)
    require(offset and 0 < count < 0xff00 and 0 < names < count,
            "oracle requires ordinary named fixture section tables")
    fmt = order + ("IIQQQQIIQQ" if wide else "IIIIIIIIII")
    require(stride >= struct.calcsize(fmt) and offset + stride * count <= len(data), "bad table")
    entries = [struct.unpack_from(fmt, data, offset + index * stride) for index in range(count)]
    strings = entries[names]
    table = data[strings[4]:strings[4] + strings[5]]
    result = {}
    for index, entry in enumerate(entries[1:], 1):
        end = table.find(b"\0", entry[0])
        require(end >= entry[0], "bad fixture section name")
        name = table[entry[0]:end].decode("ascii")
        require(name not in result, "duplicate fixture section name")
        result[name] = {"header": offset + index * stride, "type": entry[1],
                        "offset": entry[4], "size": entry[5]}
    return order, wide, result


def probe(paths, jar, classes, prefix, expected, *, counts=None):
    inputs = paths[1:] if paths[0] == "--expect-rejection" else paths
    before = {str(path): snapshot(path) for path in inputs}
    output = run([os.environ.get("JAVA", "java"), "-Xmx64m", "-cp",
                  os.pathsep.join([str(jar), str(classes)]),
                  "ghidradwarfforge.elf.ElfBuildIdProbe", *paths], prefix)
    require({str(path): snapshot(path) for path in inputs} == before,
            "observation changed an input's bytes or mtime")
    lines = output.splitlines()
    for index, kind in enumerate(("build-id", "elf-image")):
        require(lines[index].startswith(kind + "-class-source="), "missing class origin")
        origin = urlparse(lines[index].split("=", 1)[1])
        require(origin.scheme == "file" and Path(unquote(origin.path)).resolve() == jar,
                "observer or ELF reader not loaded from installed JAR")
    require(lines[2].startswith("java-version="), "missing Java version")
    require(lines[3].startswith("max-heap=") and int(lines[3].split("=", 1)[1]) <= 64 * 1024 * 1024,
            "unbounded observer heap")
    if paths[0] == "--expect-rejection":
        require(len(lines) == 6 and lines[4] in ("rejected=java.io.IOException",
                "rejected=java.lang.IllegalArgumentException") and
                lines[5].startswith("diagnostic-base64="), "malformed input was not rejected")
        return
    require(len(lines) == 4 + len(paths) + len(paths) // 2, "unexpected observer output")
    values = []
    for index, line in enumerate(lines[4:4 + len(paths)]):
        match = re.fullmatch(r"observation=(\d+) hex=(-|[0-9a-f]+) notes=(\d+)", line)
        require(match is not None and int(match[1]) == index, "bad observation record")
        value, count = match[2], int(match[3])
        require((value == "-") == (count == 0), "absence/occurrence disagreement")
        if counts is not None:
            require(count == counts[index], "wrong physical occurrence count")
        values.append(value)
    require(values == expected, f"observer/GNU ID disagreement: {prefix}")
    for index, line in enumerate(lines[4 + len(paths):]):
        left, right = values[index * 2:index * 2 + 2]
        relation = ("ABSENT_BOTH" if left == right == "-" else
                    "MISSING_FROM_ORIGINAL" if left == "-" else
                    "MISSING_FROM_SIDECAR" if right == "-" else
                    "SAME_BUILD_ID" if left == right else "DIFFERENT_BUILD_IDS")
        require(line == f"relation={index} {relation}", "incorrect observed-ID relationship")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path)
    parser.add_argument("target", choices=PROFILES)
    parser.add_argument("--fixture-root", type=Path, default=REPOSITORY / "build/fixtures")
    args = parser.parse_args()
    results = REPOSITORY / "build/test-results/elf-build-id"
    results.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=args.target + ".", dir=results))
    print(f"elf-build-id-results={work}", flush=True)
    jar = (args.module / "lib/GhidraDwarfForge.jar").resolve(strict=True)
    classes = work / "classes"
    classes.mkdir()
    run([os.environ.get("JAVAC", "javac"), "--release", "21", "-cp", jar, "-d", classes,
         REPOSITORY / "src/test/java/ghidradwarfforge/elf/ElfBuildIdProbe.java"], work / "compile")
    run(["readelf", "--version"], work / "gnu-version")
    elf_class, byte_order, machine, objcopy = PROFILES[args.target]
    fixture = args.fixture_root.resolve(strict=True) / args.target
    paths = [fixture / f"semantic.{role}.{suffix}" for role in ("exec", "pie", "exec.no-build-id")
             for suffix in ("stripped", "ghidra-forge.dbg")]
    protected = [jar, *paths, *(Path(str(path) + ".c") for path in paths[1::2])]
    before = {str(path): snapshot(path) for path in protected}
    expected = []
    for index, path in enumerate(paths):
        data = path.read_bytes()
        order = "little" if data[5] == 1 else "big"
        require((data[4], data[5], int.from_bytes(data[18:20], order)) ==
                (elf_class, byte_order, machine), "mislabeled target fixture")
        ids = set(gnu_ids(path, work / f"original-{index}"))
        require(len(ids) == (0 if index >= 4 else 1), "unexpected original GNU IDs")
        expected.append(next(iter(ids), "-"))
    require(expected[0] == expected[1] and expected[2] == expected[3] and
            expected[0] != expected[2], "fixture pair IDs or mismatch control invalid")
    probe(paths, jar, classes, work / "pairs", expected)
    probe(paths, jar, classes, work / "repeat", expected)
    probe([paths[0], paths[3], paths[0], paths[4], paths[4], paths[1]], jar, classes,
          work / "relationships", [expected[i] for i in (0, 3, 0, 4, 4, 1)])
    original = paths[0].read_bytes()
    order, wide, table = sections(original)
    build_id = table[".note.gnu.build-id"]
    require(build_id["type"] == 7, "fixture build ID section is not SHT_NOTE")
    note = original[build_id["offset"]:build_id["offset"] + build_id["size"]]
    name_size, descriptor_size, note_type = struct.unpack_from(order + "III", note)
    require(name_size == 4 and note_type == 3 and note[12:16] == b"GNU\0" and descriptor_size > 0,
            "unexpected original GNU note encoding")
    owned = []

    def retain(name, data):
        path = work / name
        path.write_bytes(data)
        owned.append(path)
        return path

    # The matched sidecar has no PT_DYNAMIC. GNU readelf tries to resolve that
    # segment by section name in a nameless dynamic original, producing an
    # unrelated error; use the actual sidecar for a quiet typed-note oracle.
    nameless = bytearray(paths[1].read_bytes())
    struct.pack_into(order + "H", nameless, 62 if wide else 50, 0)
    nameless_path = retain("nameless.elf", nameless)
    sectionless = bytearray(original)
    struct.pack_into(order + ("Q" if wide else "I"), sectionless, 40 if wide else 32, 0)
    struct.pack_into(order + "HH", sectionless, 60 if wide else 48, 0, 0)
    sectionless_path = retain("sectionless.elf", sectionless)
    renamed = work / "renamed.elf"
    run([objcopy, "--rename-section", ".note.gnu.build-id=.note.observed-identity",
         paths[0], renamed], work / "rename-note")
    owned.append(renamed)
    for name, path in (("nameless", nameless_path), ("sectionless", sectionless_path),
                       ("renamed", renamed)):
        require(set(gnu_ids(path, work / f"{name}-gnu")) == {expected[0]}, "GNU lost variant ID")
        probe([path, paths[1]], jar, classes, work / f"{name}-probe", [expected[0], expected[1]])

    decoy = bytearray(original)
    decoy[build_id["offset"] + 12:build_id["offset"] + 16] = b"XYZ\0"
    decoy_path = retain("named-decoy.elf", decoy)
    require(not gnu_ids(decoy_path, work / "decoy-gnu"), "vendor decoy still recognized as GNU")
    probe([decoy_path, paths[1]], jar, classes, work / "decoy-probe", ["-", expected[1]])

    for name, payload, conflict in (("duplicate", note, False),
                                    ("conflicting", note[:16] + bytes([note[16] ^ 0x80]) + note[17:], True)):
        note_file = retain(name + ".note", payload)
        destination = work / (name + ".elf")
        section_name = ".note.forge." + name
        run([objcopy, f"--add-section={section_name}={note_file}", paths[0], destination],
            work / (name + "-objcopy"))
        data = bytearray(destination.read_bytes())
        _, _, added = sections(data)
        # Declare a typed note explicitly; do not depend on objcopy's naming heuristic.
        struct.pack_into(order + "I", data, added[section_name]["header"] + 4, 7)
        struct.pack_into(order + ("Q" if wide else "I"), data,
                         added[section_name]["header"] + (48 if wide else 32), 4)
        destination.write_bytes(data)
        owned.append(destination)
        ids = gnu_ids(destination, work / (name + "-gnu"))
        require(len(ids) == 2 and (len(set(ids)) == 2 if conflict else set(ids) == {expected[0]}),
                "GNU duplicate/conflict control invalid")
        if conflict:
            probe(["--expect-rejection", destination], jar, classes, work / (name + "-probe"), None)
        else:
            probe([destination, paths[1]], jar, classes, work / (name + "-probe"),
                  [expected[0], expected[1]], counts=[2, 1])

    malformed = bytearray(original)
    struct.pack_into(order + "I", malformed, build_id["offset"] + 4, 0xffffffff)
    malformed_path = retain("malformed.elf", malformed)
    gnu_ids(malformed_path, work / "malformed-gnu", warning=True)
    malformed_before = snapshot(malformed_path)
    probe(["--expect-rejection", malformed_path], jar, classes, work / "malformed-probe", None)
    require(snapshot(malformed_path) == malformed_before, "rejection modified its input")
    require({str(path): snapshot(path) for path in protected} == before, "protected input/JAR changed")
    (work / "result.json").write_text(json.dumps({"status": "PASS", "target": args.target,
        "jar": str(jar), "protected_inputs": before, "ids": expected,
        "owned_fixtures": {str(path): snapshot(path) for path in owned},
        "scope": "observed IDs/relationships only; no file identity or attachment eligibility"},
        indent=4) + "\n")
    print(f"elf-build-id-{args.target}=PASS", flush=True)


if __name__ == "__main__":
    main()

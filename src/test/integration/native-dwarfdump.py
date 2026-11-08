#!/usr/bin/env python3
"""Exercise the raw pinned checker on compiler-built ELF, without a shell launcher."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess


CONFIGURATION_SHA256 = "842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--compiler", required=True, type=Path)
    parser.add_argument("--clang-target")
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    compiler = args.compiler.resolve(strict=True)
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("strict_check", Path(__file__).with_name("check-dwarfdump.py"))
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    commands = []

    def run(label, command, env=None):
        command = [str(value) for value in command]
        result = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=120)
        (root / (label + ".stdout")).write_bytes(result.stdout)
        (root / (label + ".stderr")).write_bytes(result.stderr)
        commands.append({"label": label, "command": command, "exit": result.returncode})
        (root / "commands.json").write_text(json.dumps(commands, indent=4) + "\n", encoding="utf-8")
        return result

    source = root / "fixture.c"
    source.write_text("int fixture_global = 17;\nint fixture(int value) { return value + fixture_global; }\n", encoding="utf-8")
    artifact = root / "fixture.o"
    options = ["--target=" + args.clang_target] if args.clang_target else []
    result = run("compile", [compiler, *options, "-gdwarf-5", "-O0", "-c", source, "-o", artifact])
    require(result.returncode == 0 and not result.stderr, "ELF fixture compilation failed")
    original = artifact.read_bytes()
    require(original[:6] == b"\x7fELF\x02\x01", "fixture must be ELF64 little endian")
    require(struct.unpack_from("<H", original, 16)[0] == 1, "fixture must be compiler-built ET_REL")
    relocated = root / "relocated validator with spaces"
    shutil.copytree(bundle / "libexec", relocated / "libexec")
    shutil.copytree(bundle / "share", relocated / "share")
    executable = relocated / "libexec" / ("dwarfdump.exe" if os.name == "nt" else "dwarfdump")
    configuration = relocated / "share/dwarfdump/dwarfdump.conf"
    require(digest(configuration) == CONFIGURATION_SHA256, "unexpected checker configuration")
    before = {str(p.relative_to(relocated)): digest(p) for p in relocated.rglob("*") if p.is_file()}
    # The product passes the selected configuration directly. A hostile CWD
    # must not replace it; the Windows checker cannot find DLLs via MSYS PATH.
    (root / "dwarfdump.conf").write_bytes(b"\xff\n")
    environment = os.environ.copy()
    if os.name == "nt":
        environment["PATH"] = str(Path(os.environ["SystemRoot"]) / "System32")
        require(executable.read_bytes()[:2] == b"MZ", "checker is not native PE")
    version = run("version", [executable, "--version"], environment)
    require(version.returncode == 0 and not version.stderr and
        b"libdwarf 2.3.2 dwarfdump 2.3.2" in version.stdout, "unexpected checker version")
    command = [executable, "--file-name=" + str(configuration), "--no-follow-debuglink", "-ka", "-ki", "-kd"]
    valid = run("valid", [*command, artifact], environment)
    require(valid.returncode == 0 and not valid.stderr, "checker failed on compiler ELF")
    checker.validate_output(valid.stdout.decode("utf-8"))
    # Exercise Unicode ancestors separately from the already checked ASCII
    # baseline. No alternate basename or path fallback may select another file.
    unicode_root = root / "validator λ 字 with spaces"
    shutil.copytree(relocated, unicode_root)
    unicode_tool = unicode_root / "libexec" / executable.name
    unicode_configuration = unicode_root / "share/dwarfdump/dwarfdump.conf"
    unicode_artifact = unicode_root / "input λ 字.o"
    unicode_artifact.write_bytes(original)
    unicode_result = run("unicode-paths", [unicode_tool, "--file-name=" + str(unicode_configuration),
        "--no-follow-debuglink", "-ka", "-ki", "-kd", unicode_artifact], environment)
    require(unicode_result.returncode == 0 and not unicode_result.stderr,
        "native checker failed on explicit Unicode paths")
    checker.validate_output(unicode_result.stdout.decode("utf-8"))
    require(unicode_artifact.read_bytes() == original, "checker changed Unicode-path input")
    for relative, expected in before.items():
        require(digest(unicode_root / relative) == expected, "checker changed Unicode-path bundle")
    # Corrupt only the DWARF version, preserving the ELF and all section bounds.
    table = struct.unpack_from("<Q", original, 40)[0]
    count, names_index = struct.unpack_from("<HH", original, 60)
    entry_size = struct.unpack_from("<H", original, 58)[0]
    require(entry_size == 64 and 0 < names_index < count, "unexpected ELF section table")
    names_offset, names_size = struct.unpack_from("<QQ", original, table + names_index * 64 + 24)
    names = original[names_offset:names_offset + names_size]
    info = []
    for index in range(count):
        section = table + index * 64
        name_offset = struct.unpack_from("<I", original, section)[0]
        name = names[name_offset:].split(b"\x00", 1)[0]
        if name == b".debug_info":
            info.append(struct.unpack_from("<QQ", original, section + 24))
    require(len(info) == 1, "expected one .debug_info section")
    offset, size = info[0]
    require(size >= 12 and struct.unpack_from("<H", original, offset + 4)[0] == 5, "expected DWARF32 version 5")
    corrupted = bytearray(original)
    struct.pack_into("<H", corrupted, offset + 4, 0xffff)
    malformed = root / "invalid-version.o"
    malformed.write_bytes(corrupted)
    rejected = run("invalid-version", [*command, malformed], environment)
    require(b"DW_DLE_VERSION_STAMP_ERROR" in rejected.stdout + rejected.stderr,
        "malformed control did not reach the intended version check")
    try:
        checker.validate_output(rejected.stdout.decode("utf-8"))
    except checker.ValidationFailure:
        pass
    else:
        raise AssertionError("malformed DWARF passed strict output parsing")
    require(artifact.read_bytes() == original, "checker changed its valid input")
    require(malformed.read_bytes() == corrupted, "checker changed its malformed input")
    require(before == {str(p.relative_to(relocated)): digest(p) for p in relocated.rglob("*") if p.is_file()},
        "checker bundle changed")
    (root / "result.json").write_text(json.dumps({"status": "PASS", "host": os.name,
        "compiler": str(compiler), "compilerSha256": digest(compiler), "sourceSha256": digest(source),
        "fixtureSha256": digest(artifact), "malformedSha256": digest(malformed), "bundle": before,
        "scope": "Raw native checker: compiler ELF/DWARF5, relocated explicit config, Unicode paths, corrupt-version refusal; no attachment acceptance"}, indent=4) + "\n", encoding="utf-8")
    print("native-dwarfdump=PASS")


if __name__ == "__main__":
    main()

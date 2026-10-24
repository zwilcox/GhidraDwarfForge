#!/usr/bin/env python3
"""Prove the relocated validator uses its pinned configuration, not host defaults."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


CONFIGURATION_SHA256 = "842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log, cwd):
    command = [str(value) for value in command]
    log.with_suffix(log.suffix + ".command.json").write_text(json.dumps(command, indent=4) + "\n")
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=120)
    log.write_text(result.stdout)
    log.with_suffix(log.suffix + ".stderr").write_text(result.stderr)
    log.with_suffix(log.suffix + ".status").write_text(str(result.returncode) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    repository = Path(__file__).resolve().parents[3]
    results = repository / "build/test-results/dwarfdump-configuration"
    results.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="run.", dir=results))
    print("dwarfdump-configuration-results=" + str(work), flush=True)
    relative_files = ("bin/dwarfdump", "libexec/dwarfdump", "share/dwarfdump/dwarfdump.conf")
    hashes = {name: digest(bundle / name) for name in relative_files}
    require(hashes[relative_files[2]] == CONFIGURATION_SHA256, "wrong bundled configuration")
    relocated = work / "relocated validator with spaces"
    for name in relative_files:
        destination = relocated / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bundle / name, destination)
    launcher = relocated / relative_files[0]
    raw_tool = relocated / relative_files[1]
    configuration = relocated / relative_files[2]
    hostile = work / "hostile working directory"
    hostile.mkdir()
    (hostile / "dwarfdump.conf").write_bytes(b"\xff\n")
    source = work / "frames.s"
    source.write_text(".text\n.globl _start\n_start:\n.rept 3\n.cfi_startproc\n" +
        'nop\n.cfi_endproc\n.endr\n.section .note.GNU-stack,"",@progbits\n')
    artifact = work / "frames.dbg"
    original = work / "frames.elf"
    for name, command in (
            ("assembler", ["as", "--gdwarf-5", "-o", work / "frames.o", source]),
            ("linker", ["ld", "-e", "_start", "-o", artifact, work / "frames.o"]),
            ("strip", ["objcopy", "--strip-debug", artifact, original])):
        result = run(command, work / (name + ".txt"), work)
        require(result.returncode == 0 and not result.stderr, name + " failed")
    input_hashes = {str(path): digest(path) for path in (source, artifact, original)}
    missing = work / "missing-dwarfdump.conf"
    result = run([raw_tool, "--file-name=" + str(missing), "--no-follow-debuglink",
        "-ka", "-ki", "-kd", artifact], work / "missing-config-baseline.txt", hostile)
    require(result.returncode == 0 and not result.stderr and
        "ERROR: dwarfdump found no dwarfdump.conf" in result.stdout and
        "Frame section access suppressed." in result.stdout,
        "missing-config control did not reproduce the hosted exit-zero/frame suppression")
    result = run([raw_tool, "--no-follow-debuglink", "-ka", "-ki", "-kd", artifact],
        work / "hostile-cwd-baseline.txt", hostile)
    require(result.returncode == 0 and not result.stderr and "ERROR:" in result.stdout and
        "Frame section access suppressed." in result.stdout,
        "raw-tool control did not observe the hostile local configuration")
    log = work / "relocated-strict.txt"
    result = run([sys.executable, repository / "src/test/integration/check-dwarfdump.py",
        artifact, log, "--tool", launcher, "--original", original],
        work / "relocated-strict.runner.txt", hostile)
    require(result.returncode == 0 and not result.stderr, "relocated strict validation failed")
    metadata = json.loads(log.with_name(log.name + ".check.json").read_text())
    require(metadata["status"] == "PASS" and metadata["reported_errors"] == 3 and
        metadata["uncorroborated_errors"] == 0,
        "frame checking was skipped or incomplete after relocation")
    result = run([launcher, "--show-dwarfdump-conf", "--no-follow-debuglink",
        "-ka", "-ki", "-kd", artifact], work / "selected-configuration.txt", hostile)
    require(result.returncode == 0 and not result.stderr and str(configuration) in result.stdout
        and "ERROR:" not in result.stdout and "Frame section access suppressed" not in result.stdout,
        "launcher did not select the explicit bundled configuration")
    original_configuration = configuration.read_bytes()
    try:
        configuration.unlink()
        result = run([launcher, "--version"], work / "missing-bundled-config.txt", hostile)
        require(result.returncode == 1 and not result.stdout and result.stderr.strip() ==
            "validation dwarfdump configuration is missing or unreadable",
            "missing bundled config silently fell back to host configuration")
        configuration.write_bytes(original_configuration + b"\n# altered configuration\n")
        result = run([launcher, "--version"], work / "altered-bundled-config.txt", hostile)
        require(result.returncode == 1 and not result.stdout and result.stderr.strip() ==
            "validation dwarfdump configuration checksum mismatch",
            "altered bundled config was accepted")
    finally:
        configuration.write_bytes(original_configuration)
    for index, arguments in enumerate((
            ["--file-name=" + str(missing)], ["--file-name", str(missing)],
            ["-xname=" + str(missing)], ["-x", "name=" + str(missing)],
            ["-vxname=" + str(missing)], ["-vx", "name=" + str(missing)])):
        result = run([launcher, *arguments, "--version"],
            work / ("configuration-override-" + str(index) + ".txt"), hostile)
        require(result.returncode == 1 and not result.stdout and result.stderr.strip() ==
            "validation dwarfdump configuration overrides are unsupported",
            "launcher accepted a configuration override")
    for name, before in hashes.items():
        require(digest(bundle / name) == before and digest(relocated / name) == before,
            "validator input changed: " + name)
    for name, before in input_hashes.items():
        require(digest(Path(name)) == before, "fixture input changed: " + name)
    (work / "summary.json").write_text(json.dumps({"status": "PASS", "tool_hashes": hashes,
        "input_hashes": input_hashes, "reported_errors": 3, "uncorroborated_errors": 0,
        "controls": ["missing-config-baseline", "hostile-cwd-baseline", "relocated-config",
            "missing-bundled-config", "altered-bundled-config", "configuration-overrides"]},
        indent=4) + "\n")
    print("dwarfdump-configuration=PASS")


if __name__ == "__main__":
    main()

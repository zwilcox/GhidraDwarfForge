#!/usr/bin/env python3
"""Actual exported curated PIE fixture through its generated GDB companion."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import tempfile


def quoted(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def block(text):
    return "python\n" + text + "\nend"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sidecar", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    original = args.input.resolve(strict=True)
    sidecar = args.sidecar.resolve(strict=True)
    source = Path(str(sidecar) + ".c")
    companion = Path(str(sidecar) + ".gdb.py")
    snapshots = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (original, sidecar, source, companion)}
    args.results.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run.", dir=args.results.resolve()))
    configuration = directory / ".gdbinit"
    configuration.write_text("# Owned sentinel: companion must not edit debugger configuration.\nset confirm on\n")
    configuration_bytes = configuration.read_bytes()
    (directory / "gdbinit-before.txt").write_bytes(configuration_bytes)
    artifacts = directory / "artifacts"
    artifacts.mkdir()
    for path, digest in snapshots.items():
        retained = artifacts / Path(path).name
        shutil.copyfile(path, retained)
        assert hashlib.sha256(retained.read_bytes()).hexdigest() == digest, path
    shutil.copyfile(args.reference, artifacts / "compiler.reference")
    symbols = subprocess.check_output(["nm", "-n", str(args.reference.resolve(strict=True))], text=True)
    address = next(int(line.split()[0], 16) for line in symbols.splitlines()
        if len(line.split()) == 3 and line.split()[2] == "recovered_add")
    commands = ["set pagination off", "set confirm on", "set debuginfod enabled off",
        "set auto-solib-add off", "set disable-randomization off", "file " + quoted(original),
        "source " + str(companion), "python biases=[]"]
    for iteration in range(3):
        commands += ["starti", "forge-load", block(
            "assert gdb.parameter('confirm') is True, 'companion changed user confirmation setting'\n"
            "state = next(iter(gdb._forge_loader_registry_v1.loaded.values()))\n"
            "biases.append(state['bias'])\n"
            f"assert int(gdb.parse_and_eval('&recovered_add')) == state['bias'] + {address}\n"
            "assert 'int recovered_add(int left,int right)' in gdb.execute('list recovered_add', to_string=True)\n"
            f"assert {str(source)!r} in gdb.execute('info line recovered_add', to_string=True)\n"
            "assert 'struct fixture_state' in gdb.execute('ptype struct fixture_state', to_string=True)\n"
            "point = gdb.Breakpoint('recovered_add')"), "continue", block(
            "assert gdb.selected_frame().name() == 'recovered_add'\n"
            "assert int(gdb.parse_and_eval('left')) == 19\n"
            "assert int(gdb.parse_and_eval('right')) == 23\n"
            "assert int(gdb.parse_and_eval('fixture_sink')) == 0\n"
            "assert int(gdb.parse_and_eval('scoped_counter')) == 7"), "next", block(
            "assert int(gdb.parse_and_eval('fixture_sink')) == 42\n"
            "point.delete()"), "continue", block(
            "assert not gdb._forge_loader_registry_v1.loaded\n"
            f"assert not any(obj.filename == {str(sidecar)!r} for obj in gdb.objfiles())")]
    commands.append(block("assert len(set(biases)) > 1, 'distinct ASLR biases required'\n"
        "print('FORGE_NATIVE_COMPANION=' + repr(biases))"))
    command_file = directory / "commands.gdb"
    command_file.write_text("\n".join(commands) + "\n")
    result = subprocess.run(["gdb-multiarch", "-nx", "-q", "-batch", "-x", str(command_file)],
        cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
    (directory / "gdb.txt").write_text(result.stdout)
    if (result.returncode or "FORGE_NATIVE_COMPANION=" not in result.stdout or
            "Python Exception" in result.stdout or "Traceback" in result.stdout):
        raise AssertionError(f"native companion GDB failed; see {directory / 'gdb.txt'}")
    for path, digest in snapshots.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise AssertionError(f"changed fixture artifact: {path}")
    if configuration.read_bytes() != configuration_bytes:
        raise AssertionError("companion modified existing debugger configuration")
    (directory / "gdbinit-after.txt").write_bytes(configuration.read_bytes())
    (directory / "result.json").write_text(json.dumps({"status": "PASS", "preserved": snapshots,
        "transcript": result.stdout.split("FORGE_NATIVE_COMPANION=", 1)[1].splitlines()[0]}, indent=4) + "\n")
    print(f"gdb-companion-native=PASS {directory}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Live native GDB check of production mapping arithmetic.

Uses compiler DWARF as an independent consumer reference. This is a prerequisite
test, not acceptance of Forge companion generation or lifecycle integration.
All files are newly created under build/test-results; input copies are hashed.
The reference is the complete compiler ELF, preserving valid program headers.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[3]
RESULTS = ROOT / "build/test-results/gdb-loader-mappings"
ENGINE = ROOT / "src/main/resources/ghidradwarfforge/gdb/loader.py"


def run(argv, cwd, log):
    result = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=60)
    log.write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"failed {argv!r}; see {log}")
    return result.stdout


def elf_loads(path):
    # Independent ELF program-header decoding. Do not import production ELF
    # parsing or assume .text equals the first mapped segment.
    raw = path.read_bytes()
    if raw[:4] != b"\x7fELF":
        raise ValueError("fixture is not ELF")
    order = "<" if raw[5] == 1 else ">"
    bits = {1: 32, 2: 64}[raw[4]]
    if bits == 64:
        offset = struct.unpack_from(order + "Q", raw, 32)[0]
        size, count = struct.unpack_from(order + "HH", raw, 54)
        layout = "IIQQQQQQ"
    else:
        offset = struct.unpack_from(order + "I", raw, 28)[0]
        size, count = struct.unpack_from(order + "HH", raw, 42)
        layout = "IIIIIIII"
    segments = []
    for index in range(count):
        entry = struct.unpack_from(order + layout, raw, offset + size * index)
        if entry[0] == 1:
            if bits == 64:
                segments.append([entry[2], entry[3], entry[5], entry[6]])
            else:
                segments.append([entry[1], entry[2], entry[4], entry[5]])
    return bits, segments


def quote(path):
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def python_command(source):
    return "python\n" + source + "\nend\n"


def validate_reference(original, sidecar, directory):
    for index, arguments in enumerate((['-h'], ['-S'], ['--debug-dump=info'],
            ['--debug-dump=abbrev'], ['--debug-dump=aranges'],
            ['--debug-dump=decodedline'], ['-n'])):
        output = run(["readelf", *arguments, str(sidecar)], directory,
            directory / f"readelf-sidecar-{index}.txt")
        if "error:" in output.lower() or "warning:" in output.lower():
            raise AssertionError("compiler reference has a readelf diagnostic")
    for flag in ("h", "S", "n"):
        run(["readelf", "-" + flag, str(original)], directory,
            directory / f"readelf-original-{flag}.txt")
    output = run(["llvm-dwarfdump", "--verify", str(sidecar)], directory,
        directory / "llvm-verify.txt")
    if "No errors." not in output or "error:" in output.lower() or "warning:" in output.lower():
        raise AssertionError("compiler reference failed LLVM verification")
    run([os.environ.get("DWARFDUMP", "dwarfdump"), str(sidecar)], directory,
        directory / "dwarfdump.txt")


def live_check(directory, role):
    source = directory / "mapping fixture.c"
    source.write_text("""volatile int mapping_global = 7;
__attribute__((noinline)) int mapping_function(int left, int right) {
    mapping_global = left + right;
    return mapping_global;
}
int main(void) { return mapping_function(19, 23) == 42 ? 0 : 1; }
""")
    original = directory / "mapping target"
    sidecar = directory / "mapping target.dbg"
    flags = ["-fPIE", "-pie"] if role == "pie" else ["-fno-pie", "-no-pie"]
    run(["gcc", "-O0", "-gdwarf-5", *flags, str(source), "-o", str(original)],
        directory, directory / "compile.txt")
    symbols = run(["nm", "-n", str(original)], directory, directory / "symbols.txt")
    addresses = {line.split()[2]: int(line.split()[0], 16)
        for line in symbols.splitlines() if len(line.split()) == 3}
    shutil.copyfile(original, sidecar)
    run(["strip", "--strip-all", str(original)], directory, directory / "strip.txt")
    validate_reference(original, sidecar, directory)
    bits, segments = elf_loads(original)
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (original, sidecar, source)}
    commands = ["set pagination off", "set confirm off", "set debuginfod enabled off",
        "set auto-solib-add off", "set disable-randomization off", "file " + quote(original)]
    commands.append(python_command(
        "import importlib.util, json, sys\nsys.dont_write_bytecode = True\n"
        f"spec = importlib.util.spec_from_file_location('forge_loader', {str(ENGINE)!r})\n"
        "loader = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(loader)\n"
        f"segments = [loader.LoadSegment(*row) for row in {segments!r}]\n"
        "biases = []"))
    for iteration in range(3):
        commands.append("starti")
        commands.append(python_command(
            "maps = loader.parse_mappings(gdb.execute('info proc mappings', to_string=True))\n"
            f"selected = [row for row in maps if row.path == {str(original)!r}]\n"
            f"bias = loader.select_bias(segments, selected, {bits})\n"
            "biases.append(bias)\n"
            f"gdb.execute({('add-symbol-file ' + quote(sidecar) + ' -o ')!r} + hex(bias))\n"
            f"assert int(gdb.parse_and_eval('&mapping_function')) == bias + {addresses['mapping_function']}\n"
            f"assert int(gdb.parse_and_eval('&mapping_global')) == bias + {addresses['mapping_global']}\n"
            "assert int(gdb.parse_and_eval('mapping_global')) == 7\n"
            "assert 'mapping_global = left + right' in gdb.execute('list mapping_function', to_string=True)\n"
            "point = gdb.Breakpoint('mapping_function')"))
        commands.append("continue")
        commands.append(python_command(
            "assert int(gdb.parse_and_eval('left')) == 19\n"
            "assert int(gdb.parse_and_eval('right')) == 23\n"
            "assert gdb.selected_frame().name() == 'mapping_function'"))
        commands.extend(["next", "next"])
        commands.append(python_command("assert int(gdb.parse_and_eval('mapping_global')) == 42\npoint.delete()"))
        commands.append("continue")
        commands.append("remove-symbol-file " + quote(sidecar))
    commands.append(python_command(
        ("assert len(set(biases)) > 1, 'ASLR did not produce distinct biases'\n" if role == "pie"
            else "assert biases == [0, 0, 0]\n") +
        "print('FORGE_MAPPING_RESULT=' + json.dumps(biases))"))
    script = directory / "commands.gdb"
    script.write_text("\n".join(commands) + "\n")
    text = run(["gdb-multiarch", "-nx", "-q", "-batch", "-x", str(script)],
        directory, directory / "gdb.txt")
    if "FORGE_MAPPING_RESULT=" not in text:
        raise AssertionError("missing GDB completion marker")
    for path, digest in before.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise AssertionError(f"fixture changed: {path}")
    return {"role": role, "bits": bits, "preserved": before,
        "biases": json.loads(next(line.split("=", 1)[1] for line in text.splitlines()
            if line.startswith("FORGE_MAPPING_RESULT=")))}


def shared_check(directory):
    source = directory / "library source.c"
    source.write_text("""volatile int shared_value = 7;
__attribute__((noinline)) int shared_function(int left, int right) {
    shared_value = left + right;
    return shared_value;
}
""")
    driver_source = directory / "driver.c"
    driver_source.write_text("""#include <dlfcn.h>
__attribute__((noinline)) void after_load(void) { __asm__ volatile ("" ::: "memory"); }
__attribute__((noinline)) void after_unload(void) { __asm__ volatile ("" ::: "memory"); }
int main(int argc, char **argv) {
    for (int i = 0; i < 2; i++) {
        void *handle = dlopen(argv[1], RTLD_NOW);
        if (!handle) return 2;
        int (*function)(int, int) = dlsym(handle, "shared_function");
        if (!function) return 3;
        after_load();
        if (function(19, 23) != 42) return 4;
        if (dlclose(handle)) return 5;
        after_unload();
    }
    return 0;
}
""")
    original = directory / "mapped library.so"
    sidecar = directory / "mapped library.so.dbg"
    driver = directory / "driver"
    run(["gcc", "-O0", "-gdwarf-5", "-shared", "-fPIC", str(source), "-o", str(original)],
        directory, directory / "compile-library.txt")
    run(["gcc", "-O0", "-g", str(driver_source), "-ldl", "-o", str(driver)],
        directory, directory / "compile-driver.txt")
    symbols = run(["nm", "-n", str(original)], directory, directory / "symbols.txt")
    addresses = {line.split()[2]: int(line.split()[0], 16)
        for line in symbols.splitlines() if len(line.split()) == 3}
    shutil.copyfile(original, sidecar)
    run(["strip", "--strip-all", str(original)], directory, directory / "strip.txt")
    validate_reference(original, sidecar, directory)
    bits, segments = elf_loads(original)
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (original, sidecar, source, driver, driver_source)}
    commands = ["set pagination off", "set confirm off", "set debuginfod enabled off",
        "set auto-solib-add off", "set disable-randomization off", "file " + quote(driver),
        "set args " + quote(original), "break after_load", "break after_unload"]
    commands.append(python_command(
        "import importlib.util, json, sys\nsys.dont_write_bytecode = True\n"
        f"spec = importlib.util.spec_from_file_location('forge_loader', {str(ENGINE)!r})\n"
        "loader = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(loader)\n"
        f"segments = [loader.LoadSegment(*row) for row in {segments!r}]\n"
        "biases = []"))
    commands.append("run")
    for iteration in range(2):
        commands.append(python_command(
            "assert gdb.selected_frame().name() == 'after_load'\n"
            "maps = loader.parse_mappings(gdb.execute('info proc mappings', to_string=True))\n"
            f"selected = [row for row in maps if row.path == {str(original)!r}]\n"
            f"bias = loader.select_bias(segments, selected, {bits})\n"
            "biases.append(bias)\n"
            f"gdb.execute({('add-symbol-file ' + quote(sidecar) + ' -o ')!r} + hex(bias))\n"
            f"assert int(gdb.parse_and_eval('&shared_function')) == bias + {addresses['shared_function']}\n"
            f"assert int(gdb.parse_and_eval('&shared_value')) == bias + {addresses['shared_value']}\n"
            "assert int(gdb.parse_and_eval('shared_value')) == 7\n"
            "assert 'shared_value = left + right' in gdb.execute('list shared_function', to_string=True)\n"
            "point = gdb.Breakpoint('shared_function')"))
        commands.append("continue")
        commands.append(python_command(
            "assert gdb.selected_frame().name() == 'shared_function'\n"
            "assert int(gdb.parse_and_eval('left')) == 19\n"
            "assert int(gdb.parse_and_eval('right')) == 23\npoint.delete()"))
        commands.extend(["next", "next"])
        commands.append(python_command("assert int(gdb.parse_and_eval('shared_value')) == 42"))
        commands.append("continue")
        commands.append(python_command(
            "assert gdb.selected_frame().name() == 'after_unload'\n"
            "maps = loader.parse_mappings(gdb.execute('info proc mappings', to_string=True))\n"
            f"selected = [row for row in maps if row.path == {str(original)!r}]\n"
            f"assert loader.mapping_biases(segments, selected, {bits}) == ()"))
        commands.extend(["remove-symbol-file " + quote(sidecar), "continue"])
    commands.append(python_command("print('FORGE_MAPPING_RESULT=' + json.dumps(biases))"))
    script = directory / "commands.gdb"
    script.write_text("\n".join(commands) + "\n")
    text = run(["gdb-multiarch", "-nx", "-q", "-batch", "-x", str(script)],
        directory, directory / "gdb.txt")
    for path, digest in before.items():
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
            raise AssertionError(f"fixture changed: {path}")
    return {"role": "shared", "bits": bits, "preserved": before,
        "biases": json.loads(next(line.split("=", 1)[1] for line in text.splitlines()
            if line.startswith("FORGE_MAPPING_RESULT=")))}


def main():
    for executable in ("gcc", "strip", "nm", "gdb-multiarch", "readelf",
            "llvm-dwarfdump", os.environ.get("DWARFDUMP", "dwarfdump")):
        if shutil.which(executable) is None:
            raise SystemExit(f"required tool unavailable: {executable}")
    RESULTS.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run.", dir=RESULTS))
    results = []
    for role in ("exec", "pie"):
        case = directory / role
        case.mkdir()
        results.append(live_check(case, role))
    shared = directory / "shared"
    shared.mkdir()
    results.append(shared_check(shared))
    (directory / "result.json").write_text(json.dumps({"status": "PASS",
        "engineSha256": hashlib.sha256(ENGINE.read_bytes()).hexdigest(),
        "cases": results}, indent=4) + "\n")
    print(f"gdb-loader-mappings=PASS {directory}")


if __name__ == "__main__":
    main()

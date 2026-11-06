#!/usr/bin/env python3
"""Build and validate independent unwind references before enabling synthesis."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "src/test/integration"
metadata = runpy.run_path(str(SCRIPTS / "matched-elf-prefix.py"))["metadata"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, prefix):
    command = list(map(str, command))
    prefix.with_suffix(".command.json").write_text(json.dumps(command) + "\n")
    with prefix.with_suffix(".stdout").open("wb") as out, \
            prefix.with_suffix(".stderr").open("wb") as err:
        result = subprocess.run(command, stdout=out, stderr=err, cwd=ROOT,
                                env={**os.environ, "LC_ALL": "C"}, timeout=180)
    assert result.returncode == 0, (command, result.returncode, str(prefix))
    assert not prefix.with_suffix(".stderr").stat().st_size, str(prefix)


def image(path):
    info = metadata(path)
    data = path.read_bytes()
    allocated = [{**{key: section[key] for key in (
        "name", "type", "flags", "address", "size", "alignment")},
        "data": data[section["offset"]:section["offset"] + section["size"]].hex()
        if section["type"] != 8 else ""}
        for section in info["sections"] if section["flags"] & 2]
    program_headers = data[info["phoff"]:
        info["phoff"] + info["phsize"] * info["phcount"]].hex()
    return info, allocated, program_headers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=["x86_64", "aarch64"])
    parser.add_argument("output", type=Path)
    parser.add_argument("--dwarfdump", required=True)
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    prefix = "" if args.target == "x86_64" else "aarch64-linux-gnu-"
    tools = [prefix + "gcc", prefix + "objcopy", "readelf", "llvm-dwarfdump",
             "gdb" if args.target == "x86_64" else "gdb-multiarch"]
    if args.target == "aarch64":
        tools.append("qemu-aarch64-static")
    tool_hashes = {}
    for index, tool in enumerate(tools):
        executable = Path(shutil.which(tool)).resolve(strict=True)
        tool_hashes[str(executable)] = digest(executable)
        run([tool, "--version"], work / ("tool-" + str(index)))
    reference = work / "reference"
    original = work / "without-cfi"
    source = ROOT / "src/test/fixtures/synthetic-cfi.c"
    start = source.with_name("synthetic-cfi-start-" + args.target + ".S")
    protected = {str(path): digest(path) for path in (source, start)}
    flags = ["-O1", "-g", "-gdwarf-5", "-fomit-frame-pointer",
             "-fno-optimize-sibling-calls", "-fno-asynchronous-unwind-tables",
             "-fno-unwind-tables", "-fno-pie", "-no-pie", "-nostdlib",
             "-static", "-Wl,--build-id=none"]
    for name in ("reference", "reference-repeat"):
        run([prefix + "gcc", *flags, source, start, "-o", work / name], work / (name + "-build"))
    assert reference.read_bytes() == (work / "reference-repeat").read_bytes()
    run([prefix + "objcopy", "--strip-debug", reference, original], work / "strip")
    ref_info, ref_allocated, ref_ph = image(reference)
    input_info, input_allocated, input_ph = image(original)
    assert ref_info["profile"] == [2, 1, 62 if args.target == "x86_64" else 183]
    assert input_info["profile"] == ref_info["profile"]
    assert ref_allocated == input_allocated and ref_ph == input_ph
    assert any(s["name"] == ".debug_frame" and s["size"] for s in ref_info["sections"])
    assert not any(s["name"].startswith((".eh_frame", ".ARM.exidx", ".ARM.extab"))
                   for s in ref_info["sections"])
    assert not any(s["name"].startswith((".debug_", ".zdebug_", ".eh_frame"))
                   for s in input_info["sections"])
    protected.update({str(path): digest(path) for path in (reference, original)})
    run(["readelf", "-h", "-S", "-n", "-l", "--debug-dump=info,abbrev,aranges,decodedline,frames",
         reference], work / "gnu")
    run(["readelf", "-h", "-S", "-n", "-l", original], work / "original-gnu")
    run(["llvm-dwarfdump", "--verify", reference], work / "llvm")
    run([sys.executable, SCRIPTS / "check-dwarfdump.py", reference, work / "strict.log",
         "--tool", args.dwarfdump], work / "strict")
    modes = {}
    warnings = {}
    for mode in ("compiler", "absent", "disabled"):
        run(["bash", SCRIPTS / "synthetic-cfi-reference-gdb.sh", args.target, mode,
             reference, original, work / mode], work / (mode + "-driver"))
        modes[mode] = json.loads((work / (mode + ".json")).read_text())
        log = (work / (mode + ".log")).read_text()
        # Require an accepted DWARF unwinder, not merely an attempted sniffer.
        dwarf_selected = bool(re.search(r'unwinder="dwarf2"', log))
        assert dwarf_selected == (mode == "compiler"), (mode, dwarf_selected)
        warnings[mode] = [line for line in log.splitlines() if "warning:" in line.lower()]
        assert "Traceback" not in log
    # QEMU's synthetic system DSO is outside these freestanding ELF files.
    # Accept only this exact known message and only when independently repeated
    # with compiler CFI, no CFI, and disabled DWARF unwinders.
    assert warnings["compiler"] == warnings["absent"] == warnings["disabled"], warnings
    if warnings["compiler"]:
        assert args.target == "aarch64" and len(warnings["compiler"]) == 1, warnings
        assert re.fullmatch(r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ "
                            r"has a corrupt string table index", warnings["compiler"][0]), warnings
    # Some target prologue unwinders are capable of recovering this fixture;
    # record that result rather than pretending all no-CFI backtraces fail.
    assert modes["compiler"]["complete"]
    assert protected == {path: digest(Path(path)) for path in protected}
    report = {"status": "PASS_COMPILER_REFERENCE", "target": args.target,
              "scope": "Independent compiler reference only; no Forge CFI emitted or tested",
              "toolSha256": tool_hashes,
              "protectedSha256": protected, "modes": modes, "runtimeWarnings": warnings,
              "allocatedSectionsAndProgramHeadersUnchanged": True,
              "deterministicCompilerReference": True}
    (work / "result.json").write_text(json.dumps(report, indent=4) + "\n")
    print("synthetic-cfi-reference=" + args.target + " PASS")


if __name__ == "__main__":
    main()

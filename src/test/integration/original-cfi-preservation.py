#!/usr/bin/env python3
"""Preserve real compiler CFI through headless export and relocated GDB loading."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import signal
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "src/test/integration"
metadata = runpy.run_path(str(SCRIPTS / "matched-elf-prefix.py"))["metadata"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, log, env=None, timeout=180):
    argv = list(map(str, argv))
    Path(str(log) + ".command.json").write_text(json.dumps(argv) + "\n")
    with log.open("wb") as stream:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                   env={**os.environ, "LC_ALL": "C", **(env or {})}, start_new_session=True)
        try:
            status = process.wait(timeout=timeout)
        except BaseException:
            # Own the entire launcher/Java or shell/QEMU tree on failed runs.
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            raise
    assert status == 0, (status, str(log))
    return log.read_text()


def frame_section(path):
    sections = [s for s in metadata(path)["sections"]
                if s["name"] in (".debug_frame", ".zdebug_frame")]
    assert len(sections) == 1, (path, sections)
    section = sections[0]
    payload = path.read_bytes()[section["offset"]:section["offset"] + section["size"]]
    return section, digest(path), hashlib.sha256(payload).hexdigest()


def normalized(record):
    # ASLR moves the image, not the instruction-relative frame/trace semantics.
    def rows(frames):
        result = []
        for frame in frames:
            value = dict(frame)
            if value.get("name", "").startswith("cfi_") or value.get("name") == "_start":
                value["pc"] -= record["checkpointAddress"]
            result.append(value)
        return result
    return {"frames": rows(record["frames"]),
            "trace": [rows(row) for row in record["instructionTrace"]]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=["x86_64", "aarch64"])
    parser.add_argument("ghidra", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--dwarfdump", required=True)
    parser.add_argument("--libdwarf", type=Path)
    parser.add_argument("--libdwarfp", type=Path)
    parser.add_argument("--variants", nargs="+", default=["plain", "gabi", "gnu", "rebased", "relocations"],
                        choices=["plain", "gabi", "gnu", "rebased", "relocations"])
    parser.add_argument("--roles", nargs="+", default=["exec", "pie", "shared"], choices=["exec", "pie", "shared"])
    args = parser.parse_args()
    assert bool(args.libdwarf) == bool(args.libdwarfp)
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    print(work, flush=True)
    ghidra = args.ghidra.resolve()
    module = ghidra / "Ghidra/Extensions/GhidraDwarfForge"
    native_args = (["--libdwarf=" + str(args.libdwarf.resolve()),
                    "--libdwarfp=" + str(args.libdwarfp.resolve())]
                   if args.libdwarf else ["--packaged-natives"])
    prefix = "" if args.target == "x86_64" else "aarch64-linux-gnu-"
    source = ROOT / "src/test/fixtures/synthetic-cfi.c"
    start = source.with_name("synthetic-cfi-start-" + args.target + ".S")
    driver = work / "driver"
    run([prefix + "gcc", "-O0", "-g", "-fno-pie", "-no-pie",
         source.with_name("synthetic-cfi-shared-driver.c"), "-ldl", "-o", driver], work / "driver-build.log")
    protected = {str(path): digest(path) for path in (source, start, driver,
        module / "lib/GhidraDwarfForge.jar", source.with_name("synthetic-cfi-shared-driver.c"))}
    if args.libdwarf:
        protected.update({str(path.resolve()): digest(path) for path in (args.libdwarf, args.libdwarfp)})
    cases = []
    for role in args.roles:
        role_dir = work / role
        role_dir.mkdir()
        reference = role_dir / "reference"
        flags = ["-O1", "-g", "-gdwarf-5", "-fomit-frame-pointer", "-fno-optimize-sibling-calls",
                 "-fno-asynchronous-unwind-tables", "-fno-unwind-tables", "-Wl,--build-id=none"]
        # These references deliberately contain no runtime unwind metadata.
        if role == "exec":
            flags += ["-fno-pie", "-no-pie", "-nostdlib", "-static", str(start)]
        elif role == "pie":
            flags += ["-fPIE", "-static-pie", "-nostdlib", str(start)]
        else:
            flags += ["-fPIC", "-shared", "-nostdlib"]
        run([prefix + "gcc", *flags, source, "-o", reference], role_dir / "build.log")
        assert not any(s["name"].startswith(".eh_frame") and s["size"]
                       for s in metadata(reference)["sections"]), role
        protected[str(reference)] = digest(reference)
        runtime_env = {"FORGE_CFI_SHARED": "1" if role == "shared" else "0",
                       "FORGE_CFI_DRIVER": str(driver)}
        run(["bash", SCRIPTS / "synthetic-cfi-reference-gdb.sh", args.target, "compiler",
             reference, reference, role_dir / "compiler"], role_dir / "compiler-driver.log", runtime_env)
        compiler_record = json.loads((role_dir / "compiler.json").read_text())
        reference_warnings = [line for line in (role_dir / "compiler.log").read_text().splitlines()
                              if "warning:" in line.lower()]
        assert all(args.target == "aarch64" and re.fullmatch(
            r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index",
            warning) for warning in reference_warnings), reference_warnings
        for variant in args.variants:
            case = role_dir / variant
            case.mkdir()
            original = case / "original"
            if variant == "relocations":
                run([prefix + "gcc", *flags, "-Wl,--emit-relocs", source, "-o", original], case / "copy.log")
                frame_index = frame_section(original)[0]["index"]
                assert any(s["type"] in (4, 9) and s["info"] == frame_index
                           for s in metadata(original)["sections"]), "missing retained link relocation control"
            else:
                compression = {"plain": "none", "gabi": "zlib-gabi", "gnu": "zlib-gnu", "rebased": "none"}[variant]
                run([prefix + "objcopy", "--compress-debug-sections=" + compression,
                     reference, original], case / "copy.log")
            before, input_hash, payload_hash = frame_section(original)
            symbol_text = run(["readelf", "-Ws", original], case / "symbols.log")
            names = {"cfi_checkpoint", "cfi_recursive", "cfi_outer", "cfi_main"}
            symbols = {}
            for line in symbol_text.splitlines():
                fields = line.split()
                if len(fields) == 8 and fields[3] == "FUNC" and fields[7] in names:
                    symbol = (int(fields[1], 16), int(fields[2]))
                    assert fields[7] not in symbols or symbols[fields[7]] == symbol
                    symbols[fields[7]] = symbol
            assert set(symbols) == names
            identities = case / "curation.txt"
            identities.write_text("".join(f"{name} {value:x} {size}\n"
                                         for name, (value, size) in sorted(symbols.items())))
            protected[str(original)] = input_hash
            if variant == "gabi":
                assert before["flags"] & 0x800
            if variant == "gnu":
                assert before["name"] == ".zdebug_frame"
            outputs = []
            for generation in (0, 1):
                project = case / ("project-" + str(generation))
                project.mkdir()
                # Source paths are DWARF content: deterministic reruns must use
                # the same publication path, with separate retained snapshots.
                sidecar = case / "export.dbg"
                command = [ghidra / "support/analyzeHeadless", project, "CFIPreservation",
                           "-deleteProject", "-import", original, "-loader", "ElfLoader",
                           "-analysisTimeoutPerFile", "120", "-scriptPath", SCRIPTS / "ghidra_scripts"]
                if variant == "rebased":
                    command += ["-postScript", "RebaseFixtureProgram.java", "0x200000"]
                command += ["-postScript", "PrepareCfiFixture.java", identities]
                command += ["-postScript", "GhidraDwarfForge.java", *native_args,
                            "--input=" + str(original), "--output=" + str(sidecar)]
                log = run(command, case / ("export-" + str(generation) + ".log"))
                reports = [json.loads(line.split("GhidraDwarfForge report: ", 1)[1].split(" (GhidraScript)", 1)[0])
                           for line in log.splitlines() if "GhidraDwarfForge report: {" in line]
                assert len(reports) == 1 and reports[0]["status"] in ("SUCCESS", "PARTIAL"), reports
                after, unused, after_payload = frame_section(sidecar)
                retained_fields = ("index", "name", "type", "flags", "address", "offset", "size",
                                   "link", "info", "alignment", "entry_size")
                assert all(before[key] == after[key] for key in retained_fields), (before, after)
                assert payload_hash == after_payload
                if generation:
                    assert sidecar.read_bytes() == outputs[0][0]
                    assert Path(str(sidecar) + ".c").read_bytes() == outputs[0][1]
                outputs.append((sidecar.read_bytes(), Path(str(sidecar) + ".c").read_bytes()))
                (case / ("generation-" + str(generation) + ".dbg")).write_bytes(outputs[-1][0])
                (case / ("generation-" + str(generation) + ".dbg.c")).write_bytes(outputs[-1][1])
            gnu = run(["readelf", "-h", "-S", "-n", "--debug-dump=info,abbrev,aranges,decodedline,frames",
                       sidecar], case / "gnu.log")
            assert "warning" not in gnu.lower() and "error" not in gnu.lower()
            run(["llvm-dwarfdump", "--verify", sidecar], case / "llvm.log")
            run([sys.executable, SCRIPTS / "check-dwarfdump.py", sidecar, case / "strict.log",
                 "--tool", args.dwarfdump], case / "strict-driver.log")
            run(["bash", SCRIPTS / "synthetic-cfi-reference-gdb.sh", args.target, "compiler",
                 sidecar, original, case / "gdb"], case / "gdb-driver.log", runtime_env)
            record = json.loads((case / "gdb.json").read_text())
            log = (case / "gdb.log").read_text()
            selected = 'level=0,type=NORMAL_FRAME,unwinder="dwarf2",pc=' + hex(record["checkpointAddress"])
            assert selected in log, "target frame did not select the DWARF unwinder"
            assert [line for line in log.splitlines() if "warning:" in line.lower()] == reference_warnings
            assert normalized(record) == normalized(compiler_record), str(case)
            control_result = None
            if variant == "plain":
                control = case / "without-frame.dbg"
                run([prefix + "objcopy", "--remove-section=" + before["name"], sidecar, control],
                    case / "without-frame-copy.log")
                run(["bash", SCRIPTS / "synthetic-cfi-reference-gdb.sh", args.target, "probe",
                     control, original, case / "without-frame"], case / "without-frame-driver.log", runtime_env)
                control_result = json.loads((case / "without-frame.json").read_text())
                absent_log = (case / "without-frame.log").read_text()
                absent_selected = ('level=0,type=NORMAL_FRAME,unwinder="dwarf2",pc=' +
                                   hex(control_result["checkpointAddress"]))
                assert absent_selected not in absent_log, "runtime input supplied CFI behind sidecar control"
                if args.target == "x86_64":
                    assert not control_result["complete"], "expected x86 fixture to need frame metadata"
            cases.append({"role": role, "variant": variant, "originalSha256": input_hash,
                          "originalFrameSha256": payload_hash, "sidecarSha256": digest(sidecar),
                          "sourceSha256": digest(Path(str(sidecar) + ".c")),
                          "instructionStops": len(record["instructionTrace"]),
                          "withoutFrameControl": control_result,
                          "status": "PASS_PRESERVED_COMPILER_CFI"})
            (work / "progress.json").write_text(json.dumps(cases, indent=4) + "\n")
            print(args.target + " " + role + " " + variant + " PASS", flush=True)
    assert protected == {path: digest(Path(path)) for path in protected}
    (work / "result.json").write_text(json.dumps({"status": "PASS_ORIGINAL_CFI_PRESERVATION",
        "target": args.target, "cases": cases, "protectedSha256": protected,
        "scope": "Original compiler CFI only; no synthetic unwind generation"}, indent=4) + "\n")


if __name__ == "__main__":
    main()

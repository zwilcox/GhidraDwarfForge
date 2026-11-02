#!/usr/bin/env python3
"""Validate saved AArch64 128-bit analyst lane layouts against actual vector code."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location(
    "abi_support", source.parent / "performance/export-benchmark.py"
)
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ghidra", type=Path)
    parser.add_argument("--role", choices=("exec", "pie", "pie-rebased"), default="exec")
    parser.add_argument(
        "--with-controls",
        action="store_true",
        help="require native failure isolation and production ELF-copy cancellation with saved lane layouts",
    )
    parser.add_argument(
        "--results-root", type=Path, default=repository / "build/test-results/aarch64-vector"
    )
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / "Ghidra/Extensions/GhidraDwarfForge"
    root = args.results_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.role + ".", dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + "\n")

    def run(name, command, clean=True):
        support.run(command, case / (name + ".log"), timeout=240)
        if clean:
            support.require_clean(case / (name + ".log"))

    fixture = source.parent / "fixtures/aarch64-vector.c"
    protected = [
        fixture,
        Path(__file__),
        source / "aarch64-vector-gdb.py",
        source / "aarch64-vector-gdb.sh",
        source / "aarch64-vector-locations.py",
        source / "aarch64-vector-reference.py",
        source / "check-stack-first-use.py",
        source / "aarch64-vector-controls.py",
        source / "aarch64-abi-locations.py",
        source / "ghidra_scripts/AbiDecompilerFailureExport.java",
        source / "ghidra_scripts/CancelDuringElfCopy.java",
        source / "ghidra_scripts/RebaseFixtureProgram.java",
        source / "qemu-socket.sh",
        source / "elf-layout-gdb-oracle.sh",
        source / "check-dwarfdump.py",
        source / "ghidra_scripts/PrepareAarch64Vector.java",
        source.parent / "performance/export-benchmark.py",
    ]
    protected += [path for path in module.rglob("*") if path.is_file()]
    before = {str(path): support.digest(path) for path in protected}
    reference, binary, output = [
        case / ("abi." + suffix) for suffix in ("reference", "input", "dbg")
    ]
    compiler_flags = ["-gno-variable-location-views", "-fno-ipa-sra", "-fno-ipa-cp"]
    image_flags = ["-fno-pie", "-no-pie"] if args.role == "exec" else ["-fPIE", "-pie"]
    run(
        "compile",
        [
            "aarch64-linux-gnu-gcc",
            *compiler_flags,
            "-O1",
            "-g",
            "-gdwarf-5",
            "-fno-inline",
            "-fno-omit-frame-pointer",
            *image_flags,
            "-Wl,--build-id=sha1",
            fixture,
            "-o",
            reference,
        ],
    )
    run("strip", ["aarch64-linux-gnu-objcopy", "--strip-all", reference, binary])
    run(
        "native-result",
        [
            "env",
            "QEMU_CPU=cortex-a53",
            "qemu-aarch64-static",
            "-L",
            "/usr/aarch64-linux-gnu",
            binary,
        ],
    )
    before.update({str(path): support.digest(path) for path in (reference, binary)})
    write("protected-before.json", before)
    run("symbols", ["aarch64-linux-gnu-nm", "-n", reference])
    symbols = {}
    for line in (case / "symbols.log").read_text().splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2].startswith("vector_") and fields[1] == "T":
            assert fields[1] == "T" and fields[2] not in symbols, fields
            symbols[fields[2]] = int(fields[0], 16)
    assert set(symbols) == {
        "vector_plain",
        "vector_copy",
        "vector_stack",
        "vector_alias",
        "vector_float",
        "vector_stack_arg",
    }
    (case / "labels.txt").write_text(
        "".join(name + " " + hex(address) + "\n" for name, address in symbols.items())
    )
    write(
        "metadata.json",
        {
            "role": args.role,
            "compiler": "aarch64-linux-gnu-gcc",
            "qemuCpu": "cortex-a53",
            "symbols": symbols,
        },
    )
    for name, command in [
        ("original-elf", ["readelf", "-h", "-SW", "-l", "-n", binary]),
        ("instructions", ["aarch64-linux-gnu-objdump", "-d", reference]),
        ("compiler-info", ["readelf", "--debug-dump=info,loc", reference]),
    ]:
        run(name, command)
    project = case / "project"
    project.mkdir()
    scripts = case / "scripts"
    scripts.mkdir()
    shutil.copyfile(
        source / "ghidra_scripts/PrepareAarch64Vector.java", scripts / "PrepareAarch64Vector.java"
    )
    shutil.copyfile(
        source / "ghidra_scripts/RebaseFixtureProgram.java", scripts / "RebaseFixtureProgram.java"
    )
    rebase = (
        ["-postScript", "RebaseFixtureProgram.java", "0x2000000"]
        if args.role == "pie-rebased"
        else []
    )
    run(
        "import",
        [
            ghidra / "support/analyzeHeadless",
            project,
            "Aarch64Abi",
            "-import",
            binary,
            "-analysisTimeoutPerFile",
            "120",
            "-scriptPath",
            scripts,
            *rebase,
            "-postScript",
            "PrepareAarch64Vector.java",
            "curate",
            case / "labels.txt",
            case / "curated.json",
        ],
        clean=False,
    )
    import_log = (case / "import.log").read_text()
    assert (
        "REPORT SCRIPT ERROR" not in import_log and "aarch64-vector-preparation=PASS" in import_log
    )
    curated = json.loads((case / "curated.json").read_text())
    assert (
        Path(unquote(urlsplit(curated["origin"]).path)).resolve()
        == (module / "lib/GhidraDwarfForge.jar").resolve()
    )
    assert (curated["language"], curated["compiler"]) == ("AARCH64:LE:64:v8A", "default")
    if args.role == "pie-rebased":
        assert curated["delta"] >= 0x2000000, curated["delta"]
    project_before = {
        str(path.relative_to(project)): support.digest(path)
        for path in project.rglob("*")
        if path.is_file()
    }
    write("project-before.json", project_before)
    hashes = None
    for iteration in ("first", "repeat"):
        run(
            iteration,
            [
                ghidra / "support/analyzeHeadless",
                project,
                "Aarch64Abi",
                "-process",
                binary.name,
                "-readOnly",
                "-noanalysis",
                "-scriptPath",
                scripts,
                "-postScript",
                "PrepareAarch64Vector.java",
                "observe",
                case / "labels.txt",
                case / (iteration + ".json"),
                "-postScript",
                "GhidraDwarfForge.java",
                "--packaged-natives",
                "--output=" + str(output),
            ],
            clean=False,
        )
        log = (case / (iteration + ".log")).read_text()
        assert "REPORT SCRIPT ERROR" not in log and "GhidraDwarfForge symbol export PASS" in log
        assert curated == json.loads((case / (iteration + ".json")).read_text())
        (report,) = [
            json.JSONDecoder().raw_decode(line.split("GhidraDwarfForge report: ", 1)[1])[0]
            for line in log.splitlines()
            if "GhidraDwarfForge report: " in line
        ]
        assert report["status"] in ("SUCCESS", "PARTIAL") and report["failure"] is None
        write(iteration + "-report.json", report)
        current = [support.digest(output), support.digest(Path(str(output) + ".c"))]
        assert hashes is None or hashes == current
        hashes = current
    run(
        "compiler-gnu",
        [
            "readelf",
            "-h",
            "-SW",
            "-n",
            "--debug-dump=info,abbrev,aranges,decodedline,loc",
            reference,
        ],
    )
    run("compiler-llvm", ["llvm-dwarfdump", "--verify", reference])
    run("compiler-reference", ["python3", source / "aarch64-vector-reference.py", case])
    run(
        "gnu",
        ["readelf", "-h", "-SW", "-n", "--debug-dump=info,abbrev,aranges,decodedline,loc", output],
    )
    run("llvm", ["llvm-dwarfdump", "--verify", output])
    run(
        "strict-driver",
        [
            "python3",
            source / "check-dwarfdump.py",
            output,
            case / "strict.log",
            "--original",
            binary,
        ],
    )
    run("locations", ["python3", source / "aarch64-vector-locations.py", case])
    failures = []
    for mode in ("compiler", "forge"):
        try:
            # The shell applies the shared exact diagnostic policy, including
            # only the compiler-corroborated QEMU synthetic-vDSO warning.
            run(mode + "-gdb", ["bash", source / "aarch64-vector-gdb.sh", case, mode], clean=False)
            assert not (case / (mode + "-gdb.stderr")).read_text().strip()
            assert (
                "AARCH64_VECTOR_" + mode.upper() + "_ORACLE_PASS"
                in (case / (mode + "-gdb.log")).read_text()
            )
        except (subprocess.CalledProcessError, RuntimeError, AssertionError) as error:
            failures.append({"mode": mode, "error": str(error)})
    assert before == {path: support.digest(Path(path)) for path in before}
    project_after = {
        str(path.relative_to(project)): support.digest(path)
        for path in project.rglob("*")
        if path.is_file()
    }
    write("project-after.json", project_after)
    changes = {
        name
        for name in project_before.keys() | project_after.keys()
        if project_before.get(name) != project_after.get(name)
    }
    # Ghidra rotates its filesystem index backups on read-only reopen. The
    # program database and live index must remain byte-identical.
    assert changes <= {
        "Aarch64Abi.rep/idata/~index.bak",
        "Aarch64Abi.rep/idata/~journal.bak",
    }, changes
    result = {
        "status": "FAILED" if failures else "CONTROLS_PENDING" if args.with_controls else "PASS",
        "failures": failures,
        "artifactSha256": hashes,
        "unchangedInputsAndProgramDatabase": True,
        "compilerReferenceReview": json.loads(
            (case / "compiler-reference-review.json").read_text()
        ),
        "projectBackupChanges": sorted(changes),
    }
    write("result.json", result)
    assert not failures, failures
    if args.with_controls:
        run("controls", ["python3", source / "aarch64-vector-controls.py", case, ghidra])
        (controls,) = case.glob("controls.*/result.json")
        result["controls"] = json.loads(controls.read_text())
        assert result["controls"]["status"] == "PASS"
        result["status"] = "PASS"
        write("result.json", result)
    print("aarch64-vector=PASS", case, flush=True)


if __name__ == "__main__":
    main()

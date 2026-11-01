#!/usr/bin/env python3
"""Reproduce mixed-body mode loss and isolate the standard-symbol consumer fix.

Research acceptance deliberately requires the old production failure. This must
not be used as an exporter support gate; production acceptance needs the original
sidecar to pass without the separate symbol-table experiment.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location("inventory", source / "arm-thumb-mode-check.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ghidra", type=Path)
    parser.add_argument("--production", action="store_true", help="require unmodified production sidecar to pass")
    parser.add_argument("--role", choices=("exec", "pie", "pie-rebased"), default="exec")
    parser.add_argument("--with-controls", action="store_true")
    args = parser.parse_args()
    if args.with_controls and not args.production:
        parser.error("failure/cancellation controls require production acceptance")
    ghidra = args.ghidra.resolve(strict=True)
    root = repository / "build/test-results/arm-mixed-reference"
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.role + ".", dir=root))
    print(case, flush=True)

    def run(label, command, expected=0, env=None):
        command = [str(value) for value in command]
        (case / (label + ".command.json")).write_text(json.dumps(command, indent=4) + "\n")
        with (case / (label + ".stdout")).open("wb") as out, (case / (label + ".stderr")).open("wb") as err:
            result = subprocess.run(command, stdout=out, stderr=err, env=env, timeout=240)
        assert result.returncode == expected, (label, result.returncode, expected)
        return (case / (label + ".stdout")).read_text()

    def clean(label):
        assert not (case / (label + ".stderr")).read_bytes(), label

    protected = [Path(__file__), source / "arm-mixed-mode-gdb.py", source / "arm-mixed-mapping-experiment.py",
        source / "arm-thumb-mode-check.py", source / "arm-mixed-mode-runtime.sh", source / "qemu-socket.sh",
        source / "ghidra_scripts/PrepareArmMixedBody.java",
        repository / "src/test/fixtures/arm-mixed-body.S", repository / "src/test/fixtures/arm-mixed-body-driver.c"]
    protected += [p for p in (ghidra / "Ghidra/Extensions/GhidraDwarfForge").rglob("*") if p.is_file()]
    before = {str(p): digest(p) for p in protected}
    compiler = os.environ.get("ARM32_CC", "arm-linux-gnueabihf-gcc")
    objcopy = os.environ.get("ARM32_OBJCOPY", "arm-linux-gnueabihf-objcopy")
    run("compile", [compiler, "-march=armv7-a", "-marm", "-mfpu=vfpv3-d16", "-mfloat-abi=hard",
        "-O0", "-g3", "-gdwarf-5", "-fno-pie" if args.role == "exec" else "-fPIE",
        "-no-pie" if args.role == "exec" else "-pie", "-Wl,--build-id=none",
        repository / "src/test/fixtures/arm-mixed-body.S", repository / "src/test/fixtures/arm-mixed-body-driver.c",
        "-o", case / "mixed.reference"])
    clean("compile")
    run("strip", [objcopy, "--strip-all", case / "mixed.reference", case / "mixed.stripped"])
    clean("strip")
    for tool in (compiler, objcopy, "gdb-multiarch", "qemu-arm-static", "readelf", "llvm-dwarfdump"):
        run(Path(tool).name + "-version", [tool, "--version"])
    image = inventory.elf(case / "mixed.reference")
    section = inventory.section(image, ".forge_mixed")
    start = section["row"][3]
    symbols = [s for s in image["symbols"] if s["section"] == section["index"]]
    assert section["row"][5] == 44
    assert [(s["name"], s["raw"] - start, s["size"], s["info"]) for s in symbols if s["name"].startswith("$")] == [
        ("$a", 0, 0, 0), ("$t", 16, 0, 0), ("$a", 24, 0, 0), ("$d", 40, 0, 0)]
    assert section["data"].hex() == "030080e204308fe2013083e213ff2fe1053000bf00a31847070080e204209fe5020080e01eff2fe134120000"
    (case / "labels.json").write_text(json.dumps({"start": start, "size": 44, "role": args.role,
        "symbols": symbols, "hex": section["data"].hex()}, indent=4) + "\n")
    before.update({str(case / name): digest(case / name) for name in ("mixed.reference", "mixed.stripped", "labels.json")})
    project = case / "project"
    project.mkdir()
    text = run("import", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-import",
        case / "mixed.stripped", "-analysisTimeoutPerFile", "120"])
    assert "REPORT: Import succeeded" in text
    text = run("prepare", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-process",
        "mixed.stripped", "-noanalysis", "-scriptPath", source / "ghidra_scripts",
        "-postScript", "PrepareArmMixedBody.java", hex(start), *(["0x200000"] if args.role == "pie-rebased" else [])])
    assert "REPORT SCRIPT ERROR" not in text
    program_before = {str(p.relative_to(project)): digest(p) for p in project.rglob("*") if p.is_file()}
    text = run("export", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-process",
        "mixed.stripped", "-noanalysis", "-readOnly", "-postScript", "GhidraDwarfForge.java",
        "--packaged-natives", "--output=" + str(case / "curated.dbg")])
    assert "GhidraDwarfForge symbol export PASS" in text and "REPORT SCRIPT ERROR" not in text
    model = inventory.transcript(case / "prepare.stdout", "ARM_MIXED_MODEL=")
    assert len(model["units"]) == 13 and all(row["inBody"] for row in model["units"][:12])
    assert not model["units"][-1]["inBody"]
    assert [(int(row["address"], 16) - start - model["imageBaseDelta"], row["mode"]) for row in model["units"][:12]] == [
        (offset, 1 if 16 <= offset < 24 else 0) for offset in (0, 4, 8, 12, 16, 18, 20, 22, 24, 28, 32, 36)]
    if args.role == "pie-rebased":
        assert model["imageBaseDelta"] == 0x200000
    if args.production:
        emitted = inventory.elf(case / "curated.dbg")
        allocation = inventory.section(emitted, ".forge_mixed")
        boundaries = [s for s in emitted["symbols"] if s["section"] == allocation["index"] and s["name"].startswith("$")]
        assert [(s["name"][:2], s["raw"] - start, s["size"], s["info"], s["other"]) for s in boundaries] == [
            ("$a", 0, 0, 0, 0), ("$t", 16, 0, 0, 0), ("$a", 24, 0, 0, 0), ("$d", 40, 0, 0, 0)]
    artifact_hashes = [digest(case / name) for name in ("curated.dbg", "curated.dbg.c")]
    run("repeat", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-process", "mixed.stripped",
        "-readOnly", "-noanalysis", "-postScript", "GhidraDwarfForge.java", "--packaged-natives",
        "--output=" + str(case / "curated.dbg")])
    assert artifact_hashes == [digest(case / name) for name in ("curated.dbg", "curated.dbg.c")]
    program_after = {str(p.relative_to(project)): digest(p) for p in project.rglob("*") if p.is_file()}
    changed = sorted(name for name in program_before.keys() | program_after.keys()
        if program_before.get(name) != program_after.get(name))
    assert set(changed) <= {"MixedModes.rep/idata/~index.bak", "MixedModes.rep/idata/~journal.bak"}, changed
    if not args.production:
        run("experiment", ["python3", source / "arm-mixed-mapping-experiment.py", case / "curated.dbg", case / "experiment.dbg"])
    results = {}
    for variant in (("compiler", "curated") if args.production else ("compiler", "curated", "experiment")):
        expected_failure = variant == "curated" and not args.production
        run(variant + "-gdb", ["bash", source / "arm-mixed-mode-runtime.sh", case, variant],
            expected=1 if expected_failure else 0)
        results[variant] = json.loads((case / (variant + "-gdb.json")).read_text())
        assert results[variant]["status"] == ("FAILED" if expected_failure else "PASS")
        assert len(results[variant]["observations"]) == 12 and results[variant]["exitCodes"] == [0]
        stderr = (case / (variant + "-gdb.stderr")).read_text()
        warnings = re.findall(r"^warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index\n", stderr, re.M)
        assert len(warnings) == 1
        remaining = stderr.replace(warnings[0], "")
        assert remaining == ("Python Exception <class 'AssertionError'>: mixed instruction widths differ before attachment\n"
            "Error occurred in Python: mixed instruction widths differ before attachment\n" if expected_failure else ""), remaining
    for artifact in (("mixed.reference", "curated.dbg") if args.production else ("mixed.reference", "curated.dbg", "experiment.dbg")):
        run(artifact + "-gnu", ["readelf", "-hSWn", "--debug-dump=info,abbrev,aranges,decodedline", case / artifact])
        clean(artifact + "-gnu")
        run(artifact + "-llvm", ["llvm-dwarfdump", "--verify", case / artifact])
        clean(artifact + "-llvm")
        run(artifact + "-strict", ["python3", source / "check-dwarfdump.py", case / artifact,
            case / (artifact + ".strict.log"), "--original", case / "mixed.stripped"])
    assert all(digest(Path(path)) == value for path, value in before.items())
    assert artifact_hashes == [digest(case / name) for name in ("curated.dbg", "curated.dbg.c")]
    (case / "result.json").write_text(json.dumps({"status": "PASS_PRODUCTION_BASIC" if args.production else "PASS_RESEARCH_REPRODUCTION",
        "productionSupport": args.production, "model": model, "protectedHashes": before,
        "artifactSha256": artifact_hashes, "programBefore": program_before, "programAfter": program_after,
        "rotatedProjectBackups": changed, "results": results}, indent=4) + "\n")
    if args.with_controls:
        run("controls", ["python3", source / "arm-mixed-mode-controls.py", ghidra, case])
        control, = case.glob("controls.*/result.json")
        assert json.loads(control.read_text())["status"] == "PASS"
    print("arm-mixed-mode-reference=" + ("PASS_PRODUCTION_BASIC" if args.production else "PASS_RESEARCH_REPRODUCTION") + " " + str(case))


if __name__ == "__main__":
    main()

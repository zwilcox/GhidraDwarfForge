#!/usr/bin/env python3
"""Keep complete ARM mode maps through actual native failure and production cancellation."""
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("reference", source / "arm-mixed-mode-reference.py")
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)
spec = importlib.util.spec_from_file_location("facts", source / "dynamic-parameter-storage-check.py")
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)
spec = importlib.util.spec_from_file_location('split_ranges', source / 'arm-mixed-range-check.py')
split_ranges = importlib.util.module_from_spec(spec)
spec.loader.exec_module(split_ranges)


def snapshot(directory):
    return {str(p.relative_to(directory)): reference.digest(p) for p in directory.rglob("*") if p.is_file()}


def unchanged(directory, before):
    after = snapshot(directory)
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    assert set(changed) <= {"MixedModes.rep/idata/~index.bak", "MixedModes.rep/idata/~journal.bak"}, changed
    return changed


def main(ghidra, baseline):
    ghidra, baseline = ghidra.resolve(strict=True), baseline.resolve(strict=True)
    accepted = json.loads((baseline / "result.json").read_text())
    assert accepted["status"] == "PASS_PRODUCTION_BASIC"
    case = Path(tempfile.mkdtemp(prefix="controls.", dir=baseline))
    print(case, flush=True)
    for name in ("mixed.stripped", "mixed.reference", "labels.json", "compiler-gdb.json"):
        shutil.copy2(baseline / name, case / name)
    if (baseline / "mixed.driver").is_file():
        shutil.copy2(baseline / "mixed.driver", case / "mixed.driver")
    shutil.copytree(baseline / "project", case / "project")
    module = ghidra / "Ghidra/Extensions/GhidraDwarfForge"
    for path, expected in accepted["protectedHashes"].items():
        if module in Path(path).parents:
            assert reference.digest(Path(path)) == expected, path
    paths = [Path(__file__), source / "arm-mixed-mode-reference.py", source / "arm-mixed-range-check.py",
        source / "arm-mixed-mode-runtime.sh", source / "arm-mixed-mode-gdb.py",
        source / "ghidra_scripts/AbiDecompilerFailureExport.java", source / "ghidra_scripts/CancelDuringElfCopy.java",
        source / "ghidra_scripts/PrepareArmMixedBody.java", *(module.rglob("*")),
        *(baseline / name for name in ("mixed.stripped", "mixed.reference", "curated.dbg", "curated.dbg.c")),
        *(case / name for name in ("mixed.stripped", "mixed.reference", "labels.json"))]
    if (case / "mixed.driver").is_file():
        paths += [case / "mixed.driver", baseline / "mixed.driver"]
    before = {str(p): reference.digest(p) for p in paths if p.is_file()}

    def run(label, command):
        command = [str(v) for v in command]
        (case / (label + ".command.json")).write_text(json.dumps(command, indent=4) + "\n")
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
        (case / (label + ".log")).write_bytes(result.stdout)
        assert result.returncode == 0, (label, result.returncode)
        return result.stdout.decode()

    program_before = snapshot(case / "project")
    hashes = None
    labels = json.loads((case / "labels.json").read_text())
    failure_selection = "recovered_mixed_body"
    if labels.get("sectionless", False):
        # The isolated high load segment makes mixed_body the last function.
        # Fail the compiler-identified caller, then require the later mixed body
        # to decompile and retain its full mappings and runtime behavior.
        image = reference.inventory.elf(case / "mixed.reference")
        caller, = [s for s in image["symbols"] if s["name"] == "main" and (s["info"] & 15) == 2]
        failure_selection = "@" + hex(caller["raw"] & ~1)
    for iteration in ("first", "repeat"):
        log = run("failure-" + iteration, [ghidra / "support/analyzeHeadless", case / "project", "MixedModes",
            "-process", "mixed.stripped", "-readOnly", "-noanalysis", "-scriptPath", source / "ghidra_scripts",
            "-postScript", "AbiDecompilerFailureExport.java", case / "curated.dbg", failure_selection, "--symbol-only"])
        selected, = re.findall(r"abi-decompiler-selected-failure=([^\s]+)", log)
        assert "abi-decompiler-failure=PASS" in log and "REPORT SCRIPT ERROR" not in log
        assert "Flow exceeded maximum allowable instructions" in log
        current = [reference.digest(case / name) for name in ("curated.dbg", "curated.dbg.c")]
        assert hashes is None or hashes == current
        hashes = current
    body = (case / "curated.dbg.c").read_text()
    assert "Flow exceeded maximum allowable instructions" in body
    info = run("gnu", ["readelf", "-hSWn", "--debug-dump=info,abbrev,aranges,decodedline,loc", case / "curated.dbg"])
    dies = facts.die_records(info)
    index, failed = next((i, d) for i, d in enumerate(dies) if d["tag"] == "DW_TAG_subprogram" and
        facts.die_name(d) == selected)
    assert "DW_AT_decl_line" not in failed["attrs"] and "DW_AT_type" not in failed["attrs"]
    if labels.get('split', False) and selected == 'recovered_mixed_body':
        assert 'DW_AT_low_pc' not in failed['attrs'] and 'DW_AT_high_pc' not in failed['attrs']
        raw = reference.inventory.section(reference.inventory.elf(case / 'curated.dbg'), '.debug_rnglists')['data']
        split_ranges.check_ranges(raw, split_ranges.range_offset(failed['attrs']['DW_AT_ranges']), labels['start'])
    else:
        assert 'DW_AT_low_pc' in failed['attrs']
    assert dies[index + 1]["depth"] <= failed["depth"]
    assert "No errors." in run("llvm", ["llvm-dwarfdump", "--verify", case / "curated.dbg"])
    run("strict", ["python3", source / "check-dwarfdump.py", case / "curated.dbg", case / "strict.log",
        "--original", case / "mixed.stripped"])
    image = reference.inventory.elf(case / "curated.dbg")
    original = reference.inventory.elf(baseline / "curated.dbg")
    assert [s for s in image["symbols"] if s["name"].startswith("$")] == [
        s for s in original["symbols"] if s["name"].startswith("$")]
    if labels.get('retainSymbols', False):
        reference.check_inherited(reference.inventory.elf(case / 'mixed.stripped'), image)
    runtime_log = run("runtime", ["bash", source / "arm-mixed-mode-runtime.sh", case, "curated"])
    warnings = [line for line in runtime_log.splitlines() if line.startswith("warning:")]
    compiler_warnings = (baseline / "compiler-gdb.stderr").read_text().splitlines()
    vdso = re.compile(r"warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index")
    assert all(vdso.fullmatch(line) for line in warnings + compiler_warnings)
    assert not (Counter(vdso.sub("<vdso>", line) for line in warnings) -
        Counter(vdso.sub("<vdso>", line) for line in compiler_warnings))
    runtime = json.loads((case / "curated-gdb.json").read_text())
    assert runtime["status"] == "PASS" and len(runtime["observations"]) == len(reference.fixture(labels.get('split', False))['offsets'])
    program_changes = unchanged(case / "project", program_before)
    padded = case / "padded"
    shutil.copy2(case / "mixed.stripped", padded)
    with padded.open("r+b") as stream:
        stream.truncate(128 * 1024 * 1024)
    before[str(padded)] = reference.digest(padded)
    project = case / "cancel-project"
    project.mkdir()
    labels = json.loads((case / "labels.json").read_text())
    prepare = reference.prepare_arguments(labels)
    log = run("cancel-import", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-import", padded,
        "-analysisTimeoutPerFile", "120", "-scriptPath", source / "ghidra_scripts",
        "-postScript", "PrepareArmMixedBody.java", *prepare])
    assert "ARM_MIXED_MODEL=" in log and "REPORT SCRIPT ERROR" not in log
    cancel_before = snapshot(project)
    log = run("cancel-export", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-process", "padded",
        "-readOnly", "-noanalysis", "-scriptPath", source / "ghidra_scripts", "-postScript",
        "CancelDuringElfCopy.java", padded, case / "curated.dbg"])
    assert "production-copy-cancellation=PASS" in log and '"status":"CANCELLED"' in log
    assert hashes == [reference.digest(case / name) for name in ("curated.dbg", "curated.dbg.c")]
    cancel_changes = unchanged(project, cancel_before)
    assert before == {p: reference.digest(Path(p)) for p in before}
    assert not any(p.name.startswith(".") for p in case.iterdir())
    (case / "result.json").write_text(json.dumps({"status": "PASS", "role": labels["role"],
        "failureExports": 2, "cancelledExports": 1, "failedFunction": selected, "runtime": runtime, "protectedHashes": before,
        "programBackupChanges": program_changes, "cancelBackupChanges": cancel_changes}, indent=4) + "\n")
    print("arm-mixed-mode-controls=PASS " + str(case))


if __name__ == "__main__":
    main(*(Path(arg) for arg in sys.argv[1:]))

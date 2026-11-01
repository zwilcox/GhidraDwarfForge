#!/usr/bin/env python3
"""Reproduce mixed-body mode loss and isolate the standard-symbol consumer fix.

Research acceptance deliberately requires the old production failure. This must
not be used as an exporter support gate; production acceptance needs the original
sidecar to pass without the separate symbol-table experiment.
"""
import argparse
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location("inventory", source / "arm-thumb-mode-check.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture(split=False):
    """Source-known bytes/behavior, independently compared with compiler and Forge."""
    shift = 8 if split else 0
    offsets = ([0] if split else []) + [shift + value for value in (0, 4, 8, 12, 16, 18, 20, 22, 24, 28, 32, 36)]
    values = ([11] if split else []) + [11, 14, 14, 14, 14, 19, 19, 19, 19, 26, 26, 4686]
    boundaries = ([('a', 0), ('d', 4)] if split else []) + [
        ('a', shift), ('t', shift + 16), ('a', shift + 24), ('d', shift + 40)]
    data = ([4] if split else []) + [shift + 40]
    units = sorted(offsets + data)
    return {'size': shift + 44, 'codeEnd': shift + 40, 'thumb': [shift + 16, shift + 24],
        'offsets': offsets, 'values': values, 'boundaries': boundaries, 'data': data, 'units': units,
        'lengths': [2 if shift + 16 <= at < shift + 24 else 4 for at in units],
        'ranges': [(0, 4), (8, 48)] if split else [(0, 40)],
        'hex': ('000000eacefaedfe' if split else '') +
            '030080e204308fe2013083e213ff2fe1053000bf00a31847070080e204209fe5020080e01eff2fe134120000'}


def prepare_arguments(labels):
    args = [hex(labels['start'])]
    if labels['role'].endswith('-rebased') or labels.get('split', False):
        args.append('0x200000' if labels['role'].endswith('-rebased') else '0')
    if labels.get('split', False):
        args.append('split')
    return args



def check_inherited(original, output):
    """Every original symbol/string byte survives around any new local records."""
    old = inventory.section(original, '.symtab')
    new = inventory.section(output, '.symtab')
    old_local, new_local = old['row'][7], new['row'][7]
    assert 0 < old_local <= new_local <= len(output['symbols'])
    assert old['row'][9] == new['row'][9] == 16
    assert new['data'][:old_local * 16] + new['data'][new_local * 16:] == old['data']
    assert output['sections'][new['row'][6]]['data'].startswith(original['sections'][old['row'][6]]['data'])
    inherited = [row for row in original['symbols'] if row['name'].startswith('$')]
    assert inherited and inherited == [row for row in output['symbols'] if row['name'].startswith('$')]
    assert all(row['info'] >> 4 == 0 for row in output['symbols'][:new_local])
    assert all(row['info'] >> 4 != 0 for row in output['symbols'][new_local:])
    return {'inheritedSymbols': len(original['symbols']), 'inheritedMappings': len(inherited),
        'insertedLocals': new_local - old_local}


def inherited_controls(original, output):
    rejected = []
    for kind in ('missing-original-record', 'changed-original-record', 'changed-string-prefix', 'duplicate-mapping'):
        altered = deepcopy(output)
        table = inventory.section(altered, '.symtab')
        if kind == 'missing-original-record':
            table['data'] = table['data'][:-16]
        elif kind == 'changed-original-record':
            table['data'] = table['data'][:-1] + bytes([table['data'][-1] ^ 1])
        elif kind == 'changed-string-prefix':
            strings = altered['sections'][table['row'][6]]
            strings['data'] = bytes([strings['data'][0] ^ 1]) + strings['data'][1:]
        else:
            altered['symbols'].append(next(row for row in altered['symbols'] if row['name'].startswith('$')))
        try:
            check_inherited(original, altered)
        except AssertionError:
            rejected.append(kind)
        else:
            raise AssertionError('inherited inventory corruption accepted: ' + kind)
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ghidra", type=Path)
    parser.add_argument("--production", action="store_true", help="require unmodified production sidecar to pass")
    parser.add_argument("--role", choices=("exec", "pie", "pie-rebased", "shared", "shared-rebased"), default="exec")
    parser.add_argument("--with-controls", action="store_true")
    parser.add_argument("--with-live", action="store_true")
    parser.add_argument("--with-omissions", action="store_true")
    parser.add_argument("--sectionless", action="store_true")
    parser.add_argument("--split", action="store_true")
    parser.add_argument("--retain-symbols", action="store_true")
    args = parser.parse_args()
    if args.sectionless and not args.production:
        parser.error("sectionless reference requires production acceptance")
    if args.with_controls and not args.production:
        parser.error("failure/cancellation controls require production acceptance")
    if args.with_live and not args.production:
        parser.error("live-session checks require production acceptance")
    if args.split and not args.production:
        parser.error("split-body fixture requires production acceptance")
    if args.retain_symbols and (not args.production or args.sectionless):
        parser.error("inherited symbols require a sectioned production fixture")
    if args.with_omissions and (not args.production or not args.split or args.retain_symbols):
        parser.error("omission controls require a stripped split production fixture")
    expected = fixture(args.split)
    ghidra = args.ghidra.resolve(strict=True)
    root = repository / "build/test-results/arm-mixed-reference"
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.role + (".split" if args.split else "") +
        (".retained" if args.retain_symbols else "") +
        (".sectionless." if args.sectionless else "."), dir=root))
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
        source / "arm-mixed-inventory.py", source / "sectionless-alias-check.py",
        source / "arm-mixed-range-check.py", source / "dynamic-parameter-storage-check.py",
        source / "retained-function-aliases-export.py",
        source / "arm-mixed-omission-controls.py", source / "ghidra_scripts/ExportArmMixedUnknownData.java",
        source / "arm-mixed-live-export.py", source / "ghidra_scripts/RepeatLiveAbiExport.java",
        source / "arm-thumb-mode-check.py", source / "arm-mixed-mode-runtime.sh", source / "qemu-socket.sh",
        source / "ghidra_scripts/PrepareArmMixedBody.java",
        repository / "src/test/fixtures/arm-mixed-body.S", repository / "src/test/fixtures/arm-mixed-body-driver.c"]
    protected += [p for p in (ghidra / "Ghidra/Extensions/GhidraDwarfForge").rglob("*") if p.is_file()]
    before = {str(p): digest(p) for p in protected}
    compiler = os.environ.get("ARM32_CC", "arm-linux-gnueabihf-gcc")
    objcopy = os.environ.get("ARM32_OBJCOPY", "arm-linux-gnueabihf-objcopy")
    shared = args.role.startswith("shared")
    common = [compiler, "-march=armv7-a", "-marm", "-mfpu=vfpv3-d16", "-mfloat-abi=hard",
        "-O0", "-g3", "-gdwarf-5"]
    if args.split:
        common.append('-DFORGE_MIXED_SPLIT=1')
    inputs = [repository / "src/test/fixtures/arm-mixed-body.S"]
    if not shared:
        inputs += [repository / "src/test/fixtures/arm-mixed-body-driver.c"]
    model = ["-fPIC", "-shared", "-Wl,-soname,mixed.stripped", "-Wl,--hash-style=both"] if shared else [
        "-fno-pie" if args.role == "exec" else "-fPIE", "-no-pie" if args.role == "exec" else "-pie"]
    if args.sectionless:
        model += ["-Wl,--hash-style=both", "-Wl,--section-start=.forge_mixed=0x20000"]
    run("compile", common + model + ["-Wl,--build-id=none", *inputs, "-o", case / "mixed.reference"])
    clean("compile")
    run("strip", [objcopy, "--strip-debug" if args.retain_symbols else "--strip-all", case / "mixed.reference", case / "mixed.stripped"])
    clean("strip")
    mapping_allocation = ".forge_mixed"
    if args.sectionless:
        stripped = case / "mixed.stripped"
        shutil.copy2(stripped, case / "mixed.sectioned")
        before[str(case / "mixed.sectioned")] = digest(case / "mixed.sectioned")
        data = bytearray(stripped.read_bytes())
        phoff = struct.unpack_from("<I", data, 28)[0]
        phwidth, phcount = struct.unpack_from("<HH", data, 42)
        assert phwidth == 32
        loads = []
        candidates = []
        for index in range(phcount):
            entry = struct.unpack_from("<8I", data, phoff + index * phwidth)
            if entry[0] == 1 and entry[5]:
                loads.append(index)
                if entry[2] == 0x20000:
                    assert entry[4:7] == (expected['size'], expected['size'], 5)
                    candidates.append((index, len(loads)))
        assert len(candidates) == 1
        mapping_allocation = ".forge.load." + str(candidates[0][0])
        struct.pack_into("<I", data, 32, 0)
        struct.pack_into("<HH", data, 48, 0, 0)
        stripped.write_bytes(data)
    if shared:
        run("driver", common + ["-fno-pie", "-no-pie", "-Wl,--build-id=none",
            repository / "src/test/fixtures/arm-mixed-body-driver.c", "-L" + str(case),
            "-Wl,-rpath,$ORIGIN", "-l:mixed.reference", "-o", case / "mixed.driver"])
        clean("driver")
        before[str(case / "mixed.driver")] = digest(case / "mixed.driver")
    for tool in (compiler, objcopy, "gdb-multiarch", "qemu-arm-static", "readelf", "llvm-dwarfdump"):
        run(Path(tool).name + "-version", [tool, "--version"])
    image = inventory.elf(case / "mixed.reference")
    section = inventory.section(image, ".forge_mixed")
    start = section["row"][3]
    symbols = [s for s in image["symbols"] if s["section"] == section["index"]]
    assert section["row"][5] == expected['size']
    assert [(s["name"], s["raw"] - start, s["size"], s["info"]) for s in symbols if s["name"].startswith("$")] == [
        ('$' + tag, at, 0, 0) for tag, at in expected['boundaries']]
    assert section["data"].hex() == expected['hex']
    labels = {"start": start, "size": expected['size'], "role": args.role, "shared": shared, 'split': args.split, 'retainSymbols': args.retain_symbols,
        "textAddress": inventory.section(image, ".text")["row"][3],
        "sectionless": args.sectionless, "mappingAllocation": mapping_allocation,
        "symbols": symbols, "hex": section["data"].hex()}
    (case / "labels.json").write_text(json.dumps(labels, indent=4) + "\n")
    before.update({str(case / name): digest(case / name) for name in ("mixed.reference", "mixed.stripped", "labels.json")})
    project = case / "project"
    project.mkdir()
    text = run("import", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-import",
        case / "mixed.stripped", "-loader", "ElfLoader", "-analysisTimeoutPerFile", "120"])
    assert "REPORT: Import succeeded" in text
    text = run("prepare", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-process",
        "mixed.stripped", "-noanalysis", "-scriptPath", source / "ghidra_scripts",
        "-postScript", "PrepareArmMixedBody.java", *prepare_arguments(labels)])
    assert "REPORT SCRIPT ERROR" not in text
    program_before = {str(p.relative_to(project)): digest(p) for p in project.rglob("*") if p.is_file()}
    text = run("export", [ghidra / "support/analyzeHeadless", project, "MixedModes", "-process",
        "mixed.stripped", "-noanalysis", "-readOnly", "-postScript", "GhidraDwarfForge.java",
        "--packaged-natives", "--output=" + str(case / "curated.dbg")])
    assert "GhidraDwarfForge symbol export PASS" in text and "REPORT SCRIPT ERROR" not in text
    model = inventory.transcript(case / "prepare.stdout", "ARM_MIXED_MODEL=")
    assert len(model['units']) == len(expected['units'])
    for row, offset, width in zip(model['units'], expected['units'], expected['lengths']):
        assert int(row['address'], 16) - start - model['imageBaseDelta'] == offset
        assert row['size'] == width and row['bytes'] == expected['hex'][offset * 2:(offset + width) * 2]
        assert row['inBody'] == row['instruction'] == (offset in expected['offsets'])
        if row['instruction']:
            assert row['mode'] == int(expected['thumb'][0] <= offset < expected['thumb'][1])
    if args.role.endswith("-rebased"):
        assert model["imageBaseDelta"] == 0x200000
    if args.production:
        emitted = inventory.elf(case / "curated.dbg")
        allocation = inventory.section(emitted, mapping_allocation)
        boundaries = [s for s in emitted["symbols"] if s["section"] == allocation["index"] and s["name"].startswith("$")]
        assert [(s["name"][:2], s["raw"] - start, s["size"], s["info"], s["other"]) for s in boundaries] == [
            ('$' + tag, at, 0, 0, 0) for tag, at in expected['boundaries']]
        if args.retain_symbols:
            original = inventory.elf(case / 'mixed.stripped')
            receipt = check_inherited(original, emitted)
            receipt['rejectedCorruptions'] = inherited_controls(original, emitted)
            (case / 'inherited-symbols.json').write_text(json.dumps(receipt, indent=4) + '\n')
        if args.sectionless:
            run("raw-inventory", ["python3", source / "arm-mixed-inventory.py", case])
            clean("raw-inventory")
        if args.split:
            run('split-ranges', ['python3', source / 'arm-mixed-range-check.py', case])
            clean('split-ranges')
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
        assert len(results[variant]["observations"]) == len(expected['offsets']) and results[variant]["exitCodes"] == [0]
        stderr = (case / (variant + "-gdb.stderr")).read_text()
        warnings = re.findall(r"^warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index\n", stderr, re.M)
        assert len(warnings) == 1
        remaining = stderr.replace(warnings[0], "")
        assert remaining == ("Python Exception <class 'AssertionError'>: mixed instruction widths differ before attachment\n"
            "Error occurred in Python: mixed instruction widths differ before attachment\n" if expected_failure else ""), remaining
    if args.production:
        for variant in ("compiler", "curated"):
            for phase in ("next", "step", "address", "calls"):
                label = variant + "-" + phase
                run(label, ["bash", source / "arm-mixed-mode-runtime.sh", case, variant, phase])
                observation = json.loads((case / (label + "-gdb.json")).read_text())
                assert observation["status"] == "PASS" and observation["exitCodes"] == [0]
                assert (case / (label + ".stderr")).read_text() == (case / "compiler-gdb.stderr").read_text()
                results[label] = observation
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
    if args.with_live:
        run("live", ["python3", source / "arm-mixed-live-export.py", ghidra, case])
        live, = case.glob("live.*/result.json")
        assert json.loads(live.read_text())["status"] == "PASS"
    if args.with_omissions:
        run('omissions', ['python3', source / 'arm-mixed-omission-controls.py', ghidra, case])
        omission, = case.glob('omissions.*/result.json')
        assert json.loads(omission.read_text())['status'] == 'PASS'
    print("arm-mixed-mode-reference=" + ("PASS_PRODUCTION_BASIC" if args.production else "PASS_RESEARCH_REPRODUCTION") + " " + str(case))


if __name__ == "__main__":
    main()

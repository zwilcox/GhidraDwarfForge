#!/usr/bin/env python3
"""Real exports omit unsupported mapping evidence without inventing data modes."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mixed_reference', source / 'arm-mixed-mode-reference.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def main(ghidra, baseline):
    ghidra, baseline = ghidra.resolve(strict=True), baseline.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    labels = json.loads((baseline / 'labels.json').read_text())
    assert accepted['status'] == 'PASS_PRODUCTION_BASIC'
    assert labels['split'] and not labels.get('retainSymbols', False)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    for path, expected in accepted['protectedHashes'].items():
        if module in Path(path).parents:
            assert reference.digest(Path(path)) == expected
    root = Path(tempfile.mkdtemp(prefix='omissions.', dir=baseline))
    print(root, flush=True)
    protected = [Path(__file__), source / 'arm-mixed-mode-reference.py', source / 'arm-mixed-mode-gdb.py',
        source / 'arm-mixed-mode-runtime.sh', source / 'qemu-socket.sh',
        source / 'ghidra_scripts/ExportArmMixedUnknownData.java', source / 'ghidra_scripts/RepeatLiveAbiExport.java',
        *module.rglob('*'), *(baseline / name for name in ('mixed.stripped', 'curated.dbg', 'curated.dbg.c'))]
    before = {str(p): reference.digest(p) for p in protected if p.is_file()}
    results = []
    for offset in (4, 48):
        case = root / ('unknown-' + str(offset))
        case.mkdir()
        for name in ('mixed.stripped', 'mixed.reference', 'labels.json', 'compiler-gdb.json', 'mixed.driver'):
            if (baseline / name).is_file():
                shutil.copy2(baseline / name, case / name)
        shutil.copytree(baseline / 'project', case / 'project')
        program = {str(p.relative_to(case)): reference.digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
        originals = {str(p): reference.digest(p) for p in case.iterdir() if p.is_file()}

        def run(label, command, expected=0):
            command = [str(v) for v in command]
            (case / (label + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
            process = subprocess.run(command, capture_output=True, timeout=240)
            (case / (label + '.stdout')).write_bytes(process.stdout)
            (case / (label + '.stderr')).write_bytes(process.stderr)
            assert process.returncode == expected, (label, process.returncode)
            return process.stdout.decode(), process.stderr.decode()

        log, _ = run('export', [ghidra / 'support/analyzeHeadless', case / 'project', 'MixedModes',
            '-process', 'mixed.stripped', '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'ExportArmMixedUnknownData.java', hex(labels['start']), str(offset), case / 'curated.dbg'])
        assert 'REPORT SCRIPT ERROR' not in log and 'mixed-unknown-data-export=PASS' in log
        assert 'live-abi-export-repeat=PASS' in log and log.count('GhidraDwarfForge symbol export PASS') == 2
        diagnostic = 'Omitted ARM32 section mappings for ' + labels['mappingAllocation'] + ': unknown bytes cannot be mapped as data'
        assert diagnostic in log
        image = reference.inventory.elf(case / 'curated.dbg')
        allocation = reference.inventory.section(image, labels['mappingAllocation'])
        assert not [s for s in image['symbols'] if s['section'] == allocation['index'] and s['name'].startswith('$')]
        for tool, command in (
                ('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', case / 'curated.dbg']),
                ('llvm', ['llvm-dwarfdump', '--verify', case / 'curated.dbg']),
                ('strict', ['python3', source / 'check-dwarfdump.py', case / 'curated.dbg', case / 'strict.log',
                    '--original', case / 'mixed.stripped']),
                ('ranges', ['python3', source / 'arm-mixed-range-check.py', case])):
            out, err = run(tool, command)
            assert not err
            if tool == 'llvm':
                assert 'No errors.' in out
        # The ordinary runtime oracle must report the exact known static loss,
        # after all thirteen instruction values and normal program exit pass.
        _, err = run('runtime', ['bash', source / 'arm-mixed-mode-runtime.sh', case, 'curated'], expected=1)
        runtime = json.loads((case / 'curated-gdb.json').read_text())
        assert runtime['status'] == 'FAILED' and not runtime['staticWidthsMatch']
        assert len(runtime['observations']) == 13 and runtime['exitCodes'] == [0]
        expected_error = "Python Exception <class 'AssertionError'>: mixed instruction widths differ before attachment\nError occurred in Python: mixed instruction widths differ before attachment\n"
        assert err == (baseline / 'compiler-gdb.stderr').read_text() + expected_error
        after = {str(p.relative_to(case)): reference.digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
        changed = sorted(p for p in program.keys() | after.keys() if program.get(p) != after.get(p))
        assert set(changed) <= {'project/MixedModes.rep/idata/~index.bak', 'project/MixedModes.rep/idata/~journal.bak'}
        assert originals == {p: reference.digest(Path(p)) for p in originals}
        results.append({'offset': offset, 'status': 'PASS_OMISSION_CONTROL', 'diagnostic': diagnostic,
            'runtime': runtime, 'programBackupChanges': changed,
            'artifactSha256': [reference.digest(case / name) for name in ('curated.dbg', 'curated.dbg.c')]})
    assert before == {p: reference.digest(Path(p)) for p in before}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'results': results,
        'protectedHashes': before}, indent=4) + '\n')
    print('arm-mixed-omission-controls=PASS', root, flush=True)


if __name__ == '__main__':
    main(*(Path(arg) for arg in sys.argv[1:]))

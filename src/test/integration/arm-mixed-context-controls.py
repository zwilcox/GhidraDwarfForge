#!/usr/bin/env python3
"""Real mixed-body exports with changed context and contradictory inherited modes."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mixed_reference', source / 'arm-mixed-mode-reference.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def conflicting_input(case, kind, run):
    """Change only inherited symbol metadata; keep every target instruction byte."""
    run('retain', [os.environ.get('ARM32_OBJCOPY', 'arm-linux-gnueabihf-objcopy'),
        '--strip-debug', case / 'mixed.reference', case / 'mixed.stripped'])
    image = reference.inventory.elf(case / 'mixed.stripped')
    allocation = reference.inventory.section(image, '.forge_mixed')
    data = bytearray(image['data'])
    changes = []
    for table in image['sections']:
        if table['row'][1] != 2:
            continue
        assert table['row'][2] & 2 == 0  # non-allocated .symtab only
        strings = image['sections'][table['row'][6]]['data']
        for offset in range(0, len(table['data']), 16):
            name, value, size, info, other, section = struct.unpack_from('<IIIBBH', table['data'], offset)
            text = strings[name:strings.index(0, name)]
            if section != allocation['index']:
                continue
            if kind == 'mapping' and text == b'$t':
                assert table['row'][1] == 2 and value == allocation['row'][3] + 24
                replacement = strings.index(b'\0$a\0') + 1
                at, prior = table['row'][4] + offset, name
            elif kind == 'function-tag' and text == b'mixed_body':
                assert info & 15 == 2 and value == allocation['row'][3]
                at, prior, replacement = table['row'][4] + offset + 4, value, value | 1
            else:
                continue
            struct.pack_into('<I', data, at, replacement)
            changes.append({'table': table['name'], 'offset': at, 'before': prior, 'after': replacement})
    assert len(changes) == 1
    allowed = {at for row in changes for at in range(row['offset'], row['offset'] + 4)}
    actual = {i for i, (before, after) in enumerate(zip(image['data'], data)) if before != after}
    assert actual and actual <= allowed and len(image['data']) == len(data)
    phoff = struct.unpack_from('<I', data, 28)[0]
    phwidth, phcount = struct.unpack_from('<HH', data, 42)
    assert phwidth == 32
    for index in range(phcount):
        segment = struct.unpack_from('<8I', data, phoff + index * phwidth)
        if segment[0] == 1:
            begin, end = segment[1], segment[1] + segment[4]
            assert data[begin:end] == image['data'][begin:end], 'control changed loaded bytes'
    (case / 'mixed.stripped').write_bytes(data)
    altered = reference.inventory.elf(case / 'mixed.stripped')
    assert reference.inventory.section(altered, '.forge_mixed')['data'] == allocation['data']
    (case / 'mutations.json').write_text(json.dumps(changes, indent=4) + '\n')
    return altered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('--control', choices=('context', 'mapping', 'function-tag'), action='append')
    args = parser.parse_args()
    ghidra, baseline = args.ghidra.resolve(strict=True), args.baseline.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    labels = json.loads((baseline / 'labels.json').read_text())
    assert accepted['status'] == 'PASS_PRODUCTION_BASIC' and labels['split']
    assert not labels.get('retainSymbols', False)
    controls = args.control or ['context', 'mapping', 'function-tag']
    assert not labels.get('sectionless', False) or controls == ['context']
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    for path, expected in accepted['protectedHashes'].items():
        if module in Path(path).parents:
            assert reference.digest(Path(path)) == expected
    protected = [Path(__file__), source / 'ghidra_scripts/ExportArmMixedContext.java',
        source / 'ghidra_scripts/PrepareArmMixedConflict.java', source / 'ghidra_scripts/PrepareArmMixedBody.java',
        source / 'ghidra_scripts/RepeatLiveAbiExport.java', source / 'arm-mixed-mode-reference.py',
        source / 'arm-mixed-mode-gdb.py', source / 'arm-mixed-mode-runtime.sh', source / 'qemu-socket.sh',
        source / 'arm-mixed-range-check.py', source / 'arm-thumb-mode-check.py',
        source / 'check-dwarfdump.py', source / 'dynamic-parameter-storage-check.py',
        *module.rglob('*'), *(baseline / name for name in ('mixed.stripped', 'mixed.reference', 'mixed.driver',
            'labels.json', 'result.json', 'curated.dbg', 'curated.dbg.c', 'compiler-gdb.json', 'compiler-gdb.stderr')),
        *(baseline / 'project').rglob('*')]
    before = {str(p): reference.digest(p) for p in protected if p.is_file()}
    root = Path(tempfile.mkdtemp(prefix='context-controls.', dir=baseline))
    (root / 'protected-before.json').write_text(json.dumps(before, indent=4) + '\n')
    print(root, flush=True)
    results = []
    for kind in controls:
        case = root / kind
        case.mkdir()
        for name in ('mixed.stripped', 'mixed.reference', 'labels.json', 'compiler-gdb.json', 'mixed.driver'):
            if (baseline / name).is_file():
                shutil.copy2(baseline / name, case / name)
        def run(label, command, expected=0):
            command = list(map(str, command))
            (case / (label + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
            process = subprocess.run(command, capture_output=True, timeout=240)
            (case / (label + '.stdout')).write_bytes(process.stdout)
            (case / (label + '.stderr')).write_bytes(process.stderr)
            assert process.returncode == expected, (case, label, process.returncode, expected)
            return process.stdout.decode(), process.stderr.decode()

        altered = conflicting_input(case, kind, run) if kind != 'context' else None
        if kind == 'context':
            shutil.copytree(baseline / 'project', case / 'project')
        else:
            # Import the actual mutated file: never override Ghidra's imported
            # executable identity to smuggle different input past preflight.
            (case / 'project').mkdir()
            log, _ = run('import', [ghidra / 'support/analyzeHeadless', case / 'project', 'MixedModes',
                '-import', case / 'mixed.stripped', '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120'])
            assert 'REPORT: Import succeeded' in log
            log, _ = run('prepare', [ghidra / 'support/analyzeHeadless', case / 'project', 'MixedModes',
                '-process', 'mixed.stripped', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
                '-postScript', 'PrepareArmMixedConflict.java', *reference.prepare_arguments(labels)])
            assert 'REPORT SCRIPT ERROR' not in log and 'mixed-conflict-curation=PASS' in log
        original = {str(p): reference.digest(p) for p in case.iterdir() if p.is_file()}
        program = {str(p.relative_to(case)): reference.digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
        log, _ = run('export', [ghidra / 'support/analyzeHeadless', case / 'project', 'MixedModes',
            '-process', 'mixed.stripped', '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'ExportArmMixedContext.java', hex(labels['start']), case / 'mixed.stripped',
            case / 'curated.dbg', kind])
        assert 'REPORT SCRIPT ERROR' not in log and 'mixed-context-export=PASS control=' + kind in log
        repeats = 3 if kind == 'context' else 1
        assert log.count('live-abi-export-repeat=PASS') == repeats
        assert log.count('GhidraDwarfForge symbol export PASS') == repeats * 2
        reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert len(reports) == repeats * 2
        assert all(not report['failedFunctions'] and report['failure'] is None for report in reports)
        image = reference.inventory.elf(case / 'curated.dbg')
        allocation = reference.inventory.section(image, labels['mappingAllocation'])
        mappings = [s for s in image['symbols'] if s['section'] == allocation['index'] and s['name'].startswith('$')]
        if kind == 'context':
            diagnostic = 'Omitted ARM32 section mappings for ' + labels['mappingAllocation'] + ': unknown bytes cannot be mapped as data'
            assert 'mixed-context-write-rejected=PASS' in log and 'mixed-context-restoration=PASS' in log
            assert not mappings
        else:
            reason = 'inherited mapping contradicts listing' if kind == 'mapping' else 'inherited function tag contradicts listing'
            diagnostic = 'Omitted ARM32 section mappings for section ' + str(allocation['index']) + ': ' + reason
            if kind == 'function-tag' and labels['shared']:
                diagnostic = ('Omitted ARM32 section mappings: original symbol inventory: '
                    'conflicting original mode evidence at one address')
            reference.check_inherited(altered, image)
            assert mappings and all('.forge_' not in row['name'] for row in mappings)
        assert diagnostic in log, diagnostic
        for tool, command in (
                ('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', case / 'curated.dbg']),
                ('llvm', ['llvm-dwarfdump', '--verify', case / 'curated.dbg']),
                ('strict', ['python3', source / 'check-dwarfdump.py', case / 'curated.dbg', case / 'strict.log',
                    '--original', case / 'mixed.stripped']),
                ('ranges', ['python3', source / 'arm-mixed-range-check.py', case,
                    *(['--entry-only'] if kind == 'context' else [])])):
            out, err = run(tool, command)
            assert not err, (tool, err)
            if tool == 'llvm':
                assert 'No errors.' in out
        # Correct inherited mapping intervals still let GDB decode the function
        # in the function-tag conflict case. A wrong inherited Thumb mapping or
        # completely absent mapping has a distinct, exactly checked consequence.
        successful_decode = kind == 'function-tag'
        _, err = run('runtime', ['bash', source / 'arm-mixed-mode-runtime.sh', case, 'curated'],
            expected=0 if successful_decode else 1)
        runtime = json.loads((case / 'curated-gdb.json').read_text())
        assert runtime['status'] == ('PASS' if successful_decode else 'FAILED')
        assert runtime['staticWidthsMatch'] == successful_decode
        assert len(runtime['observations']) == 13 and runtime['exitCodes'] == [0]
        expected_error = '' if successful_decode else "Python Exception <class 'AssertionError'>: mixed instruction widths differ before attachment\nError occurred in Python: mixed instruction widths differ before attachment\n"
        assert err == (baseline / 'compiler-gdb.stderr').read_text() + expected_error, err
        if kind == 'context':
            shutil.copy2(case / 'split-dwarf-ranges.json', case / 'omitted-dwarf-ranges.json')
            for suffix in ('', '.c'):
                shutil.copy2(case / ('curated.dbg.restored' + suffix), case / ('curated.dbg' + suffix))
            for tool, command in (
                    ('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', case / 'curated.dbg']),
                    ('llvm', ['llvm-dwarfdump', '--verify', case / 'curated.dbg']),
                    ('strict', ['python3', source / 'check-dwarfdump.py', case / 'curated.dbg', case / 'restored-strict.log',
                        '--original', case / 'mixed.stripped']),
                    ('ranges', ['python3', source / 'arm-mixed-range-check.py', case])):
                out, err = run('restored-' + tool, command)
                assert not err, (tool, err)
                if tool == 'llvm':
                    assert 'No errors.' in out
            _, err = run('restored-runtime', ['bash', source / 'arm-mixed-mode-runtime.sh', case, 'curated'])
            assert err == (baseline / 'compiler-gdb.stderr').read_text()
            restored = json.loads((case / 'curated-gdb.json').read_text())
            assert restored['status'] == 'PASS' and len(restored['observations']) == 13
        else:
            restored = None
        after = {str(p.relative_to(case)): reference.digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
        changed = sorted(p for p in program.keys() | after.keys() if program.get(p) != after.get(p))
        assert set(changed) <= {'project/MixedModes.rep/idata/~index.bak', 'project/MixedModes.rep/idata/~journal.bak'}
        assert original == {p: reference.digest(Path(p)) for p in original}
        results.append({'control': kind, 'diagnostic': diagnostic, 'runtime': runtime,
            'restoredRuntime': restored, 'programBackupChanges': changed})
    changed = [p for p in before if before[p] != reference.digest(Path(p))]
    assert not changed, changed
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'results': results,
        'protectedHashes': before}, indent=4) + '\n')
    print('arm-mixed-context-controls=PASS', root, flush=True)


if __name__ == '__main__':
    main()

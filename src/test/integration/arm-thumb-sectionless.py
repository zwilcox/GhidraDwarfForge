#!/usr/bin/env python3
"""Fresh sectionless imports of independently compiled ARM/Thumb mode fixtures."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]

def module(name, leaf):
    spec = importlib.util.spec_from_file_location(name, source / leaf)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

facts = module('thumb_facts', 'arm-thumb-mode-check.py')
inventory = module('sectionless_inventory', 'sectionless-alias-check.py')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('base', type=Path)
    parser.add_argument('--expect-omission', action='store_true', help='Require the documented empty-GNU-hash symbol-count refusal')
    parser.add_argument('--output', type=Path, default=repository / 'build/test-results/arm-thumb-sectionless')
    args = parser.parse_args()
    base = args.base.resolve(strict=True)
    ghidra = args.ghidra.resolve(strict=True)
    installed = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    accepted = json.loads((base / 'result.json').read_text())
    assert accepted['status'] == 'PASS'
    labels = json.loads((base / 'labels.json').read_text())
    assert labels['role'] in ('exec', 'pie', 'pie-rebased', 'pie-dynamic')
    labels['sectionless'] = True
    args.output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=labels['role'] + '.', dir=args.output.resolve()))
    print(case, flush=True)
    for leaf in ('project', 'empty-debug'):
        (case / leaf).mkdir()
    shutil.copyfile(base / 'thumb.reference', case / 'thumb.reference')
    data = bytearray((base / 'thumb.stripped').read_bytes())
    assert data[:7] == b'\x7fELF\x01\x01\x01'
    struct.pack_into('<I', data, 32, 0)
    struct.pack_into('<HH', data, 48, 0, 0)
    binary = case / 'thumb.stripped'
    binary.write_bytes(data)
    binary.chmod((base / "thumb.stripped").stat().st_mode & 0o777)
    (case / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    protected = [p for p in base.rglob('*') if p.is_file()]
    protected += [p for p in installed.rglob('*') if p.is_file()]
    protected += [binary, case / 'thumb.reference', Path(__file__), source / 'arm-thumb-mode-runtime.sh',
        source / 'arm-thumb-mode-gdb.py', source / 'arm-thumb-mode-check.py', source / 'sectionless-alias-check.py',
        source / 'ghidra_scripts/PrepareArmThumbMode.java', source / 'check-dwarfdump.py']
    before = {str(p): digest(p) for p in protected}
    (case / 'protected-before.json').write_text(json.dumps(before, indent=4) + '\n')

    def run(label, argv, timeout=240):
        argv = list(map(str, argv))
        (case / (label + '.command.json')).write_text(json.dumps(argv, indent=4) + '\n')
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
        (case / (label + '.log')).write_bytes(result.stdout)
        (case / (label + '.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, (case, label, result.returncode, result.stderr)
        if Path(argv[0]).name != 'analyzeHeadless':
            assert not result.stderr, (label, result.stderr)
        return result.stdout.decode()

    for phase in ('calls', 'from-arm'):
        run('reference-' + phase, ['bash', source / 'arm-thumb-mode-runtime.sh', case, 'compiler', phase])
    run('import', [ghidra / 'support/analyzeHeadless', case / 'project', 'ThumbModes', '-import', binary,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120'])
    prepare = [hex(labels[n]['code']) for n in ('thumb_add', 'arm_call', 'main', 'thumb_sink', 'thumb_pointer', 'arm_after')]
    if labels['role'] == 'pie-rebased':
        prepare.append('0x200000')
    common = [ghidra / 'support/analyzeHeadless', case / 'project', 'ThumbModes', '-process', binary.name, '-noanalysis']
    export = ['-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'thumb.dbg')]
    first = run('export-first', [*common, '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'PrepareArmThumbMode.java', *prepare, *export])
    assert 'GhidraDwarfForge symbol export PASS' in first
    for leaf in ('thumb.dbg', 'thumb.dbg.c'):
        shutil.copyfile(case / leaf, case / ('first.' + leaf))
    project_before = {str(p.relative_to(case / 'project')): digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
    repeat = run('export-repeat', [*common, '-readOnly', *export])
    assert 'GhidraDwarfForge symbol export PASS' in repeat
    for leaf in ('thumb.dbg', 'thumb.dbg.c'):
        assert (case / leaf).read_bytes() == (case / ('first.' + leaf)).read_bytes()
    reports = [facts.transcript(case / ('export-' + role + '.log'), 'GhidraDwarfForge report: ') for role in ('first', 'repeat')]
    assert reports[0] == reports[1] and reports[0]['failure'] is None and not reports[0]['failedFunctions']
    for view in ('info', 'abbrev', 'aranges', 'decodedline', 'rawline', 'loc', 'Ranges'):
        run('forge-' + view, ['readelf', '--debug-dump=' + view, case / 'thumb.dbg'])
    run('header', ['readelf', '-hSWsn', case / 'thumb.dbg'])
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', case / 'thumb.dbg'])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'thumb.dbg', case / 'strict-check.log',
        '--original', binary, '--frame-reference', base / 'thumb.stripped'])
    output = facts.elf(case / 'thumb.dbg')
    generated = [row for row in output['symbols'] if row['name'].startswith('__forge_arm_mode_')]
    if args.expect_omission:
        reference = facts.elf(base / 'thumb.reference')
        assert not any(row['name'] == '.hash' for row in reference['sections'])
        hashed = facts.section(reference, '.gnu.hash')['data']
        buckets, first, bloom, shift = struct.unpack_from('<4I', hashed)
        assert buckets > 0 and bloom > 0 and not any(struct.unpack_from('<' + 'I' * buckets, hashed, 16 + 4 * bloom))
        assert not generated and not any(row['name'] == '.symtab' for row in output['sections'])
        assert reports[0]['status'] == 'PARTIAL'
        assert any('complete PT_DYNAMIC symbol count unavailable; empty GNU hash is not a count' in item
            for item in reports[0]['diagnostics'])
    else:
        assert generated
        # Exact inventory is tied to the independently checked sectioned baseline,
        # rather than accepting whatever the new output happened to contain.
        baseline = facts.elf(base / 'thumb.dbg')
        expected = [row for row in baseline['symbols'] if row['name'].startswith('__forge_arm_mode_')]
        # With section roles absent Ghidra also treats the four-instruction PLT
        # resolver prefix as a definition. Audit its original bytes and compiler
        # mapping boundary rather than deriving an expected symbol from the output.
        reference = facts.elf(base / 'thumb.reference')
        plt = facts.section(reference, '.plt')
        assert struct.unpack_from('<4I', plt['data']) == (0xe52de004, 0xe59fe004, 0xe08fe00e, 0xe5bef008)
        plt_entry = plt['row'][3]
        mappings = [(row['raw'], row['name'].split('.')[0]) for row in reference['symbols']
            if row['section'] == plt['index'] and row['name'].split('.')[0] in ('$a', '$t', '$d')]
        assert (plt_entry, '$a') in mappings and (plt_entry + 16, '$d') in mappings
        extra_name = '__forge_arm_mode_%08x' % plt_entry
        if not any(row['name'] == extra_name for row in expected):
            expected.append({'name': extra_name, 'raw': plt_entry, 'size': 16})
        aliases = [{'alias': row['name'], 'entry': row['raw'] & ~1, 'size': row['size']} for row in expected]
        values = {row['name']: row['raw'] for row in expected}
        inventory.verify(base / 'thumb.stripped', binary, case / 'thumb.dbg', aliases, case / 'raw-inventory.json', values)
        inventory.corruption_controls(base / 'thumb.stripped', binary, case / 'thumb.dbg', aliases,
            case / 'inventory-negative-controls', values)
    vdso = re.compile(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index')
    for phase in (() if args.expect_omission else ('calls', 'from-arm')):
        run('forge-' + phase, ['bash', source / 'arm-thumb-mode-runtime.sh', case, 'forge', phase])
        warnings = []
        for variant in ('compiler', 'forge'):
            result = json.loads((case / (variant + '-' + phase + '.json')).read_text())
            assert result['status'] == 'PASS' and result['exitCode'] == 0
            assert result['instructionSource'] == 'remote-before-continue'
            lines = (case / (variant + '-' + phase + '.stderr')).read_text().splitlines()
            assert all(vdso.fullmatch(line) for line in lines), lines
            warnings.append(Counter(vdso.sub('<oracle-vdso>', line) for line in lines))
            assert (case / (variant + '-' + phase + '.qemu.status')).read_text() == 'exit=0\n'
            assert not (case / (variant + '-' + phase + '.qemu.stderr')).read_bytes()
        # A sectionless sidecar may not trigger GDB's synthetic-vDSO probe.
        # Every Forge warning must still have an exact compiler counterpart.
        assert not (warnings[1] - warnings[0])
    after = {p: digest(Path(p)) for p in before}
    assert before == after
    project_after = {str(p.relative_to(case / 'project')): digest(p) for p in (case / 'project').rglob('*') if p.is_file()}
    changes = {p for p in project_before.keys() | project_after.keys() if project_before.get(p) != project_after.get(p)}
    assert changes <= {'ThumbModes.rep/idata/~index.bak', 'ThumbModes.rep/idata/~journal.bak'}, changes
    (case / 'protected-after.json').write_text(json.dumps(after, indent=4) + '\n')
    (case / 'result.json').write_text(json.dumps({'status': 'PASS_EXPECTED_MODE_OMISSION' if args.expect_omission else 'PASS', 'role': labels['role'],
        'sectionless': True, 'base': str(base), 'packageJarSha256': digest(installed / 'lib/GhidraDwarfForge.jar'),
        'report': reports[0], 'programBackupChanges': sorted(changes)}, indent=4) + '\n')
    if not args.expect_omission:
        run('failure-cancellation', ['python3', source / 'arm-thumb-mode-controls.py', ghidra, case])
    print(('arm-thumb-sectionless-omission=PASS ' if args.expect_omission else 'arm-thumb-sectionless=PASS ') + str(case))

if __name__ == '__main__':
    main()

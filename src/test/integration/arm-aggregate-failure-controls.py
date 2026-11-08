#!/usr/bin/env python3
"""Real native failure isolation and copy cancellation around validated ARM aggregates."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hfa', source / 'arm-hfa-lifetimes.py')
hfa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hfa)
dies = hfa.load('aggregate_dies', source / 'arm-dynamic-pcs-check.py')
facts = hfa.load('aggregate_elf', source / 'arm-thumb-mode-check.py')
reference = hfa.load('aggregate_reference', source / 'arm-pcs-call-reference.py')


def snapshot(root):
    return {str(p.relative_to(root)): hfa.digest(p) for p in root.rglob('*') if p.is_file()}


def main(baseline):
    baseline = baseline.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    assert accepted['status'] == 'PASS_HFA_CONTROLS'
    profile = json.loads((baseline / 'profile.json').read_text())
    root = Path(tempfile.mkdtemp(prefix='failure-controls.', dir=baseline))
    print(root, flush=True)
    protected = json.loads((baseline / 'protected-before.json').read_text())
    for path in [Path(__file__), source / 'arm-dynamic-pcs-check.py',
            source / 'ghidra_scripts/AbiDecompilerFailureExport.java',
            source / 'ghidra_scripts/CancelDuringElfCopy.java',
            *(baseline / name for name in ('calls.dbg', 'calls.dbg.c', 'labels.json', 'labels.txt', 'profile.json'))]:
        protected[str(path)] = hfa.digest(path)
    assert protected == {p: hfa.digest(Path(p)) for p in protected}
    baseline_program = snapshot(baseline / 'project')
    project = root / 'project'
    shutil.copytree(baseline / 'project', project)
    program_before = snapshot(project)
    headless = Path(profile['ghidra']) / 'support/analyzeHeadless'
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'command': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('wb') as out, (root / (label + '.err')).open('wb') as err:
            outcome = subprocess.run(command, stdout=out, stderr=err, timeout=240)
        assert outcome.returncode == 0, (root, label, outcome.returncode)
        error = (root / (label + '.err')).read_bytes()
        if Path(command[0]).name == 'analyzeHeadless':
            assert error == (baseline / 'import.err').read_bytes(), (label, error)
        else:
            assert not error, (label, error)
        text = (root / (label + '.log')).read_text()
        assert 'REPORT SCRIPT ERROR' not in text
        return text

    image = facts.elf(baseline / 'calls.reference', allow_big_endian=True)
    start, = [symbol for symbol in image['symbols'] if symbol['name'] == '_start']
    aggregate = json.loads((baseline / 'labels.json').read_text())['hfa_control']
    results = {}
    for role, entry in (('neighbor', start['raw']), ('aggregate', aggregate)):
        case = root / role
        case.mkdir()
        for name in ('calls.input', 'calls.reference', 'labels.json'):
            shutil.copy2(baseline / name, case / name)
            protected[str(case / name)] = hfa.digest(case / name)
        current_profile = dict(profile, symbolOnly=role == 'aggregate')
        (case / 'profile.json').write_text(json.dumps(current_profile, indent=4) + '\n')
        protected[str(case / 'profile.json')] = hfa.digest(case / 'profile.json')
        hashes = None
        for iteration in ('first', 'repeat'):
            text = run(role + '-' + iteration, [headless, project, 'Hfa', '-process', 'calls.input',
                '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
                '-postScript', 'AbiDecompilerFailureExport.java', case / 'calls.dbg', '@' + hex(entry),
                '--symbol-only' if role == 'neighbor' else 'value'])
            assert 'abi-decompiler-failure=PASS' in text and 'Flow exceeded maximum allowable instructions' in text
            selected, = re.findall(r'abi-decompiler-selected-failure=([^\s]+)', text)
            current = [hfa.digest(case / name) for name in ('calls.dbg', 'calls.dbg.c')]
            assert hashes is None or hashes == current
            hashes = current
        assert 'Flow exceeded maximum allowable instructions' in (case / 'calls.dbg.c').read_text()
        info = run(role + '-gnu', ['readelf', '-hSn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'calls.dbg'])
        records = dies.records(info)
        failed, = [row for row in records if row['tag'] == 'DW_TAG_subprogram' and dies.name(row) == selected]
        assert int(failed['attrs']['DW_AT_low_pc'], 16) == entry
        assert not {'DW_AT_type', 'DW_AT_decl_line', 'DW_AT_frame_base'}.intersection(failed['attrs'])
        assert records[records.index(failed) + 1]['depth'] <= failed['depth']
        assert 'No errors.' in run(role + '-llvm', ['llvm-dwarfdump', '--verify', case / 'calls.dbg'])
        run(role + '-strict', ['python3', source / 'check-dwarfdump.py', case / 'calls.dbg', case / 'strict.log',
            '--original', case / 'calls.input'])
        exported = facts.elf(case / 'calls.dbg', allow_big_endian=True)
        assert exported['data'][:16] == image['data'][:16]
        assert exported['header'][:4] == image['header'][:4] and exported['header'][6] == image['header'][6]
        assert exported['header'][4] == exported['header'][9] == 0
        assert facts.section(exported, '.text')['data'] == facts.section(image, '.text')['data']
        run(role + '-runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'forge',
            profile['qemu'], profile['gdb'], profile['gdbData'], source / 'arm-hfa-controls-gdb.py'])
        runtime = json.loads((case / 'forge-gdb.json').read_text())
        assert runtime['status'] == 'PASS_HFA_CONTROLS' and len(runtime['observations']) == 14
        if role == 'neighbor':
            assert sum('typed' in row for row in runtime['observations']) == accepted['forgeTypedInstructions']
            assert sum('unavailable' in row for row in runtime['observations']) == accepted['unavailableInstructions']
            assert not any('symbolOnly' in row for row in runtime['observations'])
        else:
            assert all(row.get('symbolOnly') for row in runtime['observations'])
            assert not any('typed' in row or 'unavailable' in row for row in runtime['observations'])
        warnings = (case / 'forge.stderr').read_text().splitlines()
        assert len(warnings) <= 1
        for warning in warnings:
            assert warning == 'Failed to read a valid object file image from memory.' or re.fullmatch(
                r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning)
            reference.corroborate_unmapped_vdso_sections(runtime)
        assert (case / 'forge.qemu.status').read_text() == 'exit=0\n'
        assert not (case / 'forge.qemu.stderr').read_bytes()
        results[role] = {'failedFunction': selected, 'hashes': hashes, 'runtime': runtime}
    cancellation = root / 'cancellation'
    cancellation.mkdir()
    for name in ('calls.input', 'calls.dbg', 'calls.dbg.c'):
        shutil.copy2(baseline / name, cancellation / name)
    padded = cancellation / 'padded'
    shutil.copy2(cancellation / 'calls.input', padded)
    with padded.open('r+b') as stream:
        stream.truncate(128 * 1024 * 1024)
    for path in cancellation.iterdir():
        protected[str(path)] = hfa.digest(path)
    cancel_project = root / 'cancel-project'
    cancel_project.mkdir()
    text = run('cancel-import', [headless, cancel_project, 'Hfa', '-import', padded,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'PrepareArmHfaControls.java', 'curate', baseline / 'labels.txt', root / 'cancel-curate.json', profile['storage']])
    assert 'hfa-control-preparation=PASS' in text
    cancel_before = snapshot(cancel_project)
    text = run('cancel', [headless, cancel_project, 'Hfa', '-process', 'padded', '-readOnly', '-noanalysis',
        '-scriptPath', source / 'ghidra_scripts', '-postScript', 'CancelDuringElfCopy.java',
        padded, cancellation / 'calls.dbg'])
    assert 'production-copy-cancellation=PASS' in text and '"status":"CANCELLED"' in text
    copied, = re.findall(r'copy-cancelled-after-bytes=(\d+)', text)
    assert 0 < int(copied) <= 16 * 1024 * 1024
    program_after = snapshot(project)
    cancel_after = snapshot(cancel_project)
    for before, after in ((program_before, program_after), (cancel_before, cancel_after)):
        assert {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)} <= {
            'Hfa.rep/idata/~index.bak', 'Hfa.rep/idata/~journal.bak'}
    assert baseline_program == snapshot(baseline / 'project')
    assert protected == {path: hfa.digest(Path(path)) for path in protected}
    assert not any(p.name.startswith('.') for p in cancellation.iterdir())
    result = {'status': 'PASS', 'failureExports': 4, 'cancellations': 1, 'results': results,
        'cancelledAfterBytes': int(copied), 'protectedHashes': protected,
        'programBefore': program_before, 'programAfter': program_after,
        'cancelBefore': cancel_before, 'cancelAfter': cancel_after}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    (baseline / 'failure-controls.json').write_text(json.dumps(result, indent=4) + '\n')
    print('arm-aggregate-failure-controls=PASS', flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]))

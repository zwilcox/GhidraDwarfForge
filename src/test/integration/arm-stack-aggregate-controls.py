#!/usr/bin/env python3
"""Failure isolation and production-copy cancellation for natural ARM aggregates."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('driver', source / 'arm-stack-aggregates.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
facts = driver.load('aggregate_elf', source / 'arm-thumb-mode-check.py')
reference = driver.load('aggregate_vdso', source / 'arm-pcs-call-reference.py')


def main(baseline):
    baseline = baseline.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    assert accepted['status'] == 'PASS' and accepted['availabilityContract'] == 'audited-prefix'
    profile = json.loads((baseline / 'profile.json').read_text())
    root = Path(tempfile.mkdtemp(prefix='failure-controls.', dir=baseline))
    print(root, flush=True)
    protected = json.loads((baseline / 'protected-before.json').read_text())
    assert protected == {path: driver.digest(Path(path)) for path in protected}
    for path in [Path(__file__), source / 'ghidra_scripts/AbiDecompilerFailureExport.java',
            source / 'ghidra_scripts/CancelDuringElfCopy.java',
            *(baseline / name for name in ('calls.dbg', 'calls.dbg.c', 'labels.json', 'labels.txt',
                'profile.json', 'instruction-inventory.json'))]:
        protected[str(path)] = driver.digest(path)
    baseline_program = driver.tree(baseline / 'project')
    project = root / 'project'
    shutil.copytree(baseline / 'project', project)
    project_before = driver.tree(project)
    (root / 'project-before.json').write_text(json.dumps(project_before, indent=4) + '\n')
    headless = Path(profile['ghidra']) / 'support/analyzeHeadless'
    commands = []

    def run(label, command):
        command = list(map(str, command))
        row = {'label': label, 'command': command}
        commands.append(row)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('wb') as out, (root / (label + '.err')).open('wb') as err:
            outcome = subprocess.run(command, stdout=out, stderr=err, timeout=240)
        row['exit'] = outcome.returncode
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert outcome.returncode == 0, (root, label, outcome.returncode)
        error = (root / (label + '.err')).read_bytes()
        assert error == ((baseline / 'import.err').read_bytes() if Path(command[0]).name == 'analyzeHeadless' else b''), (label, error)
        text = (root / (label + '.log')).read_text()
        assert 'REPORT SCRIPT ERROR' not in text
        return text

    image = facts.elf(baseline / 'calls.reference', allow_big_endian=True)
    start, = [symbol for symbol in image['symbols'] if symbol['name'] == '_start']
    labels = json.loads((baseline / 'labels.json').read_text())
    results = {}
    baseline_runtime = json.loads((baseline / 'forge-gdb.json').read_text())
    for role in ('neighbor', 'base_packed', 'base_bytes', 'base_floats'):
        entry = start['raw'] if role == 'neighbor' else labels[role]
        case = root / role
        case.mkdir()
        for name in ('calls.input', 'calls.reference', 'labels.json', 'instruction-inventory.json'):
            shutil.copy2(baseline / name, case / name)
            protected[str(case / name)] = driver.digest(case / name)
        hashes = None
        for iteration in ('first', 'repeat'):
            text = run(role + '-' + iteration, [headless, project, 'Stack', '-process', 'calls.input',
                '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
                '-postScript', 'AbiDecompilerFailureExport.java', case / 'calls.dbg', '@' + hex(entry),
                '--symbol-only' if role == 'neighbor' else 'value'])
            assert 'abi-decompiler-failure=PASS' in text and 'Flow exceeded maximum allowable instructions' in text
            selected, = re.findall(r'abi-decompiler-selected-failure=([^\s]+)', text)
            assert role == 'neighbor' or selected == role
            current = [driver.digest(case / name) for name in ('calls.dbg', 'calls.dbg.c')]
            assert hashes is None or hashes == current
            hashes = current
        (case / 'profile.json').write_text(json.dumps(dict(profile, failedFunction=selected), indent=4) + '\n')
        protected[str(case / 'profile.json')] = driver.digest(case / 'profile.json')
        assert 'Flow exceeded maximum allowable instructions' in (case / 'calls.dbg.c').read_text()
        info = run(role + '-gnu', ['readelf', '-hSn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'calls.dbg'])
        (case / 'dbg-info.log').write_text(info)
        assert 'No errors.' in run(role + '-llvm', ['llvm-dwarfdump', '--verify', case / 'calls.dbg'])
        run(role + '-strict', ['python3', source / 'check-dwarfdump.py', case / 'calls.dbg', case / 'strict.log',
            '--original', case / 'calls.input'])
        run(role + '-physical-locations', ['python3', source / 'arm-stack-aggregates-locations.py', case])
        exported = facts.elf(case / 'calls.dbg', allow_big_endian=True)
        assert exported['data'][:16] == image['data'][:16]
        assert exported['header'][:4] == image['header'][:4] and exported['header'][6] == image['header'][6]
        assert exported['header'][4] == exported['header'][9] == 0
        assert facts.section(exported, '.text')['data'] == facts.section(image, '.text')['data']
        run(role + '-runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'forge',
            profile['qemu'], profile['gdb'], profile['gdbData'], source / 'arm-stack-aggregates-gdb.py'])
        runtime = json.loads((case / 'forge-gdb.json').read_text())
        assert runtime['status'] == 'PASS' and len(runtime['entry']) == 14
        assert len(runtime['observations']) == accepted['forgeObservations']
        expected_symbols = [row for row in baseline_runtime['observations'] if row['name'] == selected]
        assert sum(bool(row.get('symbolOnly')) for row in runtime['observations']) == len(expected_symbols)
        assert len(runtime['carrierObservations']) == accepted['physicalCarrierObservations'] - len(expected_symbols)
        assert runtime['unavailable'] == [row for row in baseline_runtime['unavailable'] if row['name'] != selected]
        assert [row for row in runtime['observations'] if row['name'] != selected] == [
            row for row in baseline_runtime['observations'] if row['name'] != selected]
        warnings = (case / 'forge.stderr').read_text().splitlines()
        assert len(warnings) <= 1
        for warning in warnings:
            assert warning == 'Failed to read a valid object file image from memory.' or re.fullmatch(
                r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning)
            reference.corroborate_unmapped_vdso_sections(runtime)
        assert (case / 'forge.qemu.status').read_text() == 'exit=0\n'
        assert not (case / 'forge.qemu.stderr').read_bytes()
        results[role] = {'failedFunction': selected, 'hashes': hashes,
            'symbolOnlyInstructions': len(expected_symbols), 'neighborInstructions': len(runtime['carrierObservations'])}
    cancellation = root / 'cancellation'
    cancellation.mkdir()
    for name in ('calls.input', 'calls.dbg', 'calls.dbg.c'):
        shutil.copy2(baseline / name, cancellation / name)
    padded = cancellation / 'padded'
    shutil.copy2(cancellation / 'calls.input', padded)
    with padded.open('r+b') as stream:
        stream.truncate(128 * 1024 * 1024)
    for path in cancellation.iterdir():
        protected[str(path)] = driver.digest(path)
    cancel_project = root / 'cancel-project'
    cancel_project.mkdir()
    text = run('cancel-import', [headless, cancel_project, 'Stack', '-import', padded,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        *(['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if profile['role'].endswith('-rebased') else []),
        '-postScript', 'PrepareArmStackAggregates.java', 'curate', baseline / 'labels.txt', root / 'cancel-curate.json'])
    assert 'arm-stack-aggregates-preparation=PASS' in text
    cancel_before = driver.tree(cancel_project)
    (root / 'cancel-before.json').write_text(json.dumps(cancel_before, indent=4) + '\n')
    text = run('cancel', [headless, cancel_project, 'Stack', '-process', 'padded', '-readOnly', '-noanalysis',
        '-scriptPath', source / 'ghidra_scripts', '-postScript', 'CancelDuringElfCopy.java',
        padded, cancellation / 'calls.dbg'])
    assert 'production-copy-cancellation=PASS' in text and '"status":"CANCELLED"' in text
    copied, = re.findall(r'copy-cancelled-after-bytes=(\d+)', text)
    assert 0 < int(copied) <= 16 * 1024 * 1024
    project_after, cancel_after = driver.tree(project), driver.tree(cancel_project)
    (root / 'project-after.json').write_text(json.dumps(project_after, indent=4) + '\n')
    (root / 'cancel-after.json').write_text(json.dumps(cancel_after, indent=4) + '\n')
    assert project_before == project_after
    rotated = {p for p in cancel_before.keys() | cancel_after.keys() if cancel_before.get(p) != cancel_after.get(p)}
    assert rotated <= {'Stack.rep/idata/~index.bak', 'Stack.rep/idata/~journal.bak'}, rotated
    assert baseline_program == driver.tree(baseline / 'project')
    assert protected == {path: driver.digest(Path(path)) for path in protected}
    assert not any(path.name.startswith('.') for path in cancellation.iterdir())
    result = {'status': 'PASS', 'failureExports': 8, 'cancellations': 1, 'results': results,
        'cancelledAfterBytes': int(copied), 'protectedHashes': protected,
        'savedProgramDataUnchanged': True, 'rotatedIndexBackups': sorted(rotated), 'existingOutputsUnchanged': True}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    (baseline / 'failure-controls.json').write_text(json.dumps(result, indent=4) + '\n')
    print('arm-stack-aggregate-controls=PASS', flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]))

#!/usr/bin/env python3
"""Preserve ARM PCS/declaration policy through native failure and production cancellation."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('pcs', source / 'arm-pcs-profile.py')
pcs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pcs)


def snapshot(directory):
    return {str(p.relative_to(directory)): pcs.digest(p) for p in directory.rglob('*') if p.is_file()}


def main(baseline):
    baseline = baseline.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    assert accepted['status'] in ('PASS', 'PASS_BASELINE')
    profile = accepted['profile']
    ghidra = Path(profile['ghidra'])
    case = Path(tempfile.mkdtemp(prefix='controls.', dir=baseline))
    print(case, flush=True)
    for name in ('calls.input', 'calls.reference', 'profile.json'):
        shutil.copy2(baseline / name, case / name)
    shutil.copytree(baseline / 'project', case / 'project')
    protected = {path: pcs.digest(Path(path)) for path in accepted['protectedAfter']}
    assert protected == accepted['protectedAfter'], 'baseline inputs or tools changed'
    for path in [Path(__file__), source / 'ghidra_scripts/AbiDecompilerFailureExport.java',
            source / 'ghidra_scripts/CancelDuringElfCopy.java', baseline / 'calls.dbg', baseline / 'calls.dbg.c',
            *(case / name for name in ('calls.input', 'calls.reference', 'profile.json'))]:
        protected[str(path)] = pcs.digest(path)
    baseline_program = snapshot(baseline / 'project')
    program_before = snapshot(case / 'project')
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'command': command})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('wb') as out, (case / (label + '.err')).open('wb') as err:
            outcome = subprocess.run(command, stdout=out, stderr=err, timeout=240)
        assert outcome.returncode == 0, (case, label, outcome.returncode)
        stderr = (case / (label + '.err')).read_bytes()
        if Path(command[0]).name == 'analyzeHeadless':
            assert stderr == (baseline / 'java-version.stderr').read_bytes()
        else:
            assert not stderr, (label, stderr)
        return (case / (label + '.log')).read_text()

    image = pcs.facts.elf(case / 'calls.reference', allow_big_endian=True)
    entry, = [symbol for symbol in image['symbols'] if symbol['name'] == '_start']
    hashes = None
    for iteration in ('first', 'repeat'):
        log = run('failure-' + iteration, [ghidra / 'support/analyzeHeadless', case / 'project', 'Pcs',
            '-process', 'calls.input', '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'AbiDecompilerFailureExport.java', case / 'calls.dbg', '@' + hex(entry['raw']), '--symbol-only'])
        assert 'abi-decompiler-failure=PASS' in log and 'REPORT SCRIPT ERROR' not in log
        assert 'Flow exceeded maximum allowable instructions' in log
        selected, = re.findall(r'abi-decompiler-selected-failure=([^\s]+)', log)
        current = [pcs.digest(case / name) for name in ('calls.dbg', 'calls.dbg.c')]
        assert hashes is None or hashes == current
        hashes = current
    assert 'Flow exceeded maximum allowable instructions' in (case / 'calls.dbg.c').read_text()
    info = run('gnu', ['readelf', '-hSn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'calls.dbg'])
    records = pcs.dies.records(info)
    failed, = [record for record in records if record['tag'] == 'DW_TAG_subprogram' and pcs.dies.name(record) == selected]
    assert 'DW_AT_type' not in failed['attrs'] and 'DW_AT_decl_line' not in failed['attrs']
    assert int(failed['attrs']['DW_AT_low_pc'], 16) == entry['raw']
    assert records[records.index(failed) + 1]['depth'] <= failed['depth']
    for old in accepted['rawCallingConventions']:
        new, = [record for record in records if record['tag'] == old['tag'] and pcs.dies.name(record) == pcs.dies.name(old)]
        for attribute in ('DW_AT_calling_convention', 'DW_AT_declaration', 'DW_AT_external', 'DW_AT_prototyped'):
            assert new['attrs'].get(attribute) == old['attrs'].get(attribute), (pcs.dies.name(old), attribute)
        if old['attrs'].get('DW_AT_declaration') == '1':
            assert not {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges', 'DW_AT_location',
                'DW_AT_decl_file', 'DW_AT_decl_line', 'DW_AT_frame_base'}.intersection(new['attrs'])
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', case / 'calls.dbg'])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'calls.dbg', case / 'strict.log',
        '--original', case / 'calls.input'])
    emulator = profile['qemu_armeb'] if profile['order'] == 'big' else profile['qemu_arm']
    run('runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'forge', emulator,
        profile['gdb'], profile['gdb_data']])
    runtime = json.loads((case / 'forge-gdb.json').read_text())
    assert runtime['status'] == 'PASS' and runtime['exitCode'] == 0
    warnings = (case / 'forge.stderr').read_text().splitlines()
    assert len(warnings) <= 1
    for warning in warnings:
        if warning == 'Failed to read a valid object file image from memory.':
            pcs.reference.corroborate_unmapped_vdso_sections(runtime)
        else:
            assert re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning)
    assert (case / 'forge.qemu.status').read_text() == 'exit=0\n'
    assert not (case / 'forge.qemu.stderr').read_bytes()
    padded = case / 'padded'
    shutil.copy2(case / 'calls.input', padded)
    with padded.open('r+b') as stream:
        stream.truncate(128 * 1024 * 1024)
    protected[str(padded)] = pcs.digest(padded)
    # Import the actual padded fixture so production's original-image hash
    # check remains enabled and copying, rather than identity validation, is cancelled.
    cancel_project = case / 'cancel-project'
    cancel_project.mkdir()
    log = run('cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'Pcs', '-import', padded,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'PrepareArmPcsProfile.java', 'curate', baseline / 'labels.txt', case / 'cancel-curate.json',
        *(['implicit-default'] if profile['implicit_default'] else []),
        *(['guard-controls'] if profile['guard_controls'] else []),
        *(['declarations'] if profile['declarations'] else [])])
    assert 'arm-pcs-profile-preparation=PASS' in log and 'REPORT SCRIPT ERROR' not in log
    cancel_before = snapshot(cancel_project)
    log = run('cancel', [ghidra / 'support/analyzeHeadless', cancel_project, 'Pcs',
        '-process', 'padded', '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'CancelDuringElfCopy.java', padded, case / 'calls.dbg'])
    assert 'production-copy-cancellation=PASS' in log and '"status":"CANCELLED"' in log
    assert hashes == [pcs.digest(case / name) for name in ('calls.dbg', 'calls.dbg.c')]
    program_after = snapshot(case / 'project')
    changed = sorted(p for p in program_before.keys() | program_after.keys() if program_before.get(p) != program_after.get(p))
    assert set(changed) <= {'Pcs.rep/idata/~index.bak', 'Pcs.rep/idata/~journal.bak'}, changed
    cancel_after = snapshot(cancel_project)
    cancel_changed = sorted(p for p in cancel_before.keys() | cancel_after.keys() if cancel_before.get(p) != cancel_after.get(p))
    assert set(cancel_changed) <= {'Pcs.rep/idata/~index.bak', 'Pcs.rep/idata/~journal.bak'}, cancel_changed
    assert baseline_program == snapshot(baseline / 'project')
    assert protected == {path: pcs.digest(Path(path)) for path in protected}
    assert not any(path.name.startswith('.') for path in case.iterdir())
    result = {'status': 'PASS', 'case': str(case), 'failureExports': 2, 'cancelledExports': 1,
        'failedFunction': selected, 'runtime': runtime, 'protectedHashes': protected,
        'programBefore': program_before, 'programAfter': program_after, 'rotatedBackups': changed,
        'cancelBefore': cancel_before, 'cancelAfter': cancel_after, 'cancelRotatedBackups': cancel_changed}
    (case / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    (baseline / 'failure-controls.json').write_text(json.dumps(result, indent=4) + '\n')
    print('arm-pcs-failure-controls=PASS ' + str(case))


if __name__ == '__main__':
    main(Path(sys.argv[1]))

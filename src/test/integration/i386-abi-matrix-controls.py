#!/usr/bin/env python3
"""Compose i386 ABI values with native decompiler failure and publication cancellation."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('abi', HERE / 'i386-abi-matrix-export.py')
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)
support = abi.support


def snapshot(project):
    return {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}


def unchanged(project, before):
    after = snapshot(project)
    changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
    assert set(changed) <= {'I386.rep/idata/~index.bak', 'I386.rep/idata/~journal.bak'}, changed
    return after, changed


def main(ghidra, baseline):
    ghidra, baseline = ghidra.resolve(strict=True), baseline.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    assert accepted['status'] in ('PASS', 'CONTROLS_PENDING')
    case = Path(tempfile.mkdtemp(prefix='controls.', dir=baseline))
    print(case, flush=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    protected = {str(p): support.digest(p) for p in module.rglob('*') if p.is_file()}
    for name in ('profile.input', 'profile.reference', 'labels.txt', 'import.json', 'compiler-gdb.json'):
        shutil.copy2(baseline / name, case / name)
    if (baseline / 'profile.sectioned').exists():
        shutil.copy2(baseline / 'profile.sectioned', case / 'profile.sectioned')
    scripts = ('PrepareI386AbiMatrix.java', 'AbiDecompilerFailureExport.java', 'CancelDuringElfCopy.java',
        'RebaseFixtureProgram.java')
    for p in [Path(__file__), HERE / 'i386-abi-matrix-gdb.py', HERE / 'i386-abi-matrix-export.py',
            *(HERE / 'ghidra_scripts' / name for name in scripts), *case.iterdir(),
            *(baseline / name for name in ('profile.input', 'profile.reference', 'profile.dbg', 'profile.dbg.c'))]:
        if p.is_file():
            protected[str(p)] = support.digest(p)
    commands = []

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, native=False):
        commands.append({'label': name, 'command': list(map(str, command))})
        write('commands.json', commands)
        support.run(command, case / (name + '.log'), timeout=240)
        text = (case / (name + '.log')).read_text()
        if native:
            assert 'REPORT SCRIPT ERROR' not in text and 'Script error' not in text, name
        else:
            support.require_clean(case / (name + '.log'))
        return text

    project = baseline / 'project'
    before = snapshot(project)
    write('project-before.json', before)
    original_model = json.loads((baseline / 'import.json').read_text())
    hashes = None
    for iteration in ('first', 'repeat'):
        log = run('failure-' + iteration, [ghidra / 'support/analyzeHeadless', project, 'I386',
            '-process', 'profile.input', '-readOnly', '-noanalysis', '-scriptPath', HERE / 'ghidra_scripts',
            '-postScript', 'PrepareI386AbiMatrix.java', 'observe', case / 'labels.txt', case / (iteration + '.json'),
            '-postScript', 'AbiDecompilerFailureExport.java', case / 'profile.dbg', 'vector_add', 'a'], native=True)
        assert 'abi-decompiler-failure=PASS' in log and 'Flow exceeded maximum allowable instructions' in log
        assert json.loads((case / (iteration + '.json')).read_text()) == original_model
        current = [support.digest(case / name) for name in ('profile.dbg', 'profile.dbg.c')]
        assert hashes is None or hashes == current
        hashes = current
    source = (case / 'profile.dbg.c').read_text()
    assert 'Decompilation unavailable for vector_add' in source
    assert source.count('Decompilation unavailable for ') == 1
    info = run('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'profile.dbg'])
    dies = re.split(r'(?=^\s*<\d+><[0-9a-f]+>:)', info, flags=re.M)
    owner, = [i for i, die in enumerate(dies) if 'DW_TAG_subprogram' in die and
        re.search(r'DW_AT_name\s*:.*\bvector_add\s*$', die, re.M)]
    assert 'DW_AT_low_pc' in dies[owner] and 'DW_AT_type' not in dies[owner]
    assert 'DW_AT_decl_line' not in dies[owner]
    next_depth = re.match(r'\s*<(\d+)>', dies[owner + 1])
    assert next_depth and int(next_depth[1]) <= 1, dies[owner + 1]
    run('llvm', ['llvm-dwarfdump', '--verify', case / 'profile.dbg'])
    run('strict', [sys.executable, HERE / 'check-dwarfdump.py', case / 'profile.dbg', case / 'strict.txt',
        '--original', case / 'profile.input', *(['--frame-reference', case / 'profile.sectioned']
            if (case / 'profile.sectioned').exists() else [])])
    # These five existing guarded conventions must still refuse automatic return decoding.
    support.run(['env', 'I386_CASE=' + str(case), 'I386_VARIANT=forge',
        'I386_ABI_FAILED_FUNCTION=vector_add', 'gdb', '-q', '-nx', '-batch', '-x', HERE / 'i386-abi-matrix-gdb.py'],
        case / 'failure-gdb.log', timeout=120)
    output = (case / 'failure-gdb.log').read_text()
    errors = (case / 'failure-gdb.stderr').read_text()
    pattern = r"(?m)^warning: Function '([a-z_]+)' does not follow the target calling convention, cannot determine its returned value\.\n"
    found = re.findall(pattern, output + errors)
    assert len(found) == 5 and set(found) == {'sse_parameters', 'register_parameters',
        'stdcall_parameters', 'fastcall_parameters', 'thiscall_parameters'}, found
    assert not re.sub(pattern, '', errors).strip()
    assert not re.search(r'(?im)\b(?:warning|error):', re.sub(pattern, '', output))
    runtime = json.loads((case / 'forge-gdb.json').read_text())
    assert runtime['status'] == 'PASS' and len(runtime['rows']) == 11
    assert [row['function'] for row in runtime['rows'] if row.get('symbolOnly')] == ['vector_add']
    after, changes = unchanged(project, before)
    write('project-after.json', after)

    # Import the padded original separately so the production identity check stays active.
    padded = case / 'padded'
    shutil.copy2(case / 'profile.input', padded)
    with padded.open('r+b') as stream:
        stream.truncate(128 * 1024 * 1024)
    protected[str(padded)] = support.digest(padded)
    cancel_project = case / 'cancel-project'
    cancel_project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if accepted['role'] == 'pie-rebased' else []
    log = run('cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'I386', '-import', padded,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', HERE / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareI386AbiMatrix.java', 'curate', case / 'labels.txt', case / 'cancel-curated.json'], native=True)
    assert 'REPORT: Analysis succeeded' in log
    assert json.loads((case / 'cancel-curated.json').read_text()) == original_model
    cancel_before = snapshot(cancel_project)
    write('cancel-project-before.json', cancel_before)
    log = run('cancel-export', [ghidra / 'support/analyzeHeadless', cancel_project, 'I386', '-process', 'padded',
        '-readOnly', '-noanalysis', '-scriptPath', HERE / 'ghidra_scripts', '-postScript',
        'CancelDuringElfCopy.java', padded, case / 'profile.dbg'], native=True)
    assert 'production-copy-cancellation=PASS' in log and '"status":"CANCELLED"' in log
    assert hashes == [support.digest(case / name) for name in ('profile.dbg', 'profile.dbg.c')]
    cancel_after, cancel_changes = unchanged(cancel_project, cancel_before)
    write('cancel-project-after.json', cancel_after)
    assert protected == {p: support.digest(Path(p)) for p in protected}
    assert not any(p.name.startswith('.') for p in case.iterdir())
    write('result.json', {'status': 'PASS', 'baseline': str(baseline), 'role': accepted['role'],
        'runtime': runtime, 'failureArtifacts': hashes, 'projectHousekeepingChanges': changes,
        'cancelHousekeepingChanges': cancel_changes, 'protectedFiles': protected})
    print('i386-abi-matrix-controls=PASS ' + str(case))


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))

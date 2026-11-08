#!/usr/bin/env python3
"""Compose N32/N64 wide arguments with real native failure and production cancellation."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('abi', source / 'mips-wide-arguments.py')
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)
support = abi.support


def snapshot(project):
    return {str(path.relative_to(project)): support.digest(path)
        for path in project.rglob('*') if path.is_file()}


def unchanged_project(project, before):
    after = snapshot(project)
    changes = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    assert changes <= {'MipsWideArguments.rep/idata/~index.bak', 'MipsWideArguments.rep/idata/~journal.bak'}, changes
    return after, sorted(changes)


def main(baseline, ghidra):
    baseline, ghidra = baseline.resolve(strict=True), ghidra.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    assert accepted['status'] in ('PASS', 'CONTROLS_PENDING')
    assert accepted['artifactSha256'] == [support.digest(baseline / name) for name in ('abi.dbg', 'abi.dbg.c')]
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    baseline_hashes = json.loads((baseline / 'protected-before.json').read_text())
    for path, digest in baseline_hashes.items():
        path = Path(path)
        if module in path.parents or path.name in ('abi.input', 'abi.reference', 'mips_wide_arguments.c'):
            assert support.digest(path) == digest, path
    case = Path(tempfile.mkdtemp(prefix='controls.', dir=baseline))
    print(case, flush=True)

    def run(label, command, clean=True):
        log = case / (label + '.log')
        support.run(command, log, timeout=240)
        if clean:
            support.require_clean(log)
        return log.read_text()

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    for name in ('abi.input', 'abi.reference', 'metadata.json', 'labels.txt', 'curated.json',
            'compiler-observations.json', 'compiler-runtime-gdb.log'):
        shutil.copy2(baseline / name, case / name)
    if (baseline / 'abi.driver').exists():
        shutil.copy2(baseline / 'abi.driver', case / 'abi.driver')
    scripts = case / 'scripts'
    scripts.mkdir()
    script_names = ('AbiDecompilerFailureExport.java', 'CancelDuringElfCopy.java',
        'ProbeMipsWideArguments.java', 'RebaseFixtureProgram.java')
    for name in script_names:
        shutil.copyfile(source / 'ghidra_scripts' / name, scripts / name)
    protected = {str(path): support.digest(path) for path in [
        Path(__file__), source / 'mips-wide-arguments.py', source / 'mips-wide-arguments-gdb.py',
        source / 'mips-wide-arguments-gdb.sh', source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh',
        *(source / 'ghidra_scripts' / name for name in script_names),
        *(module.rglob('*')), *(case.iterdir()), *(scripts.iterdir()), *(baseline / name for name in
            ('abi.input', 'abi.reference', 'abi.dbg', 'abi.dbg.c'))] if path.is_file()}
    write('protected-before.json', protected)
    project = baseline / 'project'
    before = snapshot(project)
    write('project-before.json', before)
    hashes = None
    for iteration in ('first', 'repeat'):
        log = run('failure-' + iteration, [ghidra / 'support/analyzeHeadless', project, 'MipsWideArguments',
            '-process', 'abi.input', '-readOnly', '-noanalysis', '-scriptPath', scripts,
            '-postScript', 'ProbeMipsWideArguments.java', 'observe', case / 'labels.txt', case / (iteration + '-model.json'),
            '-postScript', 'AbiDecompilerFailureExport.java', case / 'abi.dbg', 'wide_pair', 'value'], clean=False)
        assert 'REPORT SCRIPT ERROR' not in log and 'abi-decompiler-failure=PASS' in log
        assert 'Flow exceeded maximum allowable instructions' in log
        assert json.loads((case / (iteration + '-model.json')).read_text()) == json.loads((case / 'curated.json').read_text())
        current = [support.digest(case / name) for name in ('abi.dbg', 'abi.dbg.c')]
        assert hashes is None or hashes == current
        hashes = current
    assert 'Flow exceeded maximum allowable instructions' in (case / 'abi.dbg.c').read_text()
    run('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'abi.dbg'])
    run('llvm', ['llvm-dwarfdump', '--verify', case / 'abi.dbg'])
    run('strict-driver', ['python3', source / 'check-dwarfdump.py', case / 'abi.dbg',
        case / 'strict.log', '--original', case / 'abi.input'])
    log = run('failure-gdb', ['env', 'FORGE_MIPS_WIDE_FAILED_FUNCTION=wide_pair',
        'bash', source / 'mips-wide-arguments-gdb.sh', case, 'forge'], clean=False)
    assert not (case / 'failure-gdb.stderr').read_text().strip()
    assert 'MIPS_WIDE_ARGUMENTS_FORGE_PASS' in log
    after, changes = unchanged_project(project, before)
    write('project-after.json', after)

    # The production entry point checks imported hashes. Import the padded copy
    # as its own program instead of bypassing that identity check.
    padded = case / 'padded'
    shutil.copy2(case / 'abi.input', padded)
    with padded.open('r+b') as stream:
        stream.truncate(128 * 1024 * 1024)
    protected[str(padded)] = support.digest(padded)
    cancel_project = case / 'cancel-project'
    cancel_project.mkdir()
    role = json.loads((case / 'metadata.json').read_text())['role']
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if role.endswith('-rebased') else []
    log = run('cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'MipsWideArguments',
        '-import', padded, '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', scripts,
        *rebase, '-postScript', 'ProbeMipsWideArguments.java', 'curate', case / 'labels.txt', case / 'cancel-curated.json'], clean=False)
    assert 'REPORT SCRIPT ERROR' not in log and 'MIPS_WIDE_ARGUMENTS_OBSERVATION_PASS' in log
    assert json.loads((case / 'cancel-curated.json').read_text()) == json.loads((case / 'curated.json').read_text())
    cancel_before = snapshot(cancel_project)
    write('cancel-project-before.json', cancel_before)
    log = run('cancel-export', [ghidra / 'support/analyzeHeadless', cancel_project, 'MipsWideArguments',
        '-process', 'padded', '-readOnly', '-noanalysis', '-scriptPath', scripts,
        '-postScript', 'CancelDuringElfCopy.java', padded, case / 'abi.dbg'], clean=False)
    assert 'production-copy-cancellation=PASS' in log and '"status":"CANCELLED"' in log
    assert hashes == [support.digest(case / name) for name in ('abi.dbg', 'abi.dbg.c')]
    cancel_after, cancel_changes = unchanged_project(cancel_project, cancel_before)
    write('cancel-project-after.json', cancel_after)
    assert protected == {path: support.digest(Path(path)) for path in protected}
    assert not any(path.name.startswith('.') for path in case.iterdir())
    write('result.json', {'status': 'PASS', 'baseline': str(baseline), 'role': role,
        'failedFunction': 'wide_pair', 'failureExports': 2, 'cancelledExports': 1,
        'failureArtifactHashes': hashes, 'unchangedInputs': protected,
        'projectBackupChanges': changes, 'cancelProjectBackupChanges': cancel_changes})
    print('mips-wide-arguments-controls=PASS', case, flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))

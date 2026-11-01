#!/usr/bin/env python3
"""Compose saved indirect arguments with real native failure and production cancellation."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('abi', source / 'aarch64-abi.py')
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)
support = abi.support


def snapshot(project):
    return {str(path.relative_to(project)): support.digest(path)
        for path in project.rglob('*') if path.is_file()}


def unchanged_project(project, before):
    after = snapshot(project)
    changes = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    assert changes <= {'Aarch64Abi.rep/idata/~index.bak', 'Aarch64Abi.rep/idata/~journal.bak'}, changes
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
        if module in path.parents or path.name in ('abi.input', 'abi.reference', 'aarch64-abi.c'):
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
            'compiler-observations.json', 'compiler-returns.json', 'compiler-runtime-gdb.log'):
        shutil.copy2(baseline / name, case / name)
    scripts = case / 'scripts'
    scripts.mkdir()
    script_names = ('AbiDecompilerFailureExport.java', 'CancelDuringElfCopy.java',
        'ProbeAarch64Abi.java', 'RebaseFixtureProgram.java')
    for name in script_names:
        shutil.copyfile(source / 'ghidra_scripts' / name, scripts / name)
    protected = {str(path): support.digest(path) for path in [
        Path(__file__), source / 'aarch64-abi.py', source / 'aarch64-abi-gdb.py',
        source / 'aarch64-abi-locations.py', source / 'aarch64-abi-oracle.py',
        source / 'aarch64-abi-gdb.sh', source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh',
        *(source / 'ghidra_scripts' / name for name in script_names),
        *(module.rglob('*')), *(case.iterdir()), *(scripts.iterdir()), *(baseline / name for name in
            ('abi.input', 'abi.reference', 'abi.dbg', 'abi.dbg.c'))] if path.is_file()}
    project = baseline / 'project'
    before = snapshot(project)
    write('project-before.json', before)
    hashes = None
    for iteration in ('first', 'repeat'):
        log = run('failure-' + iteration, [ghidra / 'support/analyzeHeadless', project, 'Aarch64Abi',
            '-process', 'abi.input', '-readOnly', '-noanalysis', '-scriptPath', scripts,
            '-postScript', 'ProbeAarch64Abi.java', 'observe', case / 'labels.txt', case / (iteration + '-model.json'),
            '-postScript', 'AbiDecompilerFailureExport.java', case / 'abi.dbg', 'curated_abi_large_spill'], clean=False)
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
    run('locations', ['python3', source / 'aarch64-abi-locations.py', case, 'abi_large_spill'])
    log = run('failure-gdb', ['env', 'FORGE_AARCH64_ABI_FAILED_FUNCTION=abi_large_spill',
        'bash', source / 'aarch64-abi-gdb.sh', case, 'forge'], clean=False)
    assert not (case / 'failure-gdb.stderr').read_text().strip()
    assert 'AARCH64_ABI_FORGE_ORACLE_PASS' in log
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
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if role == 'pie-rebased' else []
    log = run('cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'Aarch64Abi',
        '-import', padded, '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', scripts,
        *rebase, '-postScript', 'ProbeAarch64Abi.java', 'curate', case / 'labels.txt', case / 'cancel-curated.json'], clean=False)
    assert 'REPORT SCRIPT ERROR' not in log and 'AARCH64_ABI_OBSERVATION_PASS' in log
    assert json.loads((case / 'cancel-curated.json').read_text()) == json.loads((case / 'curated.json').read_text())
    cancel_before = snapshot(cancel_project)
    write('cancel-project-before.json', cancel_before)
    log = run('cancel-export', [ghidra / 'support/analyzeHeadless', cancel_project, 'Aarch64Abi',
        '-process', 'padded', '-readOnly', '-noanalysis', '-scriptPath', scripts,
        '-postScript', 'CancelDuringElfCopy.java', padded, case / 'abi.dbg'], clean=False)
    assert 'production-copy-cancellation=PASS' in log and '"status":"CANCELLED"' in log
    assert hashes == [support.digest(case / name) for name in ('abi.dbg', 'abi.dbg.c')]
    cancel_after, cancel_changes = unchanged_project(cancel_project, cancel_before)
    write('cancel-project-after.json', cancel_after)
    assert protected == {path: support.digest(Path(path)) for path in protected}
    assert not any(path.name.startswith('.') for path in case.iterdir())
    write('result.json', {'status': 'PASS', 'baseline': str(baseline), 'role': role,
        'failedFunction': 'curated_abi_large_spill', 'failureExports': 2, 'cancelledExports': 1,
        'failureArtifactHashes': hashes, 'unchangedInputs': protected,
        'projectBackupChanges': changes, 'cancelProjectBackupChanges': cancel_changes})
    print('aarch64-abi-controls=PASS', case, flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]))

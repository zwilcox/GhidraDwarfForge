#!/usr/bin/env python3
"""Saved later locals across real calls, immutable exports and compiler/Forge GDB."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'aarch64'))
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    parser.add_argument('--expect-baseline-gap', action='store_true')
    parser.add_argument('--storage', choices=('register', 'stack', 'outgoing'), default='register')
    parser.add_argument('--expect-memory-gap', action='store_true')
    args = parser.parse_args()
    if args.expect_memory_gap and (args.storage == 'register' or args.expect_baseline_gap):
        parser.error('--expect-memory-gap requires stack or outgoing storage and excludes --expect-baseline-gap')
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/local-call-lifetimes'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '.' + args.storage + '.' + args.role + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures' / {'stack': 'stack-call-lifetimes.c',
        'register': 'local-call-lifetimes.c', 'outgoing': 'call-memory-boundaries.c'}[args.storage]
    protected = [fixture, Path(__file__).resolve(), source / 'local-call-lifetimes-gdb.py',
        source / 'local-call-lifetimes-gdb.sh', source / 'ghidra_scripts/PrepareLocalCallLifetimes.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java', source / 'check-local-definition-flow-locations.py']
    if args.storage != 'register':
        protected += [source / 'stack-call-offsets.py', source / 'stack-call-offsets.sh', source / 'call-memory-offsets.py']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'local.reference', case / 'local.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    if args.storage != 'register':
        # Isolate the inspected call effects from an unrelated external canary
        # failure path, which deliberately has no inspected return contract.
        flags += ['-fno-stack-protector']
    if args.storage == 'outgoing':
        flags += ['-fno-ipa-cp']
        if args.target == 'x86_64':
            flags += ['-maccumulate-outgoing-args']
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-gno-variable-location-views', '-fno-inline',
        '-fno-ipa-sra', '-fno-ipa-icf', '-fomit-frame-pointer', '-fno-reorder-blocks',
        '-fno-reorder-blocks-and-partition', '-fno-align-jumps', '-fno-align-labels', '-fno-align-loops', *flags,
        '-Wl,--build-id=none', fixture, '-o', reference])
    run('strip', [objcopy, '--strip-debug', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('compiler-symbols', ['readelf', '-sW', reference])
    symbols, sizes = {}, {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7].startswith(('local_call_', 'inspected_')):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
            if fields[3] == 'FUNC':
                sizes[fields[7]] = int(fields[2])
    labels = {}
    for name, size in sorted(sizes.items()):
        row = {key[len(name) + 1:]: value for key, value in symbols.items() if key.startswith(name + '_')}
        row.update(entry=symbols[name], end=symbols[name] + size)
        labels[name] = row
    if args.storage == 'outgoing':
        assert set(labels) == {'local_call_overlap', 'local_call_adjacent',
            'inspected_overlap', 'inspected_adjacent', 'local_call_released',
            'local_call_unknown', 'inspected_released', 'inspected_unknown'}
    elif args.storage == 'stack':
        assert set(labels) == {'local_call_once', 'local_call_twice', 'local_call_alias',
            'inspected_leaf', 'inspected_nested', 'inspected_alias'}
    else:
        assert set(labels) == {'local_call_' + shape for shape in ('once', 'twice', 'branch', 'loop', 'split', 'clobber')} | {
            'inspected_leaf', 'inspected_clobber'}
    write('boundaries.json', labels)
    offset_args = []
    if args.storage != 'register':
        os.environ['LOCAL_STORAGE'] = args.storage
        run('offsets-driver', ['bash', source / 'stack-call-offsets.sh', repository, case, args.target], timeout=180)
        offset_args = [case / 'stack-offsets.json']
        labels = json.loads((case / 'boundaries.json').read_text())
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Local', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    common = [ghidra / 'support/analyzeHeadless', project, 'Local', '-process', binary.name,
        '-noanalysis', '-scriptPath', source / 'ghidra_scripts']
    run('curate', [*common, '-postScript', 'PrepareLocalCallLifetimes.java',
        'curate', case / 'curated.json', case / 'boundaries.json', *offset_args], timeout=240)
    assert len(json.loads((case / 'curated.json').read_text())['functions']) == len(labels)
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    artifact = case / 'local.dbg'
    hashes = None
    for variant in ('fixed', 'repeat'):
        run(variant, [*common, '-readOnly', '-postScript', 'PrepareLocalCallLifetimes.java',
            'observe', case / (variant + '.json'), case / 'boundaries.json', *offset_args,
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(artifact)], timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in (case / (variant + '.log')).read_text()
        current = [support.digest(artifact), support.digest(Path(str(artifact) + '.c'))]
        if hashes is not None:
            assert hashes == current
        hashes = current
    model = json.loads((case / 'fixed.json').read_text())
    assert model == json.loads((case / 'repeat.json').read_text()) == json.loads((case / 'curated.json').read_text())
    assert model['java'].startswith('21.'), model['java']
    assert Path(unquote(urlsplit(model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    model['role'] = args.role
    model['storage'] = args.storage
    assert int.from_bytes(reference.read_bytes()[16:18], 'little') == (2 if args.role == 'exec' else 3)
    if args.role == 'pie-rebased':
        assert model['delta'] >= 0x2000000 and ' by 0x2000000' in (case / 'import.log').read_text()
    for function in model['functions']:
        name = function['name']
        row = labels[name]
        row['instructions'] = function['instructions']
        if name.startswith('inspected_'):
            if args.storage == 'register':
                assert not any(i['call'] for i in row['instructions'])
                assert any(i['writesHeld'] for i in row['instructions']) == (name == 'inspected_clobber')
            continue
        assert row['entry'] + function['firstUse'] == row['definition']
        writes = [i for i in row['instructions'] if i['writesHeld' if args.storage == 'register' else 'writesSp']
            and not i['call'] and i['address'] >= row['ready'] and i != row['instructions'][-1]]
        assert len(writes) == 1, writes
        row['lost'] = writes[0]['next']
        row['return'] = row['instructions'][-1]['address']
        assert row['lost'] <= row['return']
        calls = [i for i in row['instructions'] if i['call']]
        assert len(calls) == (2 if args.storage == 'register' and name.endswith(('twice', 'branch')) else 1)
        high = calls[0]['next'] if name.endswith(('clobber', 'alias', 'overlap', 'released', 'unknown')) or args.expect_memory_gap else row['lost']
        row['available'] = [(row['ready'], high)]
        if name.endswith('split'):
            row['available'] = [(row['ready'], row['gap']), (row['resume'], high)]
    write('model.json', model)
    write('boundaries.json', labels)
    write('locations.json', {name: {'available': [] if args.expect_baseline_gap else row['available'],
        'dwarfRegister': 12 if args.target == 'x86_64' else 19, 'allowStorageMigration': args.storage != 'register'}
        for name, row in labels.items() if name.startswith('local_call_')})
    report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in (case / 'fixed.log').read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
    assert not report['failedFunctions'] and report['failure'] is None
    write('report.json', report)
    for variant, path in [('compiler', reference), ('forge', artifact)]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, path])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, path])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', path], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    run('strict', ['python3', source / 'check-dwarfdump.py', artifact, case / 'strict-checks.log', '--original', binary])
    run('locations', ['python3', source / 'check-local-definition-flow-locations.py', artifact,
        case / 'locations.json', args.target])
    os.environ['LOCAL_BASELINE'] = '1' if args.expect_baseline_gap else '0'
    run('gdb-driver', ['bash', source / 'local-call-lifetimes-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Local.rep/idata/~index.bak', 'Local.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'BASELINE_GAP_REPRODUCED' if args.expect_baseline_gap else
        'MEMORY_GAP_REPRODUCED' if args.expect_memory_gap else 'PASS',
        'target': args.target, 'role': args.role, 'storage': args.storage, 'artifactSha256': hashes, 'javaVersion': model['java'],
        'moduleSha256': support.digest(module / 'lib/GhidraDwarfForge.jar'),
        'projectBackupChanges': changes, 'protectedUnchanged': True})
    print('local-call-lifetimes-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

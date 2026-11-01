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
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/local-call-lifetimes'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '.' + args.role + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/local-call-lifetimes.c'
    protected = [fixture, Path(__file__).resolve(), source / 'local-call-lifetimes-gdb.py',
        source / 'local-call-lifetimes-gdb.sh', source / 'ghidra_scripts/PrepareLocalCallLifetimes.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java', source / 'check-local-definition-flow-locations.py']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'local.reference', case / 'local.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-gno-variable-location-views', '-fno-inline',
        '-fno-ipa-sra', '-fno-ipa-icf', '-fomit-frame-pointer', *flags,
        '-Wl,--build-id=none', fixture, '-o', reference])
    run('strip', [objcopy, '--strip-debug', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('compiler-symbols', ['readelf', '-sW', reference])
    symbols, sizes = {}, {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7].startswith(('local_call_', 'inspected_leaf')):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
            if fields[3] == 'FUNC':
                sizes[fields[7]] = int(fields[2])
    labels = {}
    for name, size in sorted(sizes.items()):
        row = {key[len(name) + 1:]: value for key, value in symbols.items() if key.startswith(name + '_')}
        row.update(entry=symbols[name], end=symbols[name] + size)
        labels[name] = row
    assert set(labels) == {'local_call_once', 'local_call_twice', 'inspected_leaf'}
    write('boundaries.json', labels)
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Local', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    common = [ghidra / 'support/analyzeHeadless', project, 'Local', '-process', binary.name,
        '-noanalysis', '-scriptPath', source / 'ghidra_scripts']
    run('curate', [*common, '-postScript', 'PrepareLocalCallLifetimes.java',
        'curate', case / 'curated.json', case / 'boundaries.json'], timeout=240)
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    artifact = case / 'local.dbg'
    hashes = None
    for variant in ('fixed', 'repeat'):
        run(variant, [*common, '-readOnly', '-postScript', 'PrepareLocalCallLifetimes.java',
            'observe', case / (variant + '.json'), case / 'boundaries.json',
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
    assert int.from_bytes(reference.read_bytes()[16:18], 'little') == (2 if args.role == 'exec' else 3)
    if args.role == 'pie-rebased':
        assert model['delta'] >= 0x2000000 and ' by 0x2000000' in (case / 'import.log').read_text()
    for function in model['functions']:
        name = function['name']
        row = labels[name]
        row['instructions'] = function['instructions']
        if name == 'inspected_leaf':
            assert not any(i['writesHeld'] or i['call'] for i in row['instructions'])
            continue
        assert row['entry'] + function['firstUse'] == row['definition']
        writes = [i for i in row['instructions'] if i['writesHeld'] and i['address'] >= row['ready']]
        assert len(writes) == 1 and writes[0] == row['instructions'][-2], writes
        row['lost'] = writes[0]['next']
        row['return'] = row['instructions'][-1]['address']
        assert row['lost'] == row['return']
        assert sum(i['call'] for i in row['instructions']) == (1 if name.endswith('once') else 2)
    write('model.json', model)
    write('boundaries.json', labels)
    write('locations.json', {name: {'available': [] if args.expect_baseline_gap else [(row['ready'], row['lost'])],
        'dwarfRegister': 12 if args.target == 'x86_64' else 19}
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
    write('result.json', {'status': 'BASELINE_GAP_REPRODUCED' if args.expect_baseline_gap else 'PASS',
        'target': args.target, 'role': args.role, 'artifactSha256': hashes, 'javaVersion': model['java'],
        'moduleSha256': support.digest(module / 'lib/GhidraDwarfForge.jar'),
        'projectBackupChanges': changes, 'protectedUnchanged': True})
    print('local-call-lifetimes-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

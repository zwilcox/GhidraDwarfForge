#!/usr/bin/env python3
"""Incoming values through complete stack stores, loads, reuse and final loss."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
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
    parser.add_argument('--previous-ghidra', type=Path)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results' / 'stack-value-transitions'
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

    fixture = source.parent / 'fixtures' / 'stack-value-transitions.c'
    protected = [fixture, Path(__file__).resolve(), source / 'stack-value-transitions-gdb.py',
        source / 'stack-value-transitions-gdb.sh', source / 'check-stack-value-transitions-locations.py',
        source / 'ghidra_scripts/PrepareStackValueTransitions.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'local.reference', case / 'local.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-gno-variable-location-views', '-fno-inline', '-fno-ipa-sra', '-fno-ipa-icf',
        '-fomit-frame-pointer', '-fno-stack-protector', *flags, '-Wl,--build-id=none', fixture, '-o', reference])
    run('strip', [objcopy, '--strip-debug', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('compiler-symbols', ['readelf', '-sW', reference])
    symbols, sizes = {}, {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7].startswith('transfer_'):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
            if fields[3] == 'FUNC':
                sizes[fields[7]] = int(fields[2])
    labels = {}
    for name, size in sorted(sizes.items()):
        row = {key[len(name) + 1:]: value for key, value in symbols.items() if key.startswith(name + '_')}
        row.update(entry=symbols[name], end=symbols[name] + size, width=4 if name.endswith('32') else 8)
        row['body'] = [(row['entry'], row['end'])]
        row['shape'] = name.removeprefix('transfer_')[:-2]
        labels[name] = row
    assert len(labels) == 12
    write('boundaries.json', labels)
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Local', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        *rebase], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    run('curate', [ghidra / 'support/analyzeHeadless', project, 'Local', '-process', binary.name,
        '-noanalysis', '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareStackValueTransitions.java',
        'curate', case / 'import.json', case / 'boundaries.json'], timeout=240)
    assert len(json.loads((case / 'import.json').read_text())['functions']) == 12
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'local.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'Local', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareStackValueTransitions.java', 'observe', case / (variant + '.json'), case / 'boundaries.json',
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in (case / (variant + '.log')).read_text()
        if variant == 'previous':
            continue
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        if hashes is not None:
            assert hashes == current
        hashes = current
        if variant == 'fixed':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
    model = json.loads((case / 'fixed.json').read_text())
    assert model == json.loads((case / 'repeat.json').read_text())
    assert model['functions'] == json.loads((case / 'import.json').read_text())['functions']
    assert Path(unquote(urlsplit(model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    delta = model['imageBase'] - model['originalImageBase']
    model.update(role=args.role, rebaseDelta=delta)
    for function in model['functions']:
        name = function['name']
        row = labels[name]
        assert int(function['entry'], 16) - delta == row['entry']
        assert int(function['end'], 16) - delta == row['end']
        assert function['source'] == 'USER_DEFINED'
        assert [(int(a, 16) - delta, int(b, 16) - delta) for a, b in function['bodyRanges']] == row['body']
        instructions = function['instructions']
        row['instructions'] = [{**i, 'address': int(i['address'], 16) - delta,
            'next': int(i['next'], 16) - delta} for i in instructions]
        row['return'] = row['instructions'][-1]['address']
        expected = ('MOV EAX,R10D' if row['width'] == 4 else 'MOV RAX,R10') if args.target == 'x86_64' else (
            'mov w0,w9' if row['width'] == 4 else 'mov x0,x9')
        if row['shape'] in ('respill', 'chainloss'):
            expected = expected.replace('R10', 'R11').replace('w9', 'w10').replace('x9', 'x10')
        copy, = [i for i in row['instructions'] if i['text'] == expected and i['address'] > row['finish']]
        row['returned_copy'] = copy['next']
        row['previous_end'] = row['saved_again'] if row['shape'] in ('respill', 'chainloss') else (
            row['aliased'] if row['shape'] == 'alias' else row['reused'])
        incoming = 5 if args.target == 'x86_64' else 0
        first, second = (10, 11) if args.target == 'x86_64' else (9, 10)
        row['locations'] = [(row['entry'], row['original_lost'], 'r', incoming),
            (row['original_lost'], row['previous_end'], 's', 0)]
        if row['shape'] == 'keep':
            row['locations'] += [(row['reused'], row['returned_copy'], 'r', first),
                (row['returned_copy'], row['end'], 'r', 0)]
        elif row['shape'] == 'loss':
            row['locations'] += [(row['reused'], row['first_lost'], 'r', first)]
        elif row['shape'] in ('respill', 'chainloss'):
            row['locations'] += [(row['saved_again'], row['first_lost'], 'r', first),
                (row['first_lost'], row['ready_again'], 's', 1),
                (row['ready_again'], row['second_lost'] if row['shape'] == 'chainloss' else row['returned_copy'], 'r', second)]
            if row['shape'] == 'respill':
                row['locations'] += [(row['returned_copy'], row['end'], 'r', 0)]
        row['available'] = []
        for low, high, kind, carrier in row['locations']:
            if row['available'] and row['available'][-1][1] == low:
                row['available'][-1][1] = high
            else:
                row['available'].append([low, high])

    elf = reference.read_bytes()
    assert int.from_bytes(elf[16:18], 'little') == (2 if args.role == 'exec' else 3)
    if args.role == 'pie-rebased':
        assert ' by 0x2000000' in (case / 'import.log').read_text() and delta >= 0x2000000
    write('model.json', model)
    write('boundaries.json', labels)
    report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in (case / 'fixed.log').read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
    assert not report['failedFunctions'] and report['failure'] is None
    for name, row in labels.items():
        omitted = [r for r in report['omittedLocations'] if r['function'] == name and r['variable'] == 'input']
        expected = []
        for body_low, body_high in row['body']:
            cursor = body_low
            for low, high in row['available']:
                if high <= body_low or low >= body_high:
                    continue
                if cursor < low:
                    expected.append((cursor, low, 'UNKNOWN_LIFETIME'))
                cursor = high
            if cursor < body_high:
                expected.append((cursor, body_high, 'UNKNOWN_LIFETIME'))
        actual = sorted((int(r['startAddress'], 16), int(r['endAddress'], 16), r['reason']) for r in omitted)
        assert actual == expected, (name, actual, expected)
        assert any('proven stack-spill lifetime for ' + name + '::input:' in line for line in report['diagnostics'])
    write('report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', case / 'local.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'local.dbg', case / 'strict-checks.log', '--original', binary])
    os.environ['LOCAL_PREVIOUS'] = 'previous' if args.previous_ghidra else ''
    run('gdb-driver', ['bash', source / 'stack-value-transitions-gdb.sh', repository, case, args.target], timeout=240)
    run('locations', ['python3', source / 'check-stack-value-transitions-locations.py', case / 'local.dbg', case / 'boundaries.json', args.target])
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Local.rep/idata/~index.bak', 'Local.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'rebaseDelta': delta,
        'inputSha256': before[str(binary)], 'artifactSha256': hashes, 'javaVersion': model['java'],
        'projectBackupChanges': changes, 'protectedUnchanged': True, 'previousPackageCompared': bool(args.previous_ghidra)})
    print('stack-value-transitions-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Curated later register-local values through real export, PIE and saved-program reopen."""
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
    parser.add_argument('--first-use', choices=('read', 'definition'), default='read')
    args = parser.parse_args()
    defined = args.first_use == 'definition'
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results' / ('defined-register-local' if defined else 'later-register-local')
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

    fixture = source.parent / 'fixtures' / ('defined-register-local.c' if defined else 'later-register-local.c')
    protected = [fixture, Path(__file__).resolve(), source / 'later-register-local-gdb.py',
        source / 'later-register-local-gdb.sh', source / 'check-later-register-local-locations.py',
        source / 'ghidra_scripts/PrepareLaterRegisterLocal.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'local.reference', case / 'local.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-fno-inline', '-fno-ipa-sra',
        '-fomit-frame-pointer', *flags, '-Wl,--build-id=none', fixture, '-o', reference])
    run('strip', [objcopy, '--strip-debug', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Local', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        *rebase, '-postScript', 'PrepareLaterRegisterLocal.java', 'curate', case / 'import.json', args.first_use], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
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
            '-postScript', 'PrepareLaterRegisterLocal.java', 'observe', case / (variant + '.json'), args.first_use,
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
    assert model['firstUseKind'] == args.first_use
    assert model == json.loads((case / 'repeat.json').read_text())
    assert model['functions'] == json.loads((case / 'import.json').read_text())['functions']
    assert Path(unquote(urlsplit(model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    delta = model['imageBase'] - model['originalImageBase']
    model.update(role=args.role, rebaseDelta=delta)
    run('compiler-symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7].startswith(('local32', 'local64')):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
    labels = {}
    for function in model['functions']:
        name = function['name']
        assert int(function['entry'], 16) - delta == symbols[name]
        assert function['source'] == 'USER_DEFINED'
        instructions = function['instructions']
        entry, end = int(function['entry'], 16) - delta, int(function['end'], 16) - delta
        points = ('before', 'definition', 'read', 'kill', 'after') if defined else ('read', 'kill', 'after')
        row = {key: symbols[name + '_' + key] for key in points}
        row.update(entry=entry, end=end, width=function['width'])
        assert entry + function['firstUse'] == row[args.first_use]
        by_address = {int(i['address'], 16) - delta: i for i in instructions}
        read = by_address[row['read']]
        kill = by_address[row['kill']]
        assert int(read['next'], 16) - delta == row['kill']
        assert int(kill['next'], 16) - delta == row['after']
        expected_read = ('MOV EAX,R10D' if row['width'] == 4 else 'MOV RAX,R10') if args.target == 'x86_64' else (
            'mov w0,w9' if row['width'] == 4 else 'mov x0,x9')
        assert read['text'] == expected_read, read
        assert kill['text'] == ('XOR R10D,R10D' if args.target == 'x86_64' else 'mov x9,xzr'), kill
        definition, = [i for i in instructions if int(i['next'], 16) - delta == row['read']]
        if defined:
            assert row['definition'] == int(definition['address'], 16) - delta
            assert int(by_address[row['before']]['next'], 16) - delta == row['definition']
        else:
            row['definition'] = int(definition['address'], 16) - delta
        row['return'] = int(instructions[-1]['address'], 16) - delta
        labels[name] = row
    assert len(labels) == 2
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
        omitted = [r for r in report['omittedLocations'] if r['function'] == name and r['variable'] == 'curated_held']
        assert len(omitted) == 2, omitted
        actual = sorted((int(r['startAddress'], 16), int(r['endAddress'], 16), r['reason']) for r in omitted)
        assert actual == [(row['entry'], row['read'], 'UNKNOWN_LIFETIME'),
            (row['after'], row['end'], 'UNKNOWN_LIFETIME')], actual
        assert any('proven later-register-local lifetime for ' + name + '::curated_held:' in line for line in report['diagnostics'])
    write('report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', case / 'local.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    run('locations', ['python3', source / 'check-later-register-local-locations.py', case / 'local.dbg', case / 'boundaries.json', args.target])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'local.dbg', case / 'strict-checks.log', '--original', binary])
    os.environ['LOCAL_PREVIOUS'] = 'previous' if args.previous_ghidra else ''
    run('gdb-driver', ['bash', source / 'later-register-local-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Local.rep/idata/~index.bak', 'Local.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'rebaseDelta': delta,
        'firstUseKind': args.first_use,
        'inputSha256': before[str(binary)], 'artifactSha256': hashes, 'javaVersion': model['java'],
        'projectBackupChanges': changes, 'protectedUnchanged': True, 'previousPackageCompared': bool(args.previous_ghidra)})
    print('later-register-local-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

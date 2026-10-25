#!/usr/bin/env python3
"""Bounded direct-call register backups, independently checked by compiler DWARF/GDB."""
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
    root = repository / 'build/test-results/direct-leaf-call'
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

    fixtures = [source.parent / 'fixtures' / name for name in
        ('direct-leaf-call.c', 'direct-leaf-callee.c')]
    protected = fixtures + [Path(__file__).resolve(), source / 'direct-leaf-call-gdb.py',
        source / 'direct-leaf-call-gdb.sh', source / 'check-direct-leaf-call-locations.py',
        source / 'ghidra_scripts/ObserveDirectLeafCall.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'call.reference', case / 'call.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-fno-inline', '-fno-ipa-sra',
        '-fno-omit-frame-pointer', *flags, '-Wl,--build-id=none',
        *fixtures, '-o', reference])
    run('strip', [objcopy, '--strip-debug', reference, binary])
    original = support.digest(binary)
    before.update({str(binary): original, str(reference): support.digest(reference)})
    write('protected-before.json', before)
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Calls', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        *rebase, '-postScript', 'ObserveDirectLeafCall.java', 'curate', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'call.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'Calls', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'ObserveDirectLeafCall.java', 'observe', case / (variant + '.json'),
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
    # Keep raw Ghidra facts; derive link-time boundaries independently checked
    # against the original compiler's symbol table before running GDB.
    delta = model['imageBase'] - model['originalImageBase']
    model['role'] = args.role
    model['rebaseDelta'] = delta
    run('compiler-symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[3] == 'FUNC' and fields[7] in ('carry_across_call', 'perturb'):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
    assert set(symbols) == {'carry_across_call', 'perturb'}
    for function in model['functions']:
        assert int(function['entry'], 16) - delta == symbols[function['name']]
    elf = reference.read_bytes()
    assert int.from_bytes(elf[16:18], 'little') == (2 if args.role == 'exec' else 3)
    if args.role == 'pie-rebased':
        assert ' by 0x2000000' in (case / 'import.log').read_text() and delta >= 0x2000000
    write('model.json', model)
    for function in model['functions']:
        assert function['signatureSource'] == 'USER_DEFINED' and not function['customStorage']
    caller, = [f for f in model['functions'] if f['name'] == 'carry_across_call']
    clobber, = [i for i in caller['instructions'] if
        (args.target == 'x86_64' and (i['text'].startswith('LEA EDI,') or i['text'].startswith('ADD EDI,'))) or
        (args.target == 'aarch64' and i['text'].startswith('add w0,w0,'))]
    restore, = [i for i in caller['instructions'] if
        (args.target == 'x86_64' and i['text'].startswith('MOV RBX,')) or
        (args.target == 'aarch64' and i['text'].startswith('ldp x19,'))]
    labels = {'carry_across_call': {'entry': int(caller['entry'], 16) - delta, 'end': int(caller['end'], 16) - delta,
        'after': int(clobber['next'], 16) - delta, 'unavailable': int(restore['next'], 16) - delta}}
    write('boundaries.json', labels)
    reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in (case / 'fixed.log').read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
    report, = reports
    assert report['status'] == 'PARTIAL' and not report['failedFunctions'] and report['failure'] is None
    omitted, = [r for r in report['omittedLocations'] if r['function'] == 'carry_across_call' and r['variable'] == 'value']
    assert omitted['reason'] == 'REGISTER_MODIFIED'
    assert int(omitted['startAddress'], 16) == labels['carry_across_call']['unavailable']
    assert int(omitted['endAddress'], 16) == labels['carry_across_call']['end']
    write('report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', case / 'call.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    run('locations', ['python3', source / 'check-direct-leaf-call-locations.py',
        case / 'call.dbg', case / 'boundaries.json', args.target])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'call.dbg',
        case / 'strict-checks.log', '--original', binary])
    os.environ['CALL_PREVIOUS'] = 'previous' if args.previous_ghidra else ''
    run('gdb-driver', ['bash', source / 'direct-leaf-call-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Calls.rep/idata/~index.bak', 'Calls.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'rebaseDelta': delta, 'inputSha256': original,
        'artifactSha256': hashes, 'javaVersion': model['java'], 'projectBackupChanges': changes,
        'protectedUnchanged': True, 'previousPackageCompared': bool(args.previous_ghidra)})
    print('direct-leaf-call-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

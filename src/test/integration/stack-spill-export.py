#!/usr/bin/env python3
"""Exact register-to-stack values through real export, PIE and saved-program reopen."""
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
    root = repository / 'build/test-results/stack-spill'
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

    fixture = source.parent / 'fixtures/stack-spill.c'
    protected = [fixture, Path(__file__).resolve(), source / 'stack-spill-gdb.py',
        source / 'stack-spill-gdb.sh', source / 'check-stack-spill-locations.py',
        source / 'ghidra_scripts/ObserveStackSpill.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'spill.reference', case / 'spill.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-fno-inline', '-fno-ipa-sra',
        '-fomit-frame-pointer', *flags, '-Wl,--build-id=none', fixture, '-o', reference])
    run('strip', [objcopy, '--strip-debug', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Spill', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        *rebase, '-postScript', 'ObserveStackSpill.java', 'curate', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'spill.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'Spill', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'ObserveStackSpill.java', 'observe', case / (variant + '.json'),
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
    run('compiler-symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7].startswith(('spill32_', 'spill64_')):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
    labels = {}
    for function in model['functions']:
        name = function['name']
        assert int(function['entry'], 16) - delta == symbols[name]
        assert function['signatureSource'] == 'USER_DEFINED' and not function['customStorage']
        instructions = function['instructions']
        entry, end = int(function['entry'], 16) - delta, int(function['end'], 16) - delta
        row = {key: symbols[name + '_' + key] for key in ('saved', 'write', 'after')}
        row.update(entry=entry, end=end, width=function['width'])
        writes = [i for i in instructions if i['memoryWrites']]
        assert len(writes) == (2 if name.endswith('kill') else 1)
        spill = writes[0]
        assert int(spill['next'], 16) - delta == row['saved']
        expected_store = ('MOV dword ptr [RSP + -0x4],EDI' if function['width'] == 4 else 'MOV qword ptr [RSP + -0x8],RDI') if args.target == 'x86_64' else (
            'str w0,[sp, #0xc]' if function['width'] == 4 else 'str x0,[sp, #0x8]')
        assert spill['text'] == expected_store, spill
        if name.endswith('kill'):
            row['kill'] = int(writes[1]['address'], 16) - delta
            row['stack_end'] = symbols[name + '_unavailable']
            assert int(writes[1]['next'], 16) - delta == row['stack_end']
        elif args.target == 'aarch64':
            restore, = [i for i in instructions if i['text'] == 'add sp,sp,#0x10']
            row['restore'] = int(restore['address'], 16) - delta
            row['stack_end'] = int(restore['next'], 16) - delta
        expected_load = ('MOV EAX,dword ptr [RSP + -0x4]' if function['width'] == 4 else
            'MOV RAX,qword ptr [RSP + -0x8]') if args.target == 'x86_64' else (
            'ldr w0,[sp, #0xc]' if function['width'] == 4 else 'ldr x0,[sp, #0x8]')
        reload, = [i for i in instructions if i['text'] == expected_load]
        row['reload_ready'] = int(reload['next'], 16) - delta
        # The fixed compiler fixture has exactly one full-width reload into its
        # ABI return register. The suffix cannot overwrite that register.
        tail = instructions[instructions.index(reload) + 1:]
        if args.target == 'x86_64':
            assert [i['text'] for i in tail][-1:] == ['RET']
            assert all(i['text'] in ('NOP', 'RET') or
                (i['text'].startswith('MOV ') and i['text'].endswith(',EAX' if function['width'] == 4 else ',RAX')) for i in tail)
        else:
            assert all(i['text'] in ('nop', 'ret', 'add sp,sp,#0x10') or
                i['text'].startswith('str w0,' if function['width'] == 4 else 'str x0,') for i in tail)
        if 'stack_end' in row:
            assert row['reload_ready'] <= row['stack_end']
        row['return'] = int(instructions[-1]['address'], 16) - delta
        labels[name] = row
    assert len(labels) == 4
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
        omitted = [r for r in report['omittedLocations'] if r['function'] == name and r['variable'] == 'value']
        assert not omitted, (name, omitted)
        assert any('proven stack-spill lifetime for ' + name + '::value:' in line for line in report['diagnostics'])
    write('report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', case / 'spill.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    run('locations', ['python3', source / 'check-stack-spill-locations.py', case / 'spill.dbg', case / 'boundaries.json', args.target])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'spill.dbg', case / 'strict-checks.log', '--original', binary])
    os.environ['SPILL_PREVIOUS'] = 'previous' if args.previous_ghidra else ''
    run('gdb-driver', ['bash', source / 'stack-spill-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Spill.rep/idata/~index.bak', 'Spill.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'rebaseDelta': delta,
        'inputSha256': before[str(binary)], 'artifactSha256': hashes, 'javaVersion': model['java'],
        'projectBackupChanges': changes, 'protectedUnchanged': True, 'previousPackageCompared': bool(args.previous_ghidra)})
    print('stack-spill-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Two proven incoming-value register handoffs through the packaged exporter."""
import argparse
import importlib.util
import json
import os
import re
from urllib.parse import unquote, urlsplit
from pathlib import Path
import shutil
import tempfile

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
    parser.add_argument('--handoffs', type=int, choices=(2, 4), default=2)
    parser.add_argument('--copy-shape', choices=('ordered', 'early', 'self'), default='ordered')
    parser.add_argument('--call-graph', choices=('none', 'branching', 'loop', 'nested', 'recursive', 'split', 'clobber'), default='none')
    args = parser.parse_args()
    assert args.call_graph == 'none' or (args.handoffs == 4 and args.copy_shape == 'ordered')
    assert args.copy_shape == 'ordered' or args.handoffs == 2
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results' / ('inspected-calls' if args.call_graph != 'none' else 'register-copy-chain' if args.handoffs == 4 else 'second-register-copy')
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '.' + args.role + '.' + args.copy_shape + '.' + args.call_graph + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/second-register-copy.c'
    protected = [fixture, Path(__file__).resolve(), source / 'second-register-copy-gdb.py',
        source / 'second-register-copy-gdb.sh', source / 'check-second-register-copy-locations.py',
        source / 'qemu-socket.sh', source / 'ghidra_scripts/PrepareRegisterCopy.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    if args.previous_ghidra:
        protected += [p for p in (args.previous_ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
    if args.call_graph != 'none':
        protected += [source.parent / 'fixtures/inspected-call-callees.c', source / 'ghidra_scripts/PrepareInspectedCalls.java']
    before = {str(p.resolve()): support.digest(p) for p in protected}
    write('protected-before.json', before)
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'chain.reference', case / 'chain.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [cc, '-O2', '-g3', '-gdwarf-5', '-gno-variable-location-views', '-fno-inline',
        '-fno-ipa-sra', '-fomit-frame-pointer', *(['-DCOPY_CHAIN'] if args.handoffs == 4 else []),
        *([] if args.copy_shape == 'ordered' else ['-DCOPY_' + args.copy_shape.upper()]), *flags, '-Wl,--build-id=sha1', fixture,
        *([] if args.call_graph == 'none' else ['-fno-optimize-sibling-calls', '-DCOPY_CALLS', '-DCOPY_CALL_TARGET=inspected_' + args.call_graph, source.parent / 'fixtures/inspected-call-callees.c']), '-o', reference])
    run('strip', [objcopy, '--strip-all', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('compiler-symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7].startswith(('chain32', 'chain64')):
            assert fields[7] not in symbols
            symbols[fields[7]] = (int(fields[1], 16), int(fields[2]))
    labels, preparation = {}, []
    for name in ('chain32', 'chain64'):
        entry, size = symbols[name]
        width = 4 if name == 'chain32' else 8
        row = {key: symbols[name + '_' + key][0] for key in
            ('saved', 'write', 'after', 'copy', 'second', 'kill', 'tail', 'erase', 'unavailable', 'sink')}
        if args.handoffs == 4:
            row.update({key: symbols[name + '_' + key][0] for key in
                ('copy3', 'third', 'kill2', 'tail3', 'copy4', 'fourth', 'kill3', 'tail4')})
        row.update(entry=entry, end=entry + size, width=width,
            **{'return': entry + size - (1 if args.target == 'x86_64' else 4)})
        points = ['entry', 'saved', 'write', 'after', 'copy', 'second', 'kill', 'tail', 'erase', 'unavailable', 'return', 'end']
        if args.handoffs == 4:
            points[8:8] = ['copy3', 'third', 'kill2', 'tail3', 'copy4', 'fourth', 'kill3', 'tail4']
        if args.copy_shape == 'early':
            points = ['entry', 'saved', 'copy', 'second', 'write', 'after', 'kill', 'tail', 'erase', 'unavailable', 'return', 'end']
        assert all(row[a] < row[b] for a, b in zip(points, points[1:])), row
        if args.call_graph != 'none':
            row.update({key: symbols[name + '_' + key][0] for number in range(1, 5) for key in (f'call{number}', f'back{number}')})
            row['callStop'] = row['back1'] if args.call_graph == 'clobber' else row['unavailable']
            row['backupRegisters'] = [3, 12] if args.target == 'x86_64' else [19, 20]
        labels[name] = row
        register = ('EDI' if width == 4 else 'RDI') if args.target == 'x86_64' else ('w0' if width == 4 else 'x0')
        preparation.append(' '.join([name, hex(entry), hex(entry + size), hex(row['sink']), str(width), register]))
    write('labels.json', labels)
    write('metadata.json', {'target': args.target, 'role': args.role, 'handoffs': args.handoffs, 'copyShape': args.copy_shape, 'callGraph': args.call_graph})
    (case / 'preparation.txt').write_text('\n'.join(preparation) + '\n')
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Chain', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        *([] if args.call_graph == 'none' else ['-postScript', 'PrepareInspectedCalls.java', case / 'compiler-symbols.log', case / 'calls-prepared.json']),
        '-postScript', 'PrepareRegisterCopy.java', case / 'preparation.txt', '2'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    assert 'register-copy-preparation=PASS' in (case / 'import.log').read_text()
    if args.role == 'pie-rebased':
        assert ' by 0x2000000' in (case / 'import.log').read_text()
    if args.call_graph != 'none':
        recorded = json.loads((case / 'calls-prepared.json').read_text())
        selected = recorded['inspected_' + args.call_graph]
        instructions = selected['instructions']
        if args.call_graph in ('branching', 'clobber'):
            assert any(i['flow'] == 'CONDITIONAL_JUMP' for i in instructions)
        if args.call_graph == 'loop':
            assert any(t < i['address'] for i in instructions for t in i['targets'])
        if args.call_graph == 'nested':
            assert any(recorded['inspected_branching']['entry'] in i['targets'] and i['flow'] == 'UNCONDITIONAL_CALL' for i in instructions)
        if args.call_graph == 'recursive':
            assert any(selected['entry'] in i['targets'] and i['flow'] == 'UNCONDITIONAL_CALL' for i in instructions)
        if args.call_graph == 'split':
            assert len(selected['body']) > 1
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'chain.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'Chain', '-process', binary.name,
            '-readOnly', '-noanalysis', *([] if args.call_graph == 'none' else ['-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareInspectedCalls.java', case / 'compiler-symbols.log', case / (variant + '-calls.json'), 'observe']), '-postScript', 'GhidraDwarfForge.java',
            '--packaged-natives', '--output=' + str(output)], timeout=240)
        export_log = (case / (variant + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in export_log
        if args.call_graph != 'none':
            origin, = re.findall(r'inspected-calls-origin=(\S+)', export_log)
            assert Path(unquote(urlsplit(origin).path)).resolve() == (installation / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar').resolve()
            java, = re.findall(r'inspected-calls-java=(\S+)', export_log)
            assert int(java.split('.')[0]) >= 21
            assert 'inspected-calls-preparation=PASS' in export_log
        if variant == 'previous':
            continue
        if args.call_graph != 'none':
            assert json.loads((case / (variant + '-calls.json')).read_text()) == json.loads((case / 'calls-prepared.json').read_text())
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        if hashes is not None:
            assert hashes == current
        hashes = current
        if variant == 'fixed':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
    report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in (case / 'fixed.log').read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
    assert not report['failedFunctions'] and report['failure'] is None
    for name, row in labels.items():
        omitted = [r for r in report['omittedLocations'] if r['function'] == name and r['variable'] == 'value']
        assert len(omitted) == 1, omitted
        assert (int(omitted[0]['startAddress'], 16), int(omitted[0]['endAddress'], 16), omitted[0]['reason']) == (
            row.get('callStop', row['unavailable']), row['end'], 'REGISTER_MODIFIED')
    write('report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', case / 'chain.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    run('locations', ['python3', source / 'check-second-register-copy-locations.py', case / 'chain.dbg', case / 'labels.json', args.target])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'chain.dbg', case / 'strict-checks.log', '--original', binary])
    os.environ['SECOND_COPY_PREVIOUS'] = 'previous' if args.previous_ghidra else ''
    run('gdb-driver', ['bash', source / 'second-register-copy-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Chain.rep/idata/~index.bak', 'Chain.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'handoffs': args.handoffs, 'copyShape': args.copy_shape, 'callGraph': args.call_graph,
        'inputSha256': before[str(binary)], 'artifactSha256': hashes, 'projectBackupChanges': changes,
        'protectedUnchanged': True, 'previousPackageCompared': bool(args.previous_ghidra)})
    print('second-register-copy-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

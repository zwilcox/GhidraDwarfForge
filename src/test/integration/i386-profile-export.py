#!/usr/bin/env python3
"""Freestanding i386 integer/stack profile through the real packaged exporter."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
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
    parser.add_argument('--role', choices=('exec', 'sectionless', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/i386-profile'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.role + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/i386-profile.c'
    protected = [fixture, Path(__file__).resolve(), source / 'i386-profile-gdb.py',
        source / 'ghidra_scripts/PrepareI386Profile.java', source / 'ghidra_scripts/RebaseFixtureProgram.java',
        source / 'check-dwarfdump.py', source.parent / 'performance/export-benchmark.py']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    reference, binary = case / 'profile.reference', case / 'profile.input'
    flags = ['-fno-pie', '-static'] if args.role in ('exec', 'sectionless') else ['-fPIE', '-static-pie']
    run('compile', ['gcc', '-m32', '-O0', '-g3', '-gdwarf-5', '-fno-omit-frame-pointer',
        '-fno-stack-protector', '-nostdlib', *flags, '-Wl,--build-id=sha1', '-Wl,-e,_start', fixture, '-o', reference])
    run('compiler-runtime', [reference])
    run('strip', ['objcopy', '--strip-all', reference, binary])
    if args.role == 'sectionless':
        raw = bytearray(binary.read_bytes())
        assert raw[:6] == b'\x7fELF\x01\x01'
        struct.pack_into('<I', raw, 32, 0)
        struct.pack_into('<3H', raw, 46, 0, 0, 0)
        binary.write_bytes(raw)
    run('stripped-runtime', [binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('compiler-symbols', ['readelf', '-sW', reference])
    run('stripped-symbols', ['readelf', '-sW', binary])
    assert 'scalar' not in (case / 'stripped-symbols.log').read_text()
    symbols = {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('scalar', 'wide', 'aggregate', '_start', 'sink',
                'scalar_ready', 'wide_ready', 'aggregate_ready'):
            assert fields[7] not in symbols
            symbols[fields[7]] = (int(fields[1], 16), int(fields[2]))
    assert len(symbols) == 8
    functions = {name: {'entry': symbols[name][0], 'end': sum(symbols[name]),
        'ready': symbols[name + '_ready'][0]} for name in ('scalar', 'wide', 'aggregate')}
    write('symbols.json', {'role': args.role, 'functions': functions,
        'start': symbols['_start'][0], 'sink': symbols['sink'][0]})
    run('compiler-relocations', ['readelf', '-rW', reference])
    assert 'There are no relocations in this file.' in (case / 'compiler-relocations.log').read_text()
    os.environ['I386_CASE'] = str(case)
    os.environ['I386_VARIANT'] = 'compiler'
    run('compiler-gdb', ['gdb', '-q', '-nx', '-batch', '-ex', 'source ' + str(source / 'i386-profile-gdb.py')])
    compiler = json.loads((case / 'compiler-gdb.json').read_text())
    assert compiler['status'] == 'PASS' and len(compiler['bindings']) == 3
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'I386', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareI386Profile.java', 'curate', case, case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    hashes = None
    for variant in ('fixed', 'repeat'):
        run(variant, [ghidra / 'support/analyzeHeadless', project, 'I386', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareI386Profile.java', 'observe', case, case / (variant + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'profile.dbg')], timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in (case / (variant + '.log')).read_text()
        current = [support.digest(case / name) for name in ('profile.dbg', 'profile.dbg.c')]
        if hashes is not None:
            assert hashes == current
        hashes = current
        if variant == 'fixed':
            shutil.copyfile(case / 'profile.dbg', case / 'first.dbg')
            shutil.copyfile(case / 'profile.dbg.c', case / 'first.dbg.c')
    model = json.loads((case / 'fixed.json').read_text())
    assert model == json.loads((case / 'repeat.json').read_text())
    assert model['functions'] == json.loads((case / 'import.json').read_text())['functions']
    assert model['language'] == 'x86:LE:32:default' and model['compiler'] == 'gcc'
    assert Path(unquote(urlsplit(model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    delta = model['imageBase'] - model['originalImageBase']
    if args.role == 'pie-rebased':
        assert delta >= 0x2000000 and ' by 0x2000000' in (case / 'import.log').read_text()
    expected_offsets = {'scalar': [(4, 4), (8, 4)], 'wide': [(4, 4), (8, 8), (16, 4)],
        'aggregate': [(4, 8), (12, 4)]}
    for row in model['functions']:
        name = row['name']
        assert int(row['entry'], 16) - delta == functions[name]['entry'] and not row['customStorage']
        assert [(p['offset'], p['bytes']) for p in row['parameters']] == expected_offsets[name]
        assert row['local']['name'] == 'curated_held'
        binding = compiler['bindings'][name]
        assert (row['local']['offset'], row['local']['firstUse']) == (binding['stackOffset'], binding['firstUse'])
    report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in (case / 'fixed.log').read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
    assert not report['failedFunctions'] and report['failure'] is None
    assert report['target']['architecture'] == 'x86' and report['target']['addressBits'] == 32
    for name in functions:
        omitted = [r for r in report['omittedLocations'] if r['function'] == name and r['variable'] == 'curated_held']
        assert omitted and all(r['reason'] == 'UNKNOWN_LIFETIME' for r in omitted)
    write('report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', case / 'profile.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        header = (case / (variant + '-header.log')).read_text()
        assert 'ELF32' in header and 'Intel 80386' in header and "2's complement, little endian" in header
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log')])
        assert json.loads((case / (variant + '-strict-checks.log.check.json')).read_text())['reported_errors'] == 0
    os.environ['I386_VARIANT'] = 'forge'
    run('forge-gdb', ['gdb', '-q', '-nx', '-batch', '-ex', 'source ' + str(source / 'i386-profile-gdb.py')])
    forge = json.loads((case / 'forge-gdb.json').read_text())
    assert forge['status'] == 'PASS' and forge['returns'] == compiler['returns']
    assert [(p['function'], p['point'], p['linkPc'], p['rawStack'], p['instructionBytes']) for p in forge['points']] == [
        (p['function'], p['point'], p['linkPc'], p['rawStack'], p['instructionBytes']) for p in compiler['points']]
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys())
        if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'I386.rep/idata/~index.bak', 'I386.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': 'x86', 'role': args.role, 'rebaseDelta': delta,
        'inputSha256': before[str(binary)], 'artifactSha256': hashes, 'javaVersion': model['java'],
        'projectBackupChanges': changes, 'protectedUnchanged': True,
        'gdbPoints': len(forge['points']) + len(compiler['points'])})
    print('i386-profile-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

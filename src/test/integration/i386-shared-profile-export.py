#!/usr/bin/env python3
"""i386 shared-library integer/stack profile through the real packaged exporter."""
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
    parser.add_argument('--role', choices=('exec', 'exec-rebased', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/i386-shared-profile'
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
    loader = Path('/lib/ld-linux.so.2').resolve(strict=True)
    run('loader-version', [loader, '--version'])
    write('loader.json', {'path': str(loader), 'sha256': support.digest(loader)})
    reference, binary = case / 'profile.reference', case / 'profile.input'
    base = ['gcc', '-m32', '-O0', '-g3', '-gdwarf-5', '-fno-omit-frame-pointer',
        '-fno-stack-protector', '-nostdlib', '-Wl,--build-id=sha1']
    run('compile', [*base, '-fPIC', '-shared', '-Wl,-soname,libprofile.so', '-DFORGE_I386_SHARED_LIBRARY', fixture, '-o', reference])
    driver = case / 'driver'
    flags = ['-fno-pie', '-no-pie'] if args.role.startswith('exec') else ['-fPIE', '-pie']
    run('compile-driver', [*base, *flags, '-Wl,-e,_start', '-Wl,--dynamic-linker=/lib/ld-linux.so.2',
        '-DFORGE_I386_SHARED_DRIVER', fixture, '-L' + str(case), '-l:profile.reference', '-o', driver])
    run('strip', ['objcopy', '--strip-all', reference, binary])
    for variant, original in [('compiler', reference), ('forge', binary)]:
        directory = case / (variant + '-runtime')
        directory.mkdir()
        runtime_library = directory / 'libprofile.so'
        shutil.copy2(original, runtime_library)
        before[str(runtime_library)] = support.digest(runtime_library)
        run(variant + '-runtime', ['env', 'LD_LIBRARY_PATH=' + str(directory), driver])
    before.update({str(path): support.digest(path) for path in
        (binary, reference, driver)})
    write('protected-before.json', before)
    run('compiler-symbols', ['readelf', '-sW', reference])
    run('stripped-symbols', ['readelf', '-sW', binary])
    assert 'scalar' in (case / 'stripped-symbols.log').read_text()
    assert 'forge_scalar' not in (case / 'stripped-symbols.log').read_text()
    symbols = {}
    for line in (case / 'compiler-symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('scalar', 'wide', 'aggregate', 'sink',
                'scalar_ready', 'wide_ready', 'aggregate_ready'):
            value = (int(fields[1], 16), int(fields[2]))
            assert fields[7] not in symbols or symbols[fields[7]] == value
            symbols[fields[7]] = value
    assert len(symbols) == 7
    functions = {name: {'entry': symbols[name][0], 'end': sum(symbols[name]),
        'ready': symbols[name + '_ready'][0]} for name in ('scalar', 'wide', 'aggregate')}
    raw = binary.read_bytes()
    assert raw[:6] == b'\x7fELF\x01\x01'
    program_offset = struct.unpack_from('<I', raw, 28)[0]
    program_size, program_count = struct.unpack_from('<HH', raw, 42)
    assert program_size == 32 and program_count > 0
    loads = [struct.unpack_from('<8I', raw, program_offset + index * program_size)
        for index in range(program_count)]
    zero_loads = [row for row in loads if row[0] == 1 and row[1] == 0]
    assert len(zero_loads) == 1
    curated_names = {name: 'forge_' + name for name in functions}
    write('symbols.json', {'role': args.role, 'functions': functions, 'driver': driver.name,
        'loadBase': zero_loads[0][2], 'curatedNames': curated_names, 'sink': symbols['sink'][0]})
    run('compiler-relocations', ['readelf', '-rW', reference])
    run('driver-dynamic', ['readelf', '-dW', driver])
    assert 'Shared library: [libprofile.so]' in (case / 'driver-dynamic.log').read_text()
    os.environ['I386_CASE'] = str(case)
    os.environ['I386_VARIANT'] = 'compiler'
    run('compiler-gdb', ['gdb', '-q', '-nx', '-batch', '-ex', 'source ' + str(source / 'i386-profile-gdb.py')])
    compiler = json.loads((case / 'compiler-gdb.json').read_text())
    assert compiler['status'] == 'PASS' and len(compiler['bindings']) == 3
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role.endswith('-rebased') else []
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
    if args.role.endswith('-rebased'):
        assert delta >= 0x2000000 and ' by 0x2000000' in (case / 'import.log').read_text()
    expected_offsets = {'scalar': [(4, 4), (8, 4)], 'wide': [(4, 4), (8, 8), (16, 4)],
        'aggregate': [(4, 8), (12, 4)]}
    for row in model['functions']:
        name = row['name']
        assert row['displayName'] == curated_names[name]
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
        omitted = [r for r in report['omittedLocations'] if r['function'] == curated_names[name] and r['variable'] == 'curated_held']
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
    print('i386-shared-profile-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

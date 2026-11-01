#!/usr/bin/env python3
"""Packaged N32/N64 wide argument acceptance with compiler and live GDB references."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('wide_support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def reference_homes(text):
    """Read only the audited direct frame-relative aggregate parameter attributes."""
    function = parameter = None
    locations = {}
    for line in text.splitlines():
        die = re.match(r'\s*<(\d+)><[0-9a-f]+>:', line)
        if die:
            depth = int(die[1])
            if depth <= 1:
                function = {} if 'DW_TAG_subprogram' in line else None
            parameter = {} if depth == 2 and 'DW_TAG_formal_parameter' in line else None
        name = re.search(r'DW_AT_name\s*:.*?([^: ]+)\s*$', line)
        if name:
            if parameter is not None:
                parameter['name'] = name[1]
            elif function is not None:
                function['name'] = name[1]
        location = re.search(r'DW_AT_location.*\(DW_OP_fbreg: (-?\d+)\)\s*$', line)
        if location and function and parameter:
            locations[(function['name'], parameter['name'])] = int(location[1])
    return {name: locations[(name, parameter)] for name, parameter in
        [('wide_pair', 'value'), ('wide_large', 'value'), ('wide_mixed', 'e')]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--abi', choices=('n32', 'n64'), required=True)
    parser.add_argument('--endian', choices=('be', 'le'), required=True)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased', 'shared', 'shared-rebased'), default='exec')
    parser.add_argument('--toolchain-root', type=Path,
        help='optional extracted Ubuntu GCC 12/binutils/glibc packages, with usr/ below this directory')
    parser.add_argument('--with-controls', action='store_true')
    parser.add_argument('--results-root', type=Path, default=repository / 'build/test-results/mips-wide-arguments')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = args.results_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='.'.join((args.abi, args.endian, args.role)) + '.', dir=root))
    print(case, flush=True)
    commands = []

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, clean=True):
        commands.append({'name': name, 'command': list(map(str, command))})
        write('commands.json', commands)
        support.run(command, case / (name + '.log'), timeout=240)
        if clean:
            support.require_clean(case / (name + '.log'))

    prefix = 'mips64' + ('el' if args.endian == 'le' else '') + '-linux-gnuabi64'
    tool_environment, compile_flags = [], []
    if args.toolchain_root:
        toolchain = args.toolchain_root.resolve(strict=True)
        tool_environment = ['env', 'LD_LIBRARY_PATH=' + str(toolchain / 'usr/lib/x86_64-linux-gnu')]
        compiler = toolchain / 'usr/bin' / (prefix + '-gcc-12')
        objcopy = toolchain / 'usr/bin' / (prefix + '-objcopy')
        compile_flags = ['--sysroot=' + str(toolchain), '-B' + str(toolchain / 'usr' / prefix / 'bin') + '/']
        sysroot = toolchain / 'usr' / prefix
    else:
        compiler, objcopy = prefix + '-gcc', prefix + '-objcopy'
        sysroot = Path('/usr') / prefix
    compile_flags += ['-DFORGE_MIPS_AGGREGATE_HOME=1', '-mabi=' + ('64' if args.abi == 'n64' else 'n32'), '-march=mips64r2',
        '-O1', '-g', '-gdwarf-5', '-Wl,--build-id=sha1']
    emulator = 'qemu-mips' + ('64' if args.abi == 'n64' else 'n32') + (
        'el' if args.endian == 'le' else '') + '-static'
    fixture = source.parent / 'fixtures/mips_wide_arguments.c'
    protected = [fixture, Path(__file__), source / 'mips-wide-arguments-gdb.py', source / 'mips-wide-arguments-gdb.sh',
        source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh', source / 'check-dwarfdump.py',
        source / 'ghidra_scripts/ProbeMipsWideArguments.java', source / 'ghidra_scripts/RebaseFixtureProgram.java',
        source / 'mips-wide-arguments-oracle.py', source / 'ghidra_scripts/AbiDecompilerFailureExport.java',
        source / 'ghidra_scripts/CancelDuringElfCopy.java',
        source.parent / 'performance/export-benchmark.py']
    protected += [path for path in module.rglob('*') if path.is_file()]
    before = {str(path): support.digest(path) for path in protected}
    reference, binary, output = [case / ('abi.' + suffix) for suffix in ('reference', 'input', 'dbg')]
    shared = args.role.startswith('shared')
    image_flags = ['-fPIC', '-shared', '-Dmain=fixture_main', '-Wl,-soname,abi.input'] if shared else (
        ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie'])
    run('compile', [*tool_environment, compiler, *compile_flags, *image_flags, fixture, '-o', reference])
    run('strip', [*tool_environment, objcopy, '--strip-all', reference, binary])
    runtime = binary
    if shared:
        driver = case / 'driver.c'
        driver.write_text('extern int fixture_main(void);\nint main(void) { return fixture_main(); }\n')
        runtime = case / 'abi.driver'
        run('compile-driver', [*tool_environment, compiler, *compile_flags, '-fPIE', '-pie', driver,
            '-L' + str(case), '-l:abi.input', '-Wl,-rpath,$ORIGIN', '-o', runtime])
        before[str(runtime)] = support.digest(runtime)
    run('native-result', [emulator, '-L', sysroot, runtime])
    before.update({str(path): support.digest(path) for path in (reference, binary)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-Ws', reference])
    symbols, sizes = {}, {}
    wanted = {'wide_words', 'wide_pair', 'wide_large', 'wide_mixed', 'integer_sink', 'real_sink', 'pair_sink', 'large_sink',
        'words_callback', 'pair_callback', 'large_callback', 'mixed_callback'}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in wanted:
            name, address, size = fields[7], int(fields[1], 16), int(fields[2])
            assert name not in symbols or (symbols[name], sizes[name]) == (address, size)
            symbols[name], sizes[name] = address, size
    assert symbols.keys() == wanted and all(sizes.values())
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n' for name, address in sorted(symbols.items())))
    metadata = {'abi': args.abi, 'endian': args.endian, 'role': args.role, 'symbols': symbols,
        'sizes': sizes, 'emulator': emulator, 'sysroot': str(sysroot), 'runtime': runtime.name}
    run('original-elf', ['readelf', '-hSWln', binary])
    entry, = re.findall(r'Entry point address:\s+(0x[0-9a-f]+)', (case / 'original-elf.log').read_text())
    metadata['entryAddress'] = int(entry, 16)
    text, = re.findall(r'\]\s+\.text\s+PROGBITS\s+([0-9a-f]+)\s+', (case / 'original-elf.log').read_text())
    if shared:
        text, = re.findall(r'\]\s+\.text\s+PROGBITS\s+([0-9a-f]+)\s+', (case / 'original-elf.log').read_text())
        metadata['textAddress'] = int(text, 16)
    run('text-bytes', [*tool_environment, objcopy, '-O', 'binary', '--only-section=.text', reference, case / 'text.bin'])
    run('reference-info', ['readelf', '--debug-dump=info', reference])
    homes = reference_homes((case / 'reference-info.log').read_text())
    text_bytes = (case / 'text.bin').read_bytes()
    metadata['code'] = {name: text_bytes[address - int(text, 16):address - int(text, 16) + sizes[name]].hex()
        for name, address in symbols.items() if name.startswith('wide_')}
    metadata['homes'] = homes
    write('metadata.json', metadata)
    project, scripts = case / 'project', case / 'scripts'
    project.mkdir()
    scripts.mkdir()
    for script in ('ProbeMipsWideArguments.java', 'RebaseFixtureProgram.java'):
        shutil.copyfile(source / 'ghidra_scripts' / script, scripts / script)
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role.endswith('-rebased') else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'MipsWideArguments', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', scripts, *rebase, '-postScript', 'ProbeMipsWideArguments.java',
        'curate', case / 'labels.txt', case / 'curated.json'], clean=False)
    log = (case / 'import.log').read_text()
    assert 'REPORT SCRIPT ERROR' not in log and 'MIPS_WIDE_ARGUMENTS_OBSERVATION_PASS' in log
    curated = json.loads((case / 'curated.json').read_text())
    assert Path(unquote(urlsplit(curated['exporterOrigin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    assert (curated['language'], curated['compiler'], curated['pointerBytes']) == (
        'MIPS:' + args.endian.upper() + ':64:' + ('default' if args.abi == 'n64' else '64-32addr'),
        'default' if args.abi == 'n64' else 'n32', 8 if args.abi == 'n64' else 4)
    assert all(not row['customStorage'] for row in curated['functions'])
    if args.role.endswith('-rebased'):
        assert curated['delta'] >= 0x2000000
    project_before = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-before.json', project_before)
    hashes = None
    for iteration in ('first', 'repeat'):
        run(iteration, [ghidra / 'support/analyzeHeadless', project, 'MipsWideArguments', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', scripts, '-postScript', 'ProbeMipsWideArguments.java',
            'observe', case / 'labels.txt', case / (iteration + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], clean=False)
        log = (case / (iteration + '.log')).read_text()
        assert 'REPORT SCRIPT ERROR' not in log and 'GhidraDwarfForge symbol export PASS' in log
        assert curated == json.loads((case / (iteration + '.json')).read_text())
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: ' in line]
        assert report['status'] in ('SUCCESS', 'PARTIAL') and report['failure'] is None
        write(iteration + '-report.json', report)
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        assert hashes is None or hashes == current
        hashes = current
    for name, artifact in (('compiler', reference), ('forge', output)):
        run(name + '-gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', artifact])
        run(name + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        run(name + '-strict-driver', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (name + '-strict.log'), '--original', binary])
        run(name + '-gdb', ['bash', source / 'mips-wide-arguments-gdb.sh', case, name], clean=False)
        assert not (case / (name + '-gdb.stderr')).read_text().strip()
        assert 'MIPS_WIDE_ARGUMENTS_' + name.upper() + '_PASS' in (case / (name + '-gdb.log')).read_text()
        run(name + '-source-gdb', ['bash', source / 'mips-wide-arguments-gdb.sh', case, name, 'source'], clean=False)
        assert not (case / (name + '-source-gdb.stderr')).read_text().strip()
        assert 'MIPS_WIDE_ARGUMENTS_' + name.upper() + '_PASS' in (case / (name + '-source-gdb.log')).read_text()
        run(name + '-calls-gdb', ['bash', source / 'mips-wide-arguments-gdb.sh', case, name, 'calls'], clean=False)
        assert not (case / (name + '-calls-gdb.stderr')).read_text().strip()
        assert 'MIPS_WIDE_ARGUMENTS_' + name.upper() + '_PASS' in (case / (name + '-calls-gdb.log')).read_text()
    assert before == {path: support.digest(Path(path)) for path in before}
    project_after = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-after.json', project_after)
    changes = {name for name in project_before.keys() | project_after.keys()
        if project_before.get(name) != project_after.get(name)}
    assert changes <= {'MipsWideArguments.rep/idata/~index.bak', 'MipsWideArguments.rep/idata/~journal.bak'}, changes
    result = {'status': 'CONTROLS_PENDING' if args.with_controls else 'PASS', 'artifactSha256': hashes,
        'unchangedInputsAndProgramDatabase': True, 'projectBackupChanges': sorted(changes)}
    write('result.json', result)
    if args.with_controls:
        run('controls', ['python3', source / 'mips-wide-arguments-controls.py', case, ghidra])
        control, = case.glob('controls.*/result.json')
        result['controls'] = json.loads(control.read_text())
        assert result['controls']['status'] == 'PASS'
        result['status'] = 'PASS'
        write('result.json', result)
    print('mips-wide-arguments=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

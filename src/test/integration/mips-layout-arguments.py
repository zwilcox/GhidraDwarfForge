#!/usr/bin/env python3
"""Packaged N32/N64 aggregate classification and alignment at entry and body."""
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
spec = importlib.util.spec_from_file_location('layout_support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--abi', choices=('n32', 'n64'), required=True)
    parser.add_argument('--endian', choices=('be', 'le'), required=True)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased', 'shared', 'shared-rebased'), default='exec')
    parser.add_argument('--toolchain-root', type=Path)
    parser.add_argument('--gdb', default='gdb-multiarch')
    parser.add_argument('--gdb-data-directory', default='')
    parser.add_argument('--results-root', type=Path, default=repository / 'build/test-results/mips-layout-arguments')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    results = args.results_root.resolve()
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='.'.join((args.abi, args.endian, args.role)) + '.', dir=results))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, clean=True):
        support.run(command, case / (name + '.log'), timeout=240)
        if clean:
            support.require_clean(case / (name + '.log'))

    prefix = 'mips64' + ('el' if args.endian == 'le' else '') + '-linux-gnuabi64'
    environment, flags = [], []
    if args.toolchain_root:
        toolchain = args.toolchain_root.resolve(strict=True)
        environment = ['env', 'LD_LIBRARY_PATH=' + str(toolchain / 'usr/lib/x86_64-linux-gnu')]
        compiler = toolchain / 'usr/bin' / (prefix + '-gcc-12')
        objcopy = toolchain / 'usr/bin' / (prefix + '-objcopy')
        flags = ['--sysroot=' + str(toolchain), '-B' + str(toolchain / 'usr' / prefix / 'bin') + '/']
        sysroot = toolchain / 'usr' / prefix
    else:
        compiler, objcopy = prefix + '-gcc', prefix + '-objcopy'
        sysroot = Path('/usr') / prefix
    flags += ['-mabi=' + ('64' if args.abi == 'n64' else 'n32'), '-march=mips64r2',
        '-O1', '-g', '-gdwarf-5', '-Wl,--build-id=sha1']
    emulator = 'qemu-mips' + ('64' if args.abi == 'n64' else 'n32') + (
        'el' if args.endian == 'le' else '') + '-static'
    fixture = source.parent / 'fixtures/mips_layout_arguments.c'
    protected = [fixture, Path(__file__), source / 'mips-layout-arguments-gdb.py',
        source / 'mips-layout-arguments-gdb.sh', source / 'mips-layout-arguments-controls.py',
        source / 'ghidra_scripts/AbiDecompilerFailureExport.java', source / 'ghidra_scripts/CancelDuringElfCopy.java',
        source / 'ghidra_scripts/ProbeMipsLayoutArguments.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [path for path in module.rglob('*') if path.is_file()]
    debugger = Path(shutil.which(args.gdb) or args.gdb).resolve(strict=True)
    protected.append(debugger)
    before = {str(path): support.digest(path) for path in protected}
    debugger_data = ['--data-directory=' + args.gdb_data_directory] if args.gdb_data_directory else []
    run('debugger-version', [debugger, *debugger_data, '--version'])
    reference, binary, output = [case / name for name in ('reference', 'input', 'input.dbg')]
    shared = args.role.startswith('shared')
    image_flags = ['-fPIC', '-shared', '-Dmain=fixture_main', '-Wl,-soname,input'] if shared else (
        ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie'])
    run('compile', [*environment, compiler, *flags, *image_flags, fixture, '-o', reference])
    run('strip', [*environment, objcopy, '--strip-all', reference, binary])
    runtime = binary
    if shared:
        driver = case / 'driver.c'
        driver.write_text('extern int fixture_main(void);\nint main(void) { return fixture_main(); }\n')
        runtime = case / 'driver'
        run('compile-driver', [*environment, compiler, *flags, '-fPIE', '-pie', driver,
            '-L' + str(case), '-l:input', '-Wl,-rpath,$ORIGIN', '-o', runtime])
        before[str(runtime)] = support.digest(runtime)
    run('native', [emulator, '-L', sysroot, runtime])
    before.update({str(path): support.digest(path) for path in (reference, binary)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    labels = {}
    functions = {'layout_array', 'layout_union', 'layout_nested', 'layout_float_box',
        'layout_small', 'layout_padded', 'layout_aligned', 'layout_aligned_stack'}
    wanted = functions | {name + '_body' for name in functions}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in wanted:
            address = int(fields[1], 16)
            assert fields[7] not in labels or labels[fields[7]] == address
            labels[fields[7]] = address
    assert labels.keys() == wanted
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n'
        for name, address in sorted(labels.items())))
    run('original-elf', ['readelf', '-hSWln', binary])
    entry, = re.findall(r'Entry point address:\s+(0x[0-9a-f]+)', (case / 'original-elf.log').read_text())
    text, = re.findall(r'\]\s+\.text\s+PROGBITS\s+([0-9a-f]+)\s+', (case / 'original-elf.log').read_text())
    write('metadata.json', dict(abi=args.abi, endian=args.endian, labels=labels,
        sysroot=str(sysroot), emulator=emulator, role=args.role, runtime=runtime.name,
        entryAddress=int(entry, 16), textAddress=int(text, 16)))
    project, scripts = case / 'project', case / 'scripts'
    project.mkdir()
    scripts.mkdir()
    for script in ('ProbeMipsLayoutArguments.java', 'RebaseFixtureProgram.java'):
        shutil.copyfile(source / 'ghidra_scripts' / script, scripts / script)
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role.endswith('-rebased') else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Layout', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', scripts, *rebase, '-postScript',
        'ProbeMipsLayoutArguments.java', case / 'labels.txt', case / 'curated.json'], clean=False)
    assert 'MIPS_LAYOUT_PROBE_PASS' in (case / 'import.log').read_text()
    curated = json.loads((case / 'curated.json').read_text())
    assert Path(unquote(urlsplit(curated['exporterOrigin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    assert (curated['language'], curated['compiler'], curated['pointerBytes']) == (
        'MIPS:' + args.endian.upper() + ':64:' + ('default' if args.abi == 'n64' else '64-32addr'),
        'default' if args.abi == 'n64' else 'n32', 8 if args.abi == 'n64' else 4)
    if args.role.endswith('-rebased'):
        assert curated['delta'] >= 0x2000000
    project_before = {str(path.relative_to(project)): support.digest(path)
        for path in project.rglob('*') if path.is_file()}
    write('project-before.json', project_before)
    hashes = None
    for iteration in ('first', 'repeat'):
        run(iteration, [ghidra / 'support/analyzeHeadless', project, 'Layout', '-process', binary.name,
            '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java',
            '--packaged-natives', '--output=' + str(output)], clean=False)
        log = (case / (iteration + '.log')).read_text()
        assert 'REPORT SCRIPT ERROR' not in log and 'GhidraDwarfForge symbol export PASS' in log
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        assert hashes is None or hashes == current
        hashes = current
    for mode, artifact in (('compiler', reference), ('forge', output)):
        run(mode + '-gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', artifact])
        run(mode + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        run(mode + '-strict-driver', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (mode + '-strict.log'), '--original', binary])
        run(mode + '-gdb', ['bash', source / 'mips-layout-arguments-gdb.sh', case, mode,
            args.gdb, args.gdb_data_directory], clean=False)
        assert 'MIPS_LAYOUT_' + mode.upper() + '_PASS' in (case / (mode + '-gdb.log')).read_text()
        assert not (case / (mode + '-gdb.stderr')).read_text().strip()
    assert before == {path: support.digest(Path(path)) for path in before}
    project_after = {str(path.relative_to(project)): support.digest(path)
        for path in project.rglob('*') if path.is_file()}
    write('project-after.json', project_after)
    changes = {name for name in project_before.keys() | project_after.keys()
        if project_before.get(name) != project_after.get(name)}
    assert changes <= {'Layout.rep/idata/~index.bak', 'Layout.rep/idata/~journal.bak'}, changes
    result = dict(status='CONTROLS_PENDING', artifactSha256=hashes,
        scope='compiler body and Forge entry/body values; failure/cancellation; no whole-lifetime or injected-call claim',
        unchangedInputsAndProgramDatabase=True, projectBackupChanges=sorted(changes))
    write('result.json', result)
    run('controls', ['python3', source / 'mips-layout-arguments-controls.py', case, ghidra,
        debugger, args.gdb_data_directory], clean=False)
    assert 'mips-layout-arguments-controls=PASS' in (case / 'controls.log').read_text()
    assert before == {path: support.digest(Path(path)) for path in before}
    result['status'] = 'PASS'
    write('result.json', result)
    print('mips-layout-arguments=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

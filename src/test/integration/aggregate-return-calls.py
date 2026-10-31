#!/usr/bin/env python3
"""Real aggregate-return prototypes, supported calls and guarded MIPS transfers."""
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


support = load('aggregate_support', source.parent / 'performance/export-benchmark.py')
facts = load('aggregate_facts', source / 'dynamic-composite-storage-check.py')
elf_support = load('aggregate_elf', source / 'retained-function-aliases-export.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'))
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    parser.add_argument('--profile', choices=('fp32', 'fpxx'), default='fp32')
    parser.add_argument('--results-root', type=Path, default=repository / 'build/test-results/aggregate-return-calls')
    args = parser.parse_args()
    if args.profile != 'fp32' and not args.target.startswith('mips'):
        parser.error('--profile is a MIPS-only selection')
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = args.results_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='.'.join((args.target, args.role, args.profile)) + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, argv, clean=True):
        support.run(argv, case / (name + '.log'), timeout=240)
        if clean:
            support.require_clean(case / (name + '.log'))

    fixture = source.parent / 'fixtures/aggregate-return-calls.c'
    protected = [fixture, Path(__file__), source / 'aggregate-return-calls-gdb.py', source / 'aggregate-return-calls-gdb.sh',
        source / 'ghidra_scripts/PrepareAggregateCalls.java', source / 'ghidra_scripts/RebaseFixtureProgram.java',
        source / 'check-dwarfdump.py', source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh',
        source / 'dynamic-composite-storage-check.py', source / 'dynamic-parameter-storage-check.py',
        source / 'retained-function-aliases-export.py', source.parent / 'performance/export-benchmark.py']
    protected += [path for path in module.rglob('*') if path.is_file()]
    before = {str(path): support.digest(path) for path in protected}
    reference, binary, output = [case / ('calls.' + suffix) for suffix in ('reference', 'input', 'dbg')]
    prefix = {'x86_64': '', 'aarch64': 'aarch64-linux-gnu-', 'arm32': 'arm-linux-gnueabihf-',
        'mips32be': 'mips-linux-gnu-', 'mips32le': 'mipsel-linux-gnu-'}[args.target]
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    if args.target.startswith('mips'):
        flags += ['-mabi=32', '-march=mips32r2', '-m' + args.profile, '-mhard-float']
    if args.target == 'arm32':
        flags += ['-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=hard', '-marm', '-funwind-tables']
    run('compile', [prefix + 'gcc', '-O1', '-g', '-gdwarf-5', '-gno-variable-location-views',
        '-fno-inline', '-fno-ipa-sra', '-fno-omit-frame-pointer', '-Wl,--build-id=sha1', *flags, fixture, '-o', reference])
    run('strip', [prefix + 'objcopy', '--strip-all', reference, binary])
    before.update({str(path): support.digest(path) for path in (reference, binary)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    functions = ['triple64', 'triple32', 'pair64', 'scalar64', 'word_mix', 'marker']
    globals_ = ['sink', 'pointer_data', 'triple64_calls', 'triple32_calls', 'pair64_calls', 'scalar64_calls', 'words_calls']
    symbols = {}
    globals_ += [name + '_pointer' for name in functions if name != 'marker']
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in functions + globals_:
            assert fields[6].isdigit()
            assert fields[3] == ('FUNC' if fields[7] in functions else 'OBJECT')
            entry = int(fields[1], 16)
            assert fields[7] not in symbols or symbols[fields[7]] == entry
            symbols[fields[7]] = entry
    assert set(symbols) == set(functions + globals_)
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(entry) + '\n' for name, entry in symbols.items()))
    write('metadata.json', {'target': args.target, 'role': args.role, 'profile': args.profile, 'symbols': symbols, 'compilerFlags': flags})
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Aggregate', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareAggregateCalls.java', 'curate', case / 'labels.txt', case / 'curated.json'], clean=False)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    curated = json.loads((case / 'curated.json').read_text())
    assert Path(unquote(urlsplit(curated['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    if args.role == 'pie-rebased':
        assert curated['delta'] >= 0x2000000
    project_before = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-before.json', project_before)
    hashes = None
    for iteration in ('first', 'repeat'):
        run(iteration, [ghidra / 'support/analyzeHeadless', project, 'Aggregate', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts', '-postScript',
            'PrepareAggregateCalls.java', 'observe', case / 'labels.txt', case / (iteration + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], clean=False)
        log = (case / (iteration + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        assert curated == json.loads((case / (iteration + '.json')).read_text())
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        assert hashes is None or hashes == current
        hashes = current
        if iteration == 'first':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert not report['failedFunctions'] and report['failure'] is None
        write(iteration + '-report.json', report)
    for variant, artifact in [('compiler', reference), ('forge', output)]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log'), '--original', binary])
    ident, header, sections = elf_support.elf(output)
    old_ident, old_header, old_sections = elf_support.elf(binary)
    assert ident == old_ident and header[:4] == old_header[:4] and header[6] == old_header[6]
    assert header[4] == header[8] == header[9] == 0
    assert sections['.text'][0][3] == old_sections['.text'][0][3]
    assert sections['.note.gnu.build-id'][1] == old_sections['.note.gnu.build-id'][1]
    dies = facts.die_records((case / 'forge-info.log').read_text())
    raw = []
    for description in curated['functions']:
        name = description['name']
        function, = [row for row in dies if row['tag'] == 'DW_TAG_subprogram' and facts.facts.die_name(row) == name]
        assert int(function['attrs']['DW_AT_low_pc'], 16) == symbols[name]
        children = facts.children(dies, dies.index(function))
        parameters = [row for row in children if row['tag'] == 'DW_TAG_formal_parameter']
        explicit = [row for row in description['parameters'] if row['autoKind'] != 'RETURN_STORAGE_PTR']
        assert [facts.facts.die_name(row) for row in parameters] == [row['name'] for row in explicit]
        hidden = [row for row in description['parameters'] if row['autoKind'] == 'RETURN_STORAGE_PTR']
        for carrier in hidden:
            variable, = [row for row in children if row['tag'] == 'DW_TAG_variable' and facts.facts.die_name(row) == carrier['name']]
            assert variable['attrs']['DW_AT_artificial'] == '1'
        convention = function['attrs']['DW_AT_calling_convention'].split()[0]
        blocked = args.target.startswith('mips') and name in ('triple64', 'pair64')
        assert int(convention) == (3 if blocked else 1), (name, convention)
        raw.append({'function': function, 'parameters': parameters, 'hiddenCount': len(hidden)})
        if name != 'marker':
            callback, = [row for row in dies if row['tag'] == 'DW_TAG_subroutine_type' and
                facts.facts.die_name(row) == name + '_pointer_type']
            assert int(callback['attrs']['DW_AT_calling_convention'].split()[0]) == (3 if blocked else 1)
            callback_parameters = [row for row in facts.children(dies, dies.index(callback))
                if row['tag'] == 'DW_TAG_formal_parameter']
            assert len(callback_parameters) == len(explicit)
            raw[-1]['pointerType'] = callback
            raw[-1]['pointerParameters'] = callback_parameters
    write('raw-dies.json', raw)
    run('gdb-driver', ['bash', source / 'aggregate-return-calls-gdb.sh', repository, case, args.target])
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-after.json', project_after)
    changes = {name for name in project_before.keys() | project_after.keys() if project_before.get(name) != project_after.get(name)}
    assert changes <= {'Aggregate.rep/idata/~index.bak', 'Aggregate.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'profile': args.profile,
        'artifactHashes': hashes, 'projectChanges': sorted(changes), 'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar')})
    print('AGGREGATE_RETURN_CALLS_PASS', flush=True)


if __name__ == '__main__':
    main()

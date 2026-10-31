#!/usr/bin/env python3
"""Preserve variadic types and diagnose the unencoded no-return type property."""
import argparse
import importlib.util
import json
from pathlib import Path
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


support = load('flag_support', source.parent / 'performance/export-benchmark.py')
facts = load('flag_facts', source / 'dynamic-composite-storage-check.py')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--previous-ghidra', type=Path)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/function-type-flags'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.role + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, argv, clean=True):
        support.run(argv, case / (name + '.log'), timeout=240)
        if clean:
            support.require_clean(case / (name + '.log'))

    fixture = source.parent / 'fixtures/function-type-flags.c'
    protected = [fixture, Path(__file__), source / 'function-type-flags-gdb.py',
        source / 'function-type-flags-gdb.sh', source / 'ghidra_scripts/PrepareFunctionTypeFlags.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java', source / 'check-dwarfdump.py',
        source / 'elf-layout-gdb-oracle.sh', source / 'dynamic-composite-storage-check.py',
        source / 'dynamic-parameter-storage-check.py', source.parent / 'performance/export-benchmark.py']
    protected += [path for path in module.rglob('*') if path.is_file()]
    if args.previous_ghidra:
        protected += [path for path in (args.previous_ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if path.is_file()]
    reference, binary, output = [case / ('flags.' + suffix) for suffix in ('reference', 'input', 'dbg')]
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', ['gcc', '-O0', '-g', '-gdwarf-5', '-gno-variable-location-views', *flags, fixture, '-o', reference])
    run('strip', ['objcopy', '--strip-debug', reference, binary])
    protected += [reference, binary]
    before = {str(path): support.digest(path) for path in protected}
    write('protected-before.json', before)
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Flags', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareFunctionTypeFlags.java', 'curate', case / 'curated.json'], clean=False)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    curated = json.loads((case / 'curated.json').read_text())
    assert Path(unquote(urlsplit(curated['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    if args.role == 'pie-rebased':
        assert curated['delta'] >= 0x2000000
    project_before = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-before.json', project_before)
    variants = [('first', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    hashes = None
    diagnostic = ('Function type /noreturn_type no-return property omitted: DW_AT_noreturn describes subprograms; '
        'no validated subroutine-type mapping')
    for variant, installation in variants:
        run(variant, [installation / 'support/analyzeHeadless', project, 'Flags', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts', '-postScript',
            'PrepareFunctionTypeFlags.java', 'observe', case / (variant + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], clean=False)
        text = (case / (variant + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in text
        observed = json.loads((case / (variant + '.json')).read_text())
        assert {k: v for k, v in observed.items() if k != 'origin'} == {k: v for k, v in curated.items() if k != 'origin'}
        assert Path(unquote(urlsplit(observed['origin']).path)).resolve() == (installation / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar').resolve()
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in text.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert not report['failedFunctions'] and report['failure'] is None
        assert report['diagnostics'].count(diagnostic) == (0 if variant == 'previous' else 1)
        write(variant + '-report.json', report)
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        assert hashes is None or hashes == current, 'diagnostic-only change altered artifact bytes'
        hashes = current
        shutil.copyfile(output, case / (variant + '.dbg'))
        shutil.copyfile(Path(str(output) + '.c'), case / (variant + '.dbg.c'))
    for variant, artifact in [('compiler', reference), ('forge', output)]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log'), '--original', binary])
    dies = facts.die_records((case / 'forge-info.log').read_text())
    for row in curated['records']:
        function, = [die for die in dies if die['tag'] == 'DW_TAG_subprogram' and facts.facts.die_name(die) == row['name']]
        assert ('DW_AT_noreturn' in function['attrs']) == row['noReturn']
        assert int(function['attrs']['DW_AT_low_pc'], 16) == row['entry']
        callback, = [die for die in dies if die['tag'] == 'DW_TAG_subroutine_type' and
            facts.facts.die_name(die) == row['type'].removeprefix('/')]
        assert 'DW_AT_noreturn' not in callback['attrs']
        children = facts.children(dies, dies.index(callback))
        assert sum(die['tag'] == 'DW_TAG_formal_parameter' for die in children) == 1
        assert sum(die['tag'] == 'DW_TAG_unspecified_parameters' for die in children) == int(row['variadic'])
    write('raw-dies.json', dies)
    run('gdb-driver', ['bash', source / 'function-type-flags-gdb.sh', repository, case])
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(path.relative_to(project)): support.digest(path) for path in project.rglob('*') if path.is_file()}
    write('project-after.json', project_after)
    changes = {name for name in project_before.keys() | project_after.keys() if project_before.get(name) != project_after.get(name)}
    assert changes <= {'Flags.rep/idata/~index.bak', 'Flags.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'role': args.role, 'hashes': hashes,
        'previousCompared': bool(args.previous_ghidra), 'jarSha256': support.digest(module / 'lib/GhidraDwarfForge.jar')})
    print('function-type-flags-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

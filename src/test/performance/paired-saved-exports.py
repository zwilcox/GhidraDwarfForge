#!/usr/bin/env python3
"""Compare installed exporters against one copied saved benchmark project."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('benchmark_support', source / 'export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference_case', type=Path, help='Recorded SQLite or synthetic benchmark case directory')
    parser.add_argument('baseline_ghidra', type=Path)
    parser.add_argument('candidate_ghidra', type=Path)
    parser.add_argument('--pairs', type=int, default=5)
    parser.add_argument('--synthetic-functions', type=int, help='Select a synthetic export-benchmark.py case of this size')
    args = parser.parse_args()
    if not 2 <= args.pairs <= 10:
        parser.error('pairs must be between 2 and 10')
    reference = args.reference_case.resolve(strict=True)
    if args.synthetic_functions is not None:
        if args.synthetic_functions <= 0:
            parser.error('synthetic-functions must be positive')
        summary, = [row for row in json.loads((reference.parent / 'summary.json').read_text())
            if row['requestedFunctions'] == args.synthetic_functions]
        binary, program_name = reference / 'benchmark', 'Benchmark'
        evidence = [reference.parent / 'summary.json', reference / 'benchmark.c']
        workload = f'Synthetic {args.synthetic_functions}-function fixture'
    else:
        summary = json.loads((reference / 'summary.json').read_text())
        assert summary['status'] == 'PASS'
        binary, program_name = reference / 'sqlite-workload', 'SQLite'
        provenance = json.loads((reference / 'source-provenance.json').read_text())
        assert provenance['archiveSha256'] == '77823cb110929c2bcb0f5d48e4833b5c59a8a6e40cdea3936b99e199dbbe5784'
        evidence = [reference / 'summary.json', reference / 'source-provenance.json']
        workload = 'SQLite 3.46.1 benchmark'
    assert support.digest(binary) == summary['inputSha256']
    installations = {'baseline': args.baseline_ghidra.resolve(strict=True),
        'candidate': args.candidate_ghidra.resolve(strict=True)}
    root = repository / 'build/test-results/paired-saved-exports'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    print(case, flush=True)
    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')
    def run(name, command, **kwargs):
        return support.run(command, case / (name + '.log'), **kwargs)
    protected = [Path(__file__).resolve(), source / 'export-benchmark.py', binary, *evidence]
    protected += [p for p in (reference / 'project').rglob('*') if p.is_file()]
    for ghidra in installations.values():
        protected += [p for p in (ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    project = case / 'project'
    shutil.copytree(reference / 'project', project)
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    write('environment.json', {'host': platform.platform(), 'loadAverage': os.getloadavg(),
        'pairs': args.pairs, 'workload': workload, 'referenceCase': str(reference), 'inputSha256': summary['inputSha256'],
        'jars': {name: support.digest(path / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar')
            for name, path in installations.items()},
        'scope': 'Alternating AB/BA pairs, fresh JVM per export, same copied saved program and output paths. '
            'GNU time includes startup/decompilation; RSS is process-family high water, not aggregate memory. '
            'Warm caches and other host work are uncontrolled. No import, validation or debugger time included.'})
    output = case / (binary.name + '.dbg')
    samples = []
    first_hashes = None
    first_counts = None
    for pair in range(args.pairs):
        order = ('baseline', 'candidate') if pair % 2 == 0 else ('candidate', 'baseline')
        for variant in order:
            print(f'pair={pair} variant={variant}', flush=True)
            ghidra = installations[variant]
            wrapper = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless'
            name = f'{pair}-{variant}'
            sample = run(name, [wrapper, '--ghidra-dir=' + str(ghidra),
                '--project-dir=' + str(project), '--project-name=' + program_name, '--program=' + binary.name,
                '--input=' + str(binary), '--output=' + str(output)], timeout=1800, measured=True)
            reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in (case / (name + '.log')).read_text().splitlines()
                if 'GhidraDwarfForge report: {' in line]
            report, = reports
            assert report['failure'] is None and not report['failedFunctions']
            write(name + '.report.json', report)
            hashes = [support.digest(output), support.digest(Path(str(output) + '.c'))]
            if first_hashes is None:
                first_hashes, first_counts = hashes, report['counts']
                shutil.copyfile(output, case / 'first.dbg')
                shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
            assert hashes == first_hashes and report['counts'] == first_counts, 'semantic artifact changed'
            sample.update(pair=pair, variant=variant, artifactSha256=hashes)
            samples.append(sample)
            write('samples.json', samples)
    if args.synthetic_functions is not None:
        support.validate(binary, output, case / 'validation', args.synthetic_functions)
        strict_result = case / 'validation/libdwarf-checks.log.check.json'
    else:
        # Every sample produced the same bytes; validate that unique artifact once.
        for name, command in [('llvm', ['llvm-dwarfdump', '--verify', output]),
                ('strict', ['python3', source.parent / 'integration/check-dwarfdump.py', output,
                    case / 'strict-checks.log', '--original', binary]),
                *[(view, ['readelf', '--debug-dump=' + view, output])
                    for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')],
                ('header', ['readelf', '-h', output]), ('sections', ['readelf', '-SW', output]),
                ('notes', ['readelf', '-n', output])]:
            run(name, command, timeout=300)
            support.require_clean(case / (name + '.log'))
        assert 'No errors.' in (case / 'llvm.log').read_text()
        script = case / 'behavior.gdb'
        script.write_text('\n'.join([
            'set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set auto-solib-add off',
            'set disable-randomization off', 'set python print-stack full',
            'file ' + str(binary), 'symbol-file ' + str(output), 'python',
            'exits = []', 'gdb.events.exited.connect(lambda event: exits.append(getattr(event, "exit_code", None)))',
            'for name in ("benchmark_checkpoint", "sqlite3_step", "sqlite3_exec"):',
            '    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)',
            '    assert symbol is not None and symbol.type.code == gdb.TYPE_CODE_FUNC and symbol.symtab is not None',
            '    assert symbol.type.target().strip_typedefs().code == gdb.TYPE_CODE_INT',
            '    assert symbol.type.target().sizeof == 4', 'end',
            'ptype benchmark_checkpoint', 'list benchmark_checkpoint', 'break *benchmark_checkpoint', 'run',
            'disable breakpoints', 'python',
            'assert int(gdb.parse_and_eval("*(unsigned int*)&observed_count")) == 100',
            'assert int(gdb.parse_and_eval("*(unsigned int*)&observed_sum")) == 5050',
            'finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)', 'gdb.execute("next")',
            'assert finish.return_value is None', 'gdb.execute("step")',
            'if finish.return_value is None: gdb.execute("continue")',
            'assert int(finish.return_value) == 5150', 'gdb.execute("continue")',
            'assert exits == [0]', 'end', 'echo sqlite-paired-gdb=PASS\\n', '']))
        run('gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-x', script], timeout=180)
        support.require_clean(case / 'gdb.log')
        assert 'sqlite-paired-gdb=PASS' in (case / 'gdb.log').read_text()
        strict_result = case / 'strict-checks.log.check.json'
    after = {str(p): support.digest(p) for p in protected}
    write('protected-after.json', after)
    assert before == after
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys())
        if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {program_name + '.rep/idata/~index.bak', program_name + '.rep/idata/~journal.bak'}
    result = {'status': 'PASS', 'samples': samples, 'artifactSha256': first_hashes, 'counts': first_counts,
        'mediansSeconds': {name: statistics.median(s['elapsedSeconds'] for s in samples if s['variant'] == name)
            for name in installations},
        'maximumResidentKiB': {name: max(s['maximumResidentKiB'] for s in samples if s['variant'] == name)
            for name in installations}, 'protectedUnchanged': True, 'projectBackupChanges': changes,
        'strict': json.loads(strict_result.read_text()), 'gdb': 'PASS',
        'scope': workload + ' on this host; identical artifact bytes, no general speed/memory guarantee.'}
    write('result.json', result)
    print('paired-saved-exports=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

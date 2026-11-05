#!/usr/bin/env python3
"""Compare installed exporters against one copied saved benchmark project."""
import argparse
import gzip
import hashlib
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
    parser.add_argument('reference_case', type=Path, help='Recorded SQLite, U-Boot or synthetic benchmark case directory')
    parser.add_argument('baseline_ghidra', type=Path)
    parser.add_argument('candidate_ghidra', type=Path)
    parser.add_argument('--pairs', type=int, default=5)
    parser.add_argument('--coverage', action='store_true',
        help='compare schema-one baseline with definition-two scorecards; verify deterministic reports and archive large logs')
    kind = parser.add_mutually_exclusive_group()
    kind.add_argument('--synthetic-functions', type=int, help='Select a synthetic export-benchmark.py case of this size')
    kind.add_argument('--uboot', action='store_true', help='Select a passing pinned U-Boot benchmark case')
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
    elif args.uboot:
        summary = json.loads((reference / 'summary.json').read_text())
        assert summary['status'] == 'PASS'
        built = Path(summary['buildCase']).resolve(strict=True)
        receipt = json.loads((built / 'build-result.json').read_text())
        assert receipt['status'] == 'PASS' and receipt['version'] == '2025.01'
        assert receipt['archiveSha256'] == 'cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f'
        for name in ('u-boot.reference', 'u-boot.workload', 'u-boot.dtb', 'build.config'):
            assert support.digest(built / name) == receipt['artifacts'][name]['sha256']
        binary, program_name = built / 'u-boot.workload', 'UBoot'
        summary['inputSha256'] = receipt['artifacts'][binary.name]['sha256']
        expected_report = json.loads((reference / 'export-0.report.json').read_text())
        addresses = json.loads((reference / 'function-addresses.json').read_text())
        evidence = [reference / name for name in ('summary.json', 'export-0.report.json', 'function-addresses.json')]
        evidence += [built / name for name in ('build-result.json', 'u-boot.reference', 'u-boot.dtb', 'build.config')]
        evidence += [source / 'uboot-benchmark.py']
        workload = 'U-Boot 2025.01 sandbox firmware code (not bare-metal hardware)'
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
    protected = [Path(__file__).resolve(), source / 'export-benchmark.py',
        source / 'headless-observations.py', binary, *evidence]
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
    first_reports = {}
    candidate_report = case / 'candidate-first.report.json'
    for pair in range(args.pairs):
        order = ('baseline', 'candidate') if pair % 2 == 0 else ('candidate', 'baseline')
        for variant in order:
            print(f'pair={pair} variant={variant}', flush=True)
            ghidra = installations[variant]
            wrapper = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless'
            name = f'{pair}-{variant}'
            command = [wrapper, '--ghidra-dir=' + str(ghidra),
                '--project-dir=' + str(project), '--project-name=' + program_name, '--program=' + binary.name,
                '--input=' + str(binary), '--output=' + str(output)]
            if args.uboot:
                command += ['--gdb-loader']
            sample = run(name, command, timeout=1800, measured=True)
            sample['runtime'] = support.verify_headless(case / (name + '.log'),
                ghidra / 'Ghidra/Extensions/GhidraDwarfForge', exported=True)
            bodies = [line.split('GhidraDwarfForge report: ', 1)[1]
                for line in (case / (name + '.log')).read_text().splitlines()
                if 'GhidraDwarfForge report: {' in line]
            body, = bodies
            report, report_end = json.JSONDecoder().raw_decode(body)
            assert body[report_end:].strip() == '(GhidraScript)'
            assert report['failure'] is None
            if args.uboot:
                # Retain the known timeout rather than relabeling this PARTIAL
                # workload as complete recovery or replacing it with an easier one.
                for field in ('status', 'counts', 'failedFunctions', 'skippedFunctions'):
                    assert report[field] == expected_report[field], field
            else:
                assert not report['failedFunctions']
            if args.coverage:
                raw = body[:report_end].encode('utf-8')
                report_sha = hashlib.sha256(raw).hexdigest()
                assert report_sha == first_reports.setdefault(variant, report_sha), 'report bytes changed across repeated exports'
                assert report['schemaVersion'] == (1 if variant == 'baseline' else 2)
                if variant == 'candidate':
                    assert report['coverage']['definitionVersion'] == 2
                    assert report['validation'] == {'status': 'NOT_RUN'}
                    assert len(raw) <= 64 * 1024 * 1024
                    if not candidate_report.exists():
                        candidate_report.write_bytes(raw)
                    sample['coverageSummary'] = report['coverage']['summary']
                else:
                    assert 'coverage' not in report
                with gzip.open(case / (name + '.report.json.gz'), 'wb') as stream:
                    stream.write(raw)
                with gzip.open(case / (name + '.report.json.gz'), 'rb') as stream:
                    assert hashlib.file_digest(stream, 'sha256').hexdigest() == report_sha
                sample.update(reportUtf8Bytes=len(raw), reportSha256=report_sha,
                    schemaVersion=report['schemaVersion'])
                sample['logArchive'] = archive_log(case / (name + '.log'))
            else:
                write(name + '.report.json', report)
            suffixes = ('', '.c', '.gdb.py') if args.uboot else ('', '.c')
            hashes = [support.digest(Path(str(output) + suffix)) for suffix in suffixes]
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
        if args.uboot:
            behavior_spec = importlib.util.spec_from_file_location('uboot_behavior', source / 'uboot-benchmark.py')
            behavior = importlib.util.module_from_spec(behavior_spec)
            behavior_spec.loader.exec_module(behavior)
            behavior.validate_behavior(case, built / 'u-boot.reference', binary, built / 'u-boot.dtb', output, addresses)
        else:
            validate_sqlite_behavior(case, binary, output, run)
        strict_result = case / 'strict-checks.log.check.json'
    if args.coverage:
        module = installations['candidate'] / 'Ghidra/Extensions/GhidraDwarfForge'
        launcher = module / 'support/ghidra-dwarf-forge-report'
        prefix = [launcher, '--ghidra-dir=' + str(installations['candidate']),
            '--extension-dir=' + str(module), '--report=' + str(candidate_report)]
        cli = {}
        for name, options in [('summary', ['--summary']), ('comparison', ['--before=' + str(candidate_report)])]:
            cli[name] = run('coverage-cli-' + name, [*prefix, *options], timeout=600, measured=True)
            text = (case / ('coverage-cli-' + name + '.log')).read_text()
            assert not (case / ('coverage-cli-' + name + '.stderr')).read_text().strip()
            if name == 'comparison':
                assert 'Reported changes: 0;' in text
            else:
                assert 'not execution coverage' in text
        write('coverage-cli.json', cli)
        archive_log(candidate_report)
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
    if args.coverage:
        result['coverage'] = {'reportSha256': first_reports, 'cli': cli,
            'medianUserSeconds': {name: statistics.median(s['userSeconds'] for s in samples if s['variant'] == name)
                for name in installations},
            'medianSystemSeconds': {name: statistics.median(s['systemSeconds'] for s in samples if s['variant'] == name)
                for name in installations},
            'medianResidentKiB': {name: statistics.median(s['maximumResidentKiB'] for s in samples if s['variant'] == name)
                for name in installations},
            'pairs': [{metric: {name: next(s[metric] for s in samples if s['pair'] == pair and s['variant'] == name)
                    for name in installations} for metric in ('elapsedSeconds', 'userSeconds', 'systemSeconds', 'maximumResidentKiB')}
                for pair in range(args.pairs)]}
    write('result.json', result)
    print('paired-saved-exports=PASS ' + str(case), flush=True)


def archive_log(path):
    """Retain exact evidence without accumulating large repeated JSON lines on disk."""
    original_sha = support.digest(path)
    archive = path.with_suffix(path.suffix + '.gz')
    assert not archive.exists()
    with path.open('rb') as source_stream, gzip.open(archive, 'wb') as target:
        shutil.copyfileobj(source_stream, target)
    with gzip.open(archive, 'rb') as stream:
        assert hashlib.file_digest(stream, 'sha256').hexdigest() == original_sha
    assert support.digest(path) == original_sha
    result = {'original': str(path), 'archive': str(archive), 'sha256': original_sha,
        'originalBytes': path.stat().st_size, 'archiveBytes': archive.stat().st_size, 'verified': True}
    path.unlink()
    return result


def validate_sqlite_behavior(case, binary, output, run):
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


if __name__ == '__main__':
    main()

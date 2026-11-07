#!/usr/bin/env python3
"""Alternate single/multi-file production exports and fresh-debugger navigation."""
import argparse
import gzip
import importlib.util
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('benchmark_support', HERE / 'export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def archive_log(path):
    """Verify compressed copies before removing only this run's large logs."""
    expected = support.digest(path)
    archive = path.with_suffix(path.suffix + '.gz')
    assert not archive.exists()
    with path.open('rb') as source, gzip.open(archive, 'wb') as target:
        shutil.copyfileobj(source, target)
    import hashlib
    with gzip.open(archive, 'rb') as source:
        assert hashlib.file_digest(source, 'sha256').hexdigest() == expected
    assert support.digest(path) == expected
    record = {'sha256': expected, 'bytes': path.stat().st_size, 'archive': str(archive)}
    path.unlink()
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--work', type=Path, required=True, help='new evidence/project directory')
    parser.add_argument('--artifacts', type=Path, help='new artifact directory on a filesystem supporting hard links')
    parser.add_argument('--counts', type=int, nargs='+', default=[1000, 10000])
    parser.add_argument('--pairs', type=int, default=3)
    parser.add_argument('--source-lines', type=int, default=1000)
    parser.add_argument('--java', type=Path, help='explicit Java 21 runtime with isolated script caches')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('this measured runtime fixture requires Linux x86-64')
    if not 2 <= args.pairs <= 10 or not 1 <= args.source_lines <= 2147483647:
        parser.error('use 2..10 pairs and a positive source line target')
    if len(set(args.counts)) != len(args.counts) or any(count < 10 or count > 10000 for count in args.counts):
        parser.error('use distinct function counts between 10 and 10000')
    ghidra, root = args.ghidra.resolve(strict=True), args.work.resolve()
    root.mkdir(parents=True, exist_ok=False)
    artifacts = args.artifacts.resolve() if args.artifacts else root / 'artifacts'
    artifacts.mkdir(parents=True, exist_ok=False)
    print('multifile-benchmark-results=' + str(root), flush=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    integration = HERE.parent / 'integration'
    protected_paths = [Path(__file__), HERE / 'export-benchmark.py', HERE / 'headless-observations.py',
        HERE / 'multifile-navigation.py', integration / 'check-multifile-semantics.py',
        integration / 'check-dwarfdump.py', *[p for p in module.rglob('*') if p.is_file()]]
    protected = {str(p): support.digest(p) for p in protected_paths}

    def write(directory, name, value):
        (directory / (name + '.json')).write_text(json.dumps(value, indent=4) + '\n')

    def run(directory, name, command, measured=False):
        return support.run(command, directory / (name + '.log'), measured=measured, cwd=directory)

    headless = [ghidra / 'support/analyzeHeadless']
    if args.java:
        import subprocess
        java = args.java.resolve(strict=True)
        vmargs = subprocess.check_output([java, '-cp', ghidra / 'support/LaunchSupport.jar',
            'LaunchSupport', ghidra, '-vmargs'], text=True).splitlines()
        # Ghidra's application log also receives the full coverage report.
        # Keep its potentially large rotations with the evidence, not on a
        # small hard-link-capable filesystem reserved for final artifacts.
        (root / 'java-home').mkdir()
        (artifacts / 'java-tmp').mkdir()
        headless = [java, *vmargs, '-Duser.home=' + str(root / 'java-home'),
            '-Djava.io.tmpdir=' + str(artifacts / 'java-tmp'), '-Xmx2G', '-XX:ParallelGCThreads=2',
            '-XX:CICompilerCount=2', '-Djava.awt.headless=true', '-showversion', '-cp',
            ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar', 'ghidra.Ghidra',
            'ghidra.app.util.headless.AnalyzeHeadless']
    write(root, 'environment', {'host': platform.platform(), 'cpuCount': os.cpu_count(),
        'loadAverageAtStart': os.getloadavg(), 'startedUtc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'counts': args.counts, 'pairs': args.pairs, 'sourceLines': args.source_lines, 'protectedSha256': protected,
        'measurementBoundary': 'One retained warm-up per layout followed by alternating AB/BA measured pairs; '
            'fresh JVM and GDB per sample. Warm-ups include first publication and script-cache initialization, '
            'and are excluded from medians. Export includes JVM startup, '
            'saved-program loading, decompilation, native production and publication. Import, validators and debugger '
            'time excluded from export. RSS is process-family high water, not aggregate memory. Fresh GDB symbol '
            'load, all-function lookup, scattered source listing and file-qualified breakpoint timings are separate. '
            'Caches and other host work are uncontrolled. No general speed or cold-cache claim.'})
    for tool in ('gcc', 'readelf', 'llvm-dwarfdump', 'gdb-multiarch'):
        run(root, 'version-' + tool, [tool, '--version'])
    summaries = []
    for count in args.counts:
        case = root / ('functions-' + str(count))
        case.mkdir()
        output_root = artifacts / case.name
        output_root.mkdir()
        destinations = {layout: output_root / directory / 'benchmark.dbg'
            for layout, directory in [('single', 'single'), ('multi', 'multi_')]}
        for path in destinations.values():
            path.parent.mkdir()
        binary = support.make_fixture(case, count)
        protected.update({str(p): support.digest(p) for p in (binary, case / 'benchmark.c')})
        project = case / 'project'
        project.mkdir()
        imported = run(case, 'import', [*headless, project, 'Benchmark', '-import', binary,
            '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '1200'], measured=True)
        imported['runtime'] = support.verify_headless(case / 'import.log', module)
        assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
        before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
        run(case, 'symbols', ['nm', '-n', '-S', binary])
        addresses = {}
        for line in (case / 'symbols.log').read_text().splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[-1].startswith('bench_'):
                start, size = int(fields[0], 16), int(fields[1], 16)
                addresses[fields[-1]] = [start, start + size]
        assert addresses.keys() == {f'bench_{i}' for i in range(count)}
        queries = random.Random(115).sample(list(addresses), min(200, count))
        write(case, 'addresses', addresses)
        samples, hashes, first_counts, sizes = [], {}, None, {}
        for pair in [-1, *range(args.pairs)]:
            for layout in (('single', 'multi') if pair < 0 or pair % 2 == 0 else ('multi', 'single')):
                print(f'functions={count} pair={pair} layout={layout}', flush=True)
                sidecar = destinations[layout]
                label = str(pair) + '-' + layout
                options = [] if layout == 'single' else ['--source-lines=' + str(args.source_lines)]
                measured = run(case, label, [*headless, project, 'Benchmark', '-process', 'benchmark',
                    '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives',
                    '--output=' + str(sidecar), *options], measured=True)
                measured['runtime'] = support.verify_headless(case / (label + '.log'), module, exported=True)
                bodies = [line.split('GhidraDwarfForge report: ', 1)[1] for line in
                    (case / (label + '.log')).read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
                body, = bodies
                report, end = json.JSONDecoder().raw_decode(body)
                assert body[end:].strip() == '(GhidraScript)'
                assert report['failure'] is None and report['counts']['functionsFailed'] == 0
                assert report['counts']['functionsDecompiled'] >= count
                if first_counts is None:
                    first_counts = report['counts']
                assert report['counts'] == first_counts
                files = [sidecar, Path(str(sidecar) + '.c'), *sorted(sidecar.parent.glob('forge-src-*'))]
                current = {p.name: support.digest(p) for p in files}
                assert current == hashes.setdefault(layout, current), 'nondeterministic source layout'
                sizes[layout] = {'sidecarBytes': sidecar.stat().st_size,
                    'sourceBytesIncludingIndexAndManifest': sum(p.stat().st_size for p in files[1:]),
                    'totalArtifactBytes': sum(p.stat().st_size for p in files), 'files': len(files),
                    'largestSourceFileBytes': max(p.stat().st_size for p in files if p.suffix == '.c')}
                record = {'pair': pair, 'warmup': pair < 0, 'layout': layout, 'export': measured, 'status': report['status'],
                    'counts': report['counts'], 'artifactSha256': current,
                    'publication': 'first' if pair < 0 else 'reuse-existing-generation'}
                record['exportLog'] = archive_log(case / (label + '.log'))
                request = {'binary': str(binary), 'sidecar': str(sidecar), 'layout': layout,
                    'addresses': addresses, 'queries': queries, 'result': str(case / (label + '-navigation.json'))}
                write(case, label + '-request', request)
                run(case, label + '-gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-ex',
                    'set $forge_request = ' + json.dumps(str(case / (label + '-request.json'))),
                    '-x', HERE / 'multifile-navigation.py'])
                support.require_clean(case / (label + '-gdb.log'))
                navigation = json.loads(Path(request['result']).read_text())
                assert navigation['status'] == 'PASS' and navigation['functions'] == count
                record['navigation'] = navigation
                samples.append(record)
                write(case, 'samples', samples)
        run(case, 'semantics', [sys.executable, integration / 'check-multifile-semantics.py', binary,
            destinations['single'], destinations['multi'], case / 'semantics'])
        for layout, sidecar in destinations.items():
            validation = case / ('validate-' + layout)
            validation.mkdir()
            for name, command in [('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
                    ('strict', [sys.executable, integration / 'check-dwarfdump.py', sidecar,
                        validation / 'dwarfdump.log', '--original', binary]),
                    *[(view, ['readelf', '-hSWn', '--debug-dump=' + view, sidecar])
                        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')]]:
                run(validation, name, command)
                support.require_clean(validation / (name + '.log'))
        after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
        changed = sorted(p for p in before.keys() | after.keys() if before.get(p) != after.get(p))
        assert set(changed) <= {'Benchmark.rep/idata/~index.bak', 'Benchmark.rep/idata/~journal.bak'}
        assert protected == {p: support.digest(Path(p)) for p in protected}
        measured_samples = [s for s in samples if not s['warmup']]
        medians = {layout: {'exportSeconds': statistics.median(s['export']['elapsedSeconds'] for s in measured_samples if s['layout'] == layout),
            'peakResidentKiB': max(s['export']['maximumResidentKiB'] for s in measured_samples if s['layout'] == layout),
            **{metric: statistics.median(s['navigation']['metrics'][metric] for s in measured_samples if s['layout'] == layout)
                for metric in measured_samples[0]['navigation']['metrics']}} for layout in destinations}
        comparisons = {}
        for metric in medians['single']:
            def measured_value(sample):
                if metric == 'exportSeconds':
                    return sample['export']['elapsedSeconds']
                if metric == 'peakResidentKiB':
                    return sample['export']['maximumResidentKiB']
                return sample['navigation']['metrics'][metric]
            ratios = [measured_value(next(s for s in samples if s['pair'] == pair and s['layout'] == 'multi')) /
                measured_value(next(s for s in samples if s['pair'] == pair and s['layout'] == 'single')) for pair in range(args.pairs)]
            direction = 'observed regression' if all(r > 1 for r in ratios) else (
                'observed reduction' if all(r < 1 for r in ratios) else 'mixed/inconclusive')
            comparisons[metric] = {'pairedMultiOverSingle': ratios, 'observation': direction,
                'scope': 'Small-sample observation, not statistical significance or a general performance guarantee.'}
        summary = {'status': 'PASS', 'functions': count, 'pairs': args.pairs, 'sourceLines': args.source_lines,
            'inputSha256': support.digest(binary), 'sourceSha256': support.digest(case / 'benchmark.c'),
            'import': imported, 'sizes': sizes, 'medians': medians, 'comparisons': comparisons,
            'samples': samples, 'projectBackupChanges': changed, 'protectedUnchanged': True,
            'artifactDirectories': {layout: str(path.parent) for layout, path in destinations.items()},
            'scope': 'Synthetic function-count fixture, not representative firmware. Timings retain regressions and '
                'inconclusive results; no performance threshold is used as an acceptance shortcut.'}
        write(case, 'summary', summary)
        summaries.append(summary)
        write(root, 'summary', summaries)
    print('multifile-benchmark=PASS', flush=True)


if __name__ == '__main__':
    main()

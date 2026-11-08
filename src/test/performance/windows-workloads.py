#!/usr/bin/env python3
"""Measure real packaged Windows exports; preserve artifacts for Linux GDB replay."""
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
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), SOURCE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('corpus', type=Path)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('helper', type=Path)
    parser.add_argument('results', type=Path)
    parser.add_argument('--checker-configuration', type=Path, required=True)
    parser.add_argument('--baseline-control-receipt', type=Path, required=True)
    parser.add_argument('--pairs', type=int, default=5)
    args = parser.parse_args()
    if os.name != 'nt' or not 2 <= args.pairs <= 10:
        parser.error('native Windows and 2..10 pairs required')
    support = load('export-benchmark')
    catalog = load('catalog-source-equivalence')
    dwarf_comparison = load('dwarf-revision-equivalence')
    corpus = args.corpus.resolve(strict=True)
    metadata = json.loads((corpus / 'corpus.json').read_text())
    assert metadata['schemaVersion'] == 1 and metadata['status'] == 'BUILT'
    for name, digest in metadata['files'].items():
        path = (corpus / name).resolve(strict=True)
        assert path.is_relative_to(corpus) and support.digest(path) == digest, name
    installations = {key: value.resolve(strict=True) for key, value in
        (('baseline', args.baseline), ('candidate', args.candidate))}
    helper = args.helper.resolve(strict=True)
    shell = Path(shutil.which('pwsh')).resolve(strict=True)
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='run.', dir=args.results.resolve()))
    print(root, flush=True)
    def write(path, value):
        path.write_text(json.dumps(value, indent=4) + '\n', encoding='utf-8')
    protected = [Path(__file__).resolve(), helper, SOURCE / 'export-benchmark.py',
        SOURCE / 'headless-observations.py', SOURCE / 'jfr-phases.py',
        SOURCE / 'coverage-measurement-package.py', SOURCE / 'catalog-source-equivalence.py',
        SOURCE / 'dwarf-revision-equivalence.py',
        args.baseline_control_receipt.resolve(strict=True),
        corpus / 'corpus.json']
    protected += [corpus / name for name in metadata['files']]
    for ghidra in installations.values():
        protected.append(ghidra / 'support/launch.properties')
        module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
        for line in (module / 'RELEASE-SHA256SUMS').read_text().splitlines():
            digest, name = line.split(None, 1)
            path = (module / name.lstrip('*')).resolve(strict=True)
            assert path.is_relative_to(module.resolve()) and support.digest(path) == digest
        protected += [p for p in module.rglob('*') if p.is_file()]
    package = load('coverage-measurement-package')
    baseline_module = installations['baseline'] / 'Ghidra/Extensions/GhidraDwarfForge'
    candidate_module = installations['candidate'] / 'Ghidra/Extensions/GhidraDwarfForge'
    control = json.loads(args.baseline_control_receipt.read_text(encoding='utf-8'))
    assert control['status'] == 'PASS' and control['compiledClassesMatchCandidate']
    assert control['productionInputsUnchanged']
    assert Path(control['controlModule']).resolve() == baseline_module.resolve()
    assert control['controlFiles'] == package.manifest(baseline_module)
    assert control['correctedSourceSha256'] == package.CORRECTED_SOURCE_SHA
    original_module = Path(control['sourceModule']).resolve(strict=True)
    assert package.manifest(original_module) == control['originalFiles']
    protected += [original_module / name for name in control['originalFiles']]
    protected.append(original_module / 'RELEASE-SHA256SUMS')
    before = {str(p): support.digest(p) for p in protected}
    write(root / 'protected-before.json', before)
    class_comparison = package.audit(baseline_module, candidate_module)
    write(root / 'baseline-control.json', control)
    write(root / 'environment.json', {'host': platform.platform(), 'cpuCount': os.cpu_count(),
        'python': sys.version, 'pairs': args.pairs, 'installations': {k: str(v) for k, v in installations.items()},
        'helperSha256': support.digest(helper), 'corpusSha256': support.digest(corpus / 'corpus.json'),
        'classComparison': class_comparison,
        'baselineControlReceiptSha256': support.digest(args.baseline_control_receipt),
        'measurementBoundary': 'Fresh PowerShell/wrapper/JVM jobs; all descendant CPU and peak commitment. '
            'Launcher CPU excluded; 10ms membership polling included in wall time. '
            'Peak commitment is NOT Linux RSS. Import, validation, profiling and Linux GDB replay separate. '
            'Alternating AB/BA pairs on a hosted runner; caches and other host load uncontrolled.'})
    def run(case, name, command, timeout=3900, env=None):
        invocation = [str(helper), str(timeout * 1000), str(case / (name + '.metrics.json')),
            str(case / (name + '.log')), str(case / (name + '.stderr')), *map(str, command)]
        write(case / (name + '.command.json'), invocation)
        completed = subprocess.run(invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout + 20, env=env)
        (case / (name + '.helper.stdout')).write_bytes(completed.stdout)
        (case / (name + '.helper.stderr')).write_bytes(completed.stderr)
        row = json.loads((case / (name + '.metrics.json')).read_text())
        assert completed.returncode == 0 and row['reason'] == 'completed', (name, row)
        assert row['cleanupComplete'] and row['activeProcesses'] == 0 and row['windowsError'] == 0, row
        return row
    summaries = []
    for workload in metadata['workloads']:
        case = root / workload['name']
        case.mkdir()
        binary = corpus / workload['binary']
        project = case / 'project'
        project.mkdir()
        candidate = installations['candidate']
        module = candidate / 'Ghidra/Extensions/GhidraDwarfForge'
        script = case / 'import.ps1'
        # Literal arguments through a file avoid a second PowerShell/cmd parser.
        command = [candidate / 'support/analyzeHeadless.bat', project, workload['program'],
            '-import', binary, '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '3600', '-max-cpu', '4']
        script.write_text("$ErrorActionPreference = 'Stop'\n& " + ' '.join(map(literal, command)) +
            "\nexit $LASTEXITCODE\n", encoding='utf-8')
        imported = run(case, 'import', [shell, '-NoProfile', '-NonInteractive', '-File', script])
        assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text(encoding='utf-8')
        imported['runtime'] = support.verify_headless(case / 'import.log', module)
        project_before = {str(p.relative_to(project)).replace('\\', '/'): support.digest(p)
            for p in project.rglob('*') if p.is_file()}
        write(case / 'project-before.json', project_before)
        output = case / (binary.name + '.dbg')
        selected_report = case / 'candidate-first.report.json'
        samples, first_hashes, first_semantics, first_reports = [], {}, None, {}
        first_sources = {}
        source_comparison = None
        dwarf_result = None
        exports = [(pair, variant, False) for pair in range(args.pairs)
            for variant in (('baseline', 'candidate') if pair % 2 == 0 else ('candidate', 'baseline'))]
        exports.append((args.pairs, 'candidate', True))
        for pair, variant, profiled in exports:
            name = 'profile' if profiled else f'{pair}-{variant}'
            print(workload['name'] + ' ' + name, flush=True)
            ghidra = installations[variant]
            module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
            command = [shell, '-NoProfile', '-NonInteractive', '-File',
                module / 'support/ghidra-dwarf-forge-headless.ps1', '-GhidraDirectory', ghidra,
                '-ProjectDirectory', project, '-ProjectName', workload['program'], '-Program', binary.name,
                '-OriginalElf', binary, '-Output', output]
            environment = os.environ.copy()
            assert not environment.get('JAVA_TOOL_OPTIONS'), 'uncontrolled JVM options'
            if profiled:
                environment['JAVA_TOOL_OPTIONS'] = '-Xlog:jfr+startup=off -XX:StartFlightRecording=filename=' + \
                    str(case / 'export.jfr') + ',settings=profile,dumponexit=true'
            sample = run(case, name, command, env=environment)
            sample['runtime'] = support.verify_headless(case / (name + '.log'), module, exported=True)
            bodies = [line.split('GhidraDwarfForge report: ', 1)[1]
                for line in (case / (name + '.log')).read_text(encoding='utf-8').splitlines()
                if 'GhidraDwarfForge report: {' in line]
            body, = bodies
            report, end = json.JSONDecoder().raw_decode(body)
            assert body[end:].strip() == '(GhidraScript)'
            raw_report = body[:end].encode('utf-8')
            report_sha = hashlib.sha256(raw_report).hexdigest()
            assert report_sha == first_reports.setdefault(variant, report_sha), 'report bytes changed'
            assert report['schemaVersion'] == (1 if variant == 'baseline' else 2)
            if variant == 'candidate':
                assert report['coverage']['definitionVersion'] == 2
                assert len(raw_report) <= 64 * 1024 * 1024
                if not selected_report.exists():
                    selected_report.write_bytes(raw_report)
            else:
                assert 'coverage' not in report
            assert report['failure'] is None
            assert report['counts']['functionsExported'] >= (1000 if workload['name'] == 'sqlite' else 5000)
            if workload['name'] == 'sqlite':
                assert not report['failedFunctions']
            else:
                assert {'name': 'main', 'reason': 'THUNK'} in report['skippedFunctions']
            report_path = case / (name + '.report.json.gz')
            with gzip.open(report_path, 'wb') as stream:
                stream.write(raw_report)
            with gzip.open(report_path, 'rb') as stream:
                assert hashlib.file_digest(stream, 'sha256').hexdigest() == report_sha
            hashes = [support.digest(Path(str(output) + suffix)) for suffix in ('', '.c')]
            semantics = {key: report[key] for key in ('status', 'counts', 'failedFunctions', 'skippedFunctions')}
            if first_semantics is None:
                first_semantics = semantics
            assert semantics == first_semantics, 'paired/profile semantics changed'
            assert hashes == first_hashes.setdefault(variant, hashes), 'variant/profile output changed'
            if variant not in first_sources:
                first_sources[variant] = Path(str(output) + '.c').read_bytes()
                (case / (variant + '-first.dbg.c')).write_bytes(first_sources[variant])
                shutil.copyfile(output, case / (variant + '-first.dbg'))
            if len(first_hashes) == 2:
                if dwarf_result is None:
                    dwarf_result = dwarf_comparison.compare(case / 'baseline-first.dbg',
                        case / 'candidate-first.dbg', Path(str(output) + '.c'),
                        case / 'dwarf-comparison')
                source_comparison = catalog.compare(first_sources['baseline'], first_sources['candidate'])
                write(case / 'source-comparison.json', source_comparison)
            sample.update(pair=pair, variant=variant, artifactSha256=hashes,
                reportSha256=report_sha, reportUtf8Bytes=len(raw_report))
            if profiled:
                write(case / 'profile.metrics.json', sample)
            else:
                samples.append(sample)
                write(case / 'samples.json', samples)
        jfr = Path(os.environ['JAVA_HOME']) / 'bin/jfr.exe'
        run(case, 'phases', [jfr, 'print', '--json', '--events', 'ghidradwarfforge.ExportPhase', case / 'export.jfr'], timeout=120)
        run(case, 'phase-summary', [sys.executable, SOURCE / 'jfr-phases.py',
            case / 'phases.log', case / 'phase-summary.json'], timeout=120)
        validation = {}
        for name, command in [('llvm', [shutil.which('llvm-dwarfdump'), '--verify', output]),
                ('baseline-strict', [sys.executable, SOURCE.parent / 'integration/check-dwarfdump.py',
                    case / 'baseline-first.dbg', case / 'baseline-strict-checks.log', '--original', binary,
                    '--configuration', args.checker_configuration.resolve(strict=True)]),
                ('baseline-readelf', [shutil.which('readelf'), '-h', '-SW', '-n',
                    *['--debug-dump=' + view for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')],
                    case / 'baseline-first.dbg']),
                ('strict', [sys.executable, SOURCE.parent / 'integration/check-dwarfdump.py', output,
                    case / 'strict-checks.log', '--original', binary,
                    '--configuration', args.checker_configuration.resolve(strict=True)]),
                *[(view, [shutil.which('readelf'), '--debug-dump=' + view, output])
                    for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc')],
                ('identity', [shutil.which('readelf'), '-h', '-SW', '-n', binary, output])]:
            assert command[0] is not None, name
            validation[name] = run(case, name, command, timeout=600)
            support.require_clean(case / (name + '.log'))
        assert 'No errors.' in (case / 'llvm.log').read_text()
        cli = {}
        for name, options in [('summary', ['-Summary']),
                ('comparison', ['-BeforeFile', selected_report])]:
            cli[name] = run(case, 'coverage-cli-' + name, [shell, '-NoProfile', '-NonInteractive',
                '-File', candidate_module / 'support/ghidra-dwarf-forge-report.ps1',
                '-GhidraDirectory', candidate, '-ExtensionDirectory', candidate_module,
                '-ReportFile', selected_report, *options], timeout=600)
            text = (case / ('coverage-cli-' + name + '.log')).read_text(encoding='utf-8')
            assert not (case / ('coverage-cli-' + name + '.stderr')).read_text(encoding='utf-8').strip()
            assert ('Reported changes: 0;' if name == 'comparison' else 'not execution coverage') in text
        assert support.digest(selected_report) == first_reports['candidate'], 'CLI changed selected report'
        project_after = {str(p.relative_to(project)).replace('\\', '/'): support.digest(p)
            for p in project.rglob('*') if p.is_file()}
        write(case / 'project-after.json', project_after)
        changes = [key for key in sorted(project_before.keys() | project_after.keys())
            if project_before.get(key) != project_after.get(key)]
        assert set(changes) <= {workload['program'] + '.rep/idata/~index.bak',
            workload['program'] + '.rep/idata/~journal.bak'}, changes
        summary = {'status': 'WINDOWS_EXPORT_VALIDATED_GDB_PENDING', 'workload': workload,
            'sourceDirectory': str(case), 'sidecar': output.name, 'import': imported,
            'samples': samples, 'artifactSha256': first_hashes['candidate'],
            'artifactSha256ByVariant': first_hashes, 'sourceComparison': source_comparison,
            'dwarfComparison': dwarf_result, 'semantics': first_semantics,
            'mediansSeconds': {variant: statistics.median(s['elapsedSeconds'] for s in samples
                if s['variant'] == variant) for variant in installations},
            'validation': validation, 'strict': json.loads((case / 'strict-checks.log.check.json').read_text()),
            'coverageCli': cli, 'reportSha256': first_reports,
            'phases': json.loads((case / 'phase-summary.json').read_text()), 'projectBackupChanges': changes}
        write(case / 'summary.json', summary)
        summaries.append(summary)
    after = {str(p): support.digest(p) for p in protected}
    write(root / 'protected-after.json', after)
    assert before == after
    write(root / 'summary.json', {'status': 'WINDOWS_EXPORT_VALIDATED_GDB_PENDING',
        'workloads': summaries, 'protectedUnchanged': True})
    print('windows-workloads=EXPORT_VALIDATED_GDB_PENDING ' + str(root), flush=True)


if __name__ == '__main__':
    main()

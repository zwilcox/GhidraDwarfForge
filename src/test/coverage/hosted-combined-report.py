#!/usr/bin/env python3
"""Verify one CI cohort, union its Java probes, and enforce the accepted coverage targets."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('combined_report', HERE / 'combined-report.py')
combined = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(combined)
changed = combined.module('changed_code', HERE / 'changed-code.py')
files = combined.javaexec
REQUIRED = {
    'linux': ('target-preflight', {'headless', 'native-java'}, {
        'gdb-companion', 'source-relocation', 'derived-validation', 'build-id-installation',
        'instruction-context', 'source-context', 'annotation-inventory', 'equate-evidence',
        'annotation-export', 'failed-source-export', 'class-scopes', 'inheritance-producer',
        'inheritance-names', 'build-id-command', 'cfi-encoder', 'cfi-composition-explicit',
        'cfi-composition-plain', 'cfi-composition-gabi', 'cfi-composition-gnu',
        'linux-attachment-exec', 'linux-attachment-pie', 'linux-attachment-exec-no-build-id',
        'gui-script-manager', 'gui-script-manager-loader', 'gui-script-manager-compressed',
        'gui-script-manager-unwind'}),
    'linux_host': ('extension-build', {'native-java'}, {
        'linux-file-metadata', 'linux-directory-sync', 'linux-metadata-visibility'}),
    'firmware': ('cortex-m-profile', {'headless'}, {'raw-firmware'}),
    'windows': ('windows-host', {'windows'}, {
        'windows-attachment', 'windows-build-id-installation', 'windows-host-primitives'}),
}


def tools_classpath(bundle):
    metadata = files.read(bundle / 'tools.json')
    libraries = metadata.get('files', {})
    if (metadata.get('schema') != 1 or metadata.get('jacocoVersion') != '0.8.16'
            or not isinstance(libraries, dict) or not 0 < len(libraries) <= 16):
        raise ValueError('invalid JaCoCo report dependency manifest')
    files.exact_files(bundle / 'tools', libraries)
    paths, size = [], 0
    for name, digest in sorted(libraries.items()):
        if not re.fullmatch(r'[A-Za-z0-9_.-]+\.jar', name) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('invalid report dependency name or digest')
        path = files.regular(bundle / 'tools' / name, 16 * 1024 * 1024)
        size += path.stat().st_size
        if size > 64 * 1024 * 1024 or files.digest(path) != digest:
            raise ValueError('changed or excessive report dependencies')
        paths.append(str(path.resolve()))
    return os.pathsep.join(paths)


def attachment_oracle(record, oracle):
    expected_role = record['suite'].removeprefix('linux-attachment-').replace('-no-build-id', '.no-build-id')
    if (oracle.get('host') != 'production Linux ext4 host' or oracle.get('target') != 'x86_64'
            or expected_role not in ('exec', 'pie', 'exec.no-build-id') or oracle.get('role') != expected_role
            or oracle.get('entryPoint') != 'AttachmentHelper'
            or oracle.get('validator') != 'production-live' or oracle.get('runtime') is not True):
        raise ValueError('hosted attachment coverage requires the real privileged host and debugger oracle')
    expected_cases = sorted(mode + '-' + boundary for mode in ('initial', 'refresh')
        for boundary in ('PREPARED', 'TARGET_REPLACED', 'BEFORE_COMMIT', 'COMMITTED')) if expected_role == 'exec' else []
    children = oracle.get('unmeasuredNestedChildren')
    halts = record.get('unmeasuredForcedHalts', [])
    if (not isinstance(children, list) or len(children) != len(expected_cases)
            or any(not isinstance(row, dict) or row.get('crashExit') != 89
                   or row.get('recoveryHelperMeasured') is not False for row in children)
            or sorted(row.get('case', '') for row in children) != expected_cases
            or sorted(row['label'] for row in halts) != expected_cases
            or any(row['exitCode'] != 89 for row in halts)):
        raise ValueError('hosted attachment coverage must disclose unmeasured recovery children')


def gui_oracle(record, oracle):
    suffix = record['suite'].removeprefix('gui-script-manager')
    mode = suffix.removeprefix('-') if suffix else 'default'
    required = {'installed-unwind-chooser=PASS', 'choices=7', 'exports=4', 'cancellations=3'} if mode == 'unwind' else {
        'script-manager-export-selection=PASS', 'script-manager-export-cancellation=PASS',
        'script-manager-structural-validation=PASS', 'script-manager-gdb=PASS'}
    if (mode not in ('default', 'loader', 'compressed', 'unwind')
            or oracle.get('status') != 'PASS_INTERACTIVE_GUI_MEASUREMENT' or oracle.get('mode') != mode
            or oracle.get('mainJvmSessions') != 1 or len(record['sessions']) != 1
            or oracle.get('desktop') != 'owned Xvfb and Openbox; actual Swing interactions'
            or not required.issubset(oracle.get('outcome', {}).get('requiredChecks', []))
            or oracle.get('unmeasuredNestedJvmKinds') != ['geometry calibration', 'report CLI', 'attachment helper']):
        raise ValueError('hosted GUI measurement requires actual interactive completion and nested-process disclosure')


def load_job(root, jar, kind, commit, run):
    job, expected_layers, expected_suites = REQUIRED[kind]
    files.exact_files(root, {'collections', 'report'})
    summary = files.read(root / 'report/summary.json')
    if (summary.get('schema') != 1 or summary.get('status') != 'PASS' or summary.get('fixtureOnly')
            or summary.get('commit') != commit or summary.get('productionJarSha256') != files.digest(jar)
            or summary.get('cohort') != {'commit': commit, 'run': run, 'job': job}
            or set(summary.get('layers', {})) != expected_layers):
        raise ValueError('missing or mismatched CI integration cohort: ' + kind)
    rows, suites, known, unmeasured = [], set(), set(), []
    for layer, measured in sorted(summary['layers'].items()):
        xml = files.regular(root / 'report' / (layer + '.xml'), 32 * 1024 * 1024)
        if files.digest(xml) != measured.get('xmlSha256'):
            raise ValueError('CI integration layer report changed')
        layer_rows, layer_suites, layer_halts = [], set(), []
        receipts = measured.get('receipts', {})
        if not isinstance(receipts, dict) or not 0 < len(receipts) <= 1000:
            raise ValueError('invalid CI integration collection inventory')
        for name, digest in sorted(receipts.items()):
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', name) or name in known:
                raise ValueError('invalid or duplicate CI integration collection')
            known.add(name)
            directory = root / 'collections' / name
            if directory.is_symlink() or files.digest(files.regular(directory / 'receipt.json', 1024 * 1024)) != digest:
                raise ValueError('CI integration receipt changed')
            record = combined.integration.validate_collection(directory, jar)
            if (record['layer'] != layer or record['host'] != ('nt' if kind == 'windows' else 'posix')
                    or record['productionClasses'] != measured['productionClasses']):
                raise ValueError('integration execution host, layer or class population mismatch')
            if record['suite'] == 'linux-metadata-visibility':
                oracle = files.read(directory / 'oracle.json')
                if oracle.get('privileged') != 'PASS' or oracle.get('unprivileged') != 'PASS':
                    raise ValueError('hosted visibility coverage requires both real privilege modes')
            if record['suite'].startswith('linux-attachment-'):
                attachment_oracle(record, files.read(directory / 'oracle.json'))
            if record['suite'].startswith('gui-script-manager'):
                gui_oracle(record, files.read(directory / 'oracle.json'))
            layer_suites.add(record['suite'])
            layer_rows.extend((layer, row['session'], directory / row['file']) for row in record['sessions'])
            layer_halts.extend({'suite': record['suite'], **row} for row in record.get('unmeasuredForcedHalts', []))
        if (len(layer_rows) != measured.get('sessions') or sorted(layer_suites) != measured.get('suites')
                or layer_halts != measured.get('unmeasuredForcedHalts', [])):
            raise ValueError('CI integration report omits or changes recorded sessions')
        rows.extend(layer_rows)
        suites.update(layer_suites)
        unmeasured.extend(layer_halts)
    files.exact_files(root / 'collections', known)
    if suites != expected_suites:
        raise ValueError('missing or unexpected required CI integration suite: ' + kind)
    return rows, {'kind': kind, 'commit': commit, 'run': run, 'job': job,
        'summarySha256': files.digest(root / 'report/summary.json'),
        'receipts': {name: files.digest(root / 'collections' / name / 'receipt.json') for name in sorted(known)},
        'sessions': len(rows), 'suites': sorted(suites), 'unmeasuredForcedHalts': unmeasured}


def targets_met(summary):
    metrics = list(summary['overall'].values())
    for group in ('binaryAndLocationCorrectness', 'fileTransactionsAndValidation'):
        metrics.extend(summary['groups'][group]['metrics'].values())
    return all(value['targetMet'] is True for value in metrics)


def report(args):
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit) or not re.fullmatch(r'[1-9][0-9]*', args.run_id):
        raise ValueError('invalid CI coverage cohort')
    files.exact_files(args.bundle, {'production.jar', 'collection', 'tools', 'tools.json'})
    jar = files.regular(args.bundle / 'production.jar', 64 * 1024 * 1024).resolve()
    args.javaexec = args.bundle / 'collection'
    manifest = files.validate_collection(args.javaexec, jar, files.read(args.expected_tasks), args.commit, args.run_id)
    rows = [('javaexec', row['session'], args.javaexec / 'execution' / (row['task'] + '.exec'))
        for row in manifest['sessions']]
    origins = [{'kind': 'javaexec', 'commit': args.commit, 'run': args.run_id, 'job': 'extension-build',
        'manifestSha256': files.digest(args.javaexec / 'manifest.json'), 'sessions': len(rows)}]
    for kind in REQUIRED:
        executions, origin = load_job(getattr(args, kind), jar, kind, args.commit, args.run_id)
        rows.extend(executions)
        origins.append(origin)
    classpath = tools_classpath(args.bundle)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='combined-report-', dir=args.output.parent) as temporary:
        args.jacoco_classpath = Path(temporary) / 'classpath.txt'
        args.jacoco_classpath.write_text(classpath)
        result = combined.write_combined(args, jar, rows, origins,
            cohort={'commit': args.commit, 'run': args.run_id})
    result['changedCode'] = changed.report(args.sources.resolve().parents[2], args.base_commit,
        args.commit, args.output / 'xml/combined.xml', files.read(args.inventory)['targets']['changedCode'])
    result['targetsMet'] = targets_met(result) and result['changedCode']['targetsMet']
    files.save(args.output / 'summary.json', result)
    renderer = combined.module('combined_public_report', HERE.parents[2] / 'support/combined-coverage-report.py')
    renderer.generate(args.output, args.output / 'public', args.inventory, args.sources,
        args.repository, args.commit, int(args.run_id))
    # Preserve diagnostics when targets fail. An unmet goal is never a passing gate.
    print(json.dumps({'status': 'COVERAGE_TARGETS_MET' if result['targetsMet'] else 'COVERAGE_TARGETS_UNMET'}))
    return 0 if result['targetsMet'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'expected-tasks', 'linux', 'linux-host', 'firmware', 'windows',
            'inventory', 'sources', 'java', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--base-commit', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--repository', required=True)
    raise SystemExit(report(parser.parse_args()))


if __name__ == '__main__':
    main()

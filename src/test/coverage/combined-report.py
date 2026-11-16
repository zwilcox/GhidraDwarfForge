#!/usr/bin/env python3
"""Build a local combined baseline from verified JavaExec and hosted integration data.

The inputs keep their actual commit/run origins. This does not publish a badge or
substitute a local baseline for the required same-run hosted acceptance gate.
"""
import argparse
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


javaexec = module('javaexec_collection', HERE / 'javaexec-coverage.py')
integration = module('integration_collection', HERE.parent / 'integration/integration_coverage.py')
REQUIRED = {
    'linux': ('target-preflight (x86_64)', {'gdb-companion', 'source-relocation', 'derived-validation',
        'build-id-installation', 'instruction-context', 'source-context', 'annotation-inventory',
        'equate-evidence', 'annotation-export', 'failed-source-export'}),
    'windows': ('windows-host', {'windows-attachment', 'windows-build-id-installation', 'windows-host-primitives'}),
    'firmware': ('cortex-m-profile', {'raw-firmware'}),
}


def load_integration(root, jar, kind):
    receipt = javaexec.read(root / 'verified.json')
    summary = javaexec.read(root / 'download/report/summary.json')
    job, required_suites = REQUIRED[kind]
    if (receipt.get('status') != 'PASS_PROVISIONAL_INTEGRATION_MEASUREMENT_ONLY'
            or receipt.get('job') != job or not isinstance(receipt.get('run'), int)
            or receipt['run'] <= 0 or not isinstance(receipt.get('artifactId'), int)
            or not re.fullmatch(r'sha256:[0-9a-f]{64}', receipt.get('artifactSha256', ''))
            or receipt.get('head') != receipt.get('sourceCommit')
            or not re.fullmatch(r'[0-9a-f]{40}', receipt.get('sourceCommit', ''))
            or summary.get('status') != 'PASS' or summary.get('commit') != receipt['sourceCommit']
            or summary.get('productionJarSha256') != javaexec.digest(jar)
            or receipt.get('productionJarSha256') != summary['productionJarSha256']):
        raise ValueError('integration input lacks matching verified provenance: ' + kind)
    collections = root / 'download/collections'
    expected = {}
    for layer, value in summary['layers'].items():
        if layer not in ('headless', 'native-java', 'windows'):
            raise ValueError('unknown integration report layer')
        if javaexec.digest(root / 'download/report' / (layer + '.xml')) != value['xmlSha256']:
            raise ValueError('integration report XML changed')
        if any(receipt['layers'][layer].get(key) != value[key]
                for key in ('sessions', 'suites', 'productionClasses', 'counters')):
            raise ValueError('verified integration counters changed')
        if set(expected) & set(value['receipts']):
            raise ValueError('duplicate integration collection')
        expected.update({name: (layer, digest) for name, digest in value['receipts'].items()})
    javaexec.exact_files(collections, expected)
    rows, suites, halts = [], set(), []
    for name, (layer, digest) in sorted(expected.items()):
        if not re.fullmatch(r'[A-Za-z0-9_-]+', name):
            raise ValueError('invalid integration collection name')
        folder = collections / name
        if javaexec.digest(folder / 'receipt.json') != digest:
            raise ValueError('integration collection receipt changed')
        record = integration.validate_collection(folder, jar)
        if record['layer'] != layer or (layer == 'windows') != (kind == 'windows'):
            raise ValueError('integration layer differs from its verified job')
        if layer == 'windows' and record['host'] != 'nt':
            raise ValueError('Windows measurement did not execute on Windows')
        suites.add(record['suite'])
        rows.extend((layer, item['session'], folder / item['file']) for item in record['sessions'])
        halts.extend({'suite': record['suite'], **item} for item in record.get('unmeasuredForcedHalts', []))
    if suites != required_suites:
        raise ValueError('missing or unexpected required integration suite: ' + kind)
    origin = {'kind': kind, 'commit': receipt['sourceCommit'], 'run': receipt['run'],
        'job': job, 'artifactId': receipt['artifactId'], 'artifactSha256': receipt['artifactSha256'],
        'verifiedReceiptSha256': javaexec.digest(root / 'verified.json'),
        'summarySha256': javaexec.digest(root / 'download/report/summary.json'),
        'sessions': len(rows), 'suites': sorted(suites), 'unmeasuredForcedHalts': halts}
    return rows, origin


def load_local(manifest, jar, repository):
    """Admit explicitly local measurements without giving them hosted provenance."""
    value = javaexec.read(manifest)
    directory = value.get('directory', '')
    receipts = value.get('receipts', {})
    harnesses = value.get('harnessSha256', {})
    snapshot = value.get('harnessSnapshotCommit')
    if (value.get('schema') != 1 or value.get('kind') != 'local-integration'
            or not re.fullmatch(r'[0-9a-f]{40}', value.get('checkoutCommit', ''))
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', value.get('run', ''))
            or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', directory)
            or not isinstance(receipts, dict) or not 0 < len(receipts) <= 100
            or not isinstance(harnesses, dict) or not 0 < len(harnesses) <= 1000):
        raise ValueError('invalid local integration manifest')
    if snapshot is not None and not re.fullmatch(r'[0-9a-f]{40}', snapshot):
        raise ValueError('invalid harness snapshot commit')
    for name, expected in harnesses.items():
        path = Path(name)
        if (path.is_absolute() or '..' in path.parts or path.as_posix() != name
                or not re.fullmatch(r'[0-9a-f]{64}', expected)):
            raise ValueError('local measurement harness changed or has an invalid path')
        if snapshot is None:
            actual = javaexec.digest(repository / path)
        else:
            # A committed snapshot may capture the previously measured worktree.
            # Its bytes must match every recorded hash; this is not a claim that
            # the tests ran with that commit checked out or that newer oracles ran.
            result = subprocess.run(['git', '--no-replace-objects', 'cat-file', 'blob', snapshot + ':' + name],
                cwd=repository, capture_output=True, timeout=10)
            if result.returncode or len(result.stdout) > 1024 * 1024:
                raise ValueError('unavailable or excessive harness snapshot')
            actual = hashlib.sha256(result.stdout).hexdigest()
        if actual != expected:
            raise ValueError('local measurement harness changed or has an invalid path')
    collections = manifest.parent / directory
    javaexec.exact_files(collections, receipts)
    rows, suites = [], set()
    for name, expected in sorted(receipts.items()):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', name):
            raise ValueError('invalid local collection name')
        folder = collections / name
        if javaexec.digest(folder / 'receipt.json') != expected:
            raise ValueError('local collection receipt changed')
        record = integration.validate_collection(folder, jar)
        if record['layer'] == 'windows' and record['host'] != 'nt':
            raise ValueError('Windows measurement did not execute on Windows')
        suites.add(record['suite'])
        rows.extend((record['layer'], row['session'], folder / row['file']) for row in record['sessions'])
    return rows, {'kind': 'local-integration', 'checkoutCommit': value['checkoutCommit'],
        'harnessSnapshotCommit': snapshot,
        'run': value['run'], 'harnessSha256': harnesses, 'manifestSha256': javaexec.digest(manifest),
        'sessions': len(rows), 'suites': sorted(suites), 'hostedAcceptance': False}


def counters(node):
    result = {metric: {'covered': 0, 'missed': 0} for metric in ('LINE', 'BRANCH')}
    seen = set()
    for row in node.findall('counter'):
        metric = row.get('type')
        if metric not in result:
            continue
        if metric in seen:
            raise ValueError('duplicate coverage counter')
        seen.add(metric)
        values = [row.get(key, '') for key in ('covered', 'missed')]
        if any(not re.fullmatch(r'0|[1-9][0-9]{0,9}', value) for value in values):
            raise ValueError('invalid coverage counter')
        result[metric] = dict(zip(('covered', 'missed'), map(int, values)))
    return result


def add(values):
    result = {metric: {'covered': 0, 'missed': 0} for metric in ('LINE', 'BRANCH')}
    for value in values:
        for metric in result:
            for key in result[metric]:
                result[metric][key] += value[metric][key]
    return result


def assessed(values, target):
    result = {}
    for metric, counter in values.items():
        total = sum(counter.values())
        threshold = None if target is None else target[metric.lower()]
        percent = None if not total else str((Decimal(counter['covered']) * 100 / total)
            .quantize(Decimal('0.1'), rounding=ROUND_HALF_UP))
        result[metric] = {**counter, 'percent': percent, 'target': threshold,
            'targetMet': None if not total or threshold is None else counter['covered'] * 100 >= total * threshold}
    return result


def inventory(path, sources):
    value = javaexec.read(path)
    groups = value.get('groups', {})
    if value.get('schema') != 1 or set(groups) != {
            'binaryAndLocationCorrectness', 'fileTransactionsAndValidation', 'remainingProduction'}:
        raise ValueError('invalid critical source inventory')
    names = [name for group in groups.values() for name in group]
    if len(names) != len(set(names)) or set(names) != sources:
        raise ValueError('critical inventory must classify every production source exactly once')
    if (value['targets']['overall'] != {'line': 85, 'branch': 80}
            or value['targets']['eachCriticalGroup'] != {'line': 95, 'branch': 90}):
        raise ValueError('coverage targets differ from the accepted milestone')
    return value


def report(args):
    jar = args.jar.resolve(strict=True)
    expected = javaexec.read(args.expected_tasks)
    tasks = javaexec.validate_collection(args.javaexec, jar, expected, args.commit, args.run_id)
    rows = [('javaexec', row['session'], args.javaexec / 'execution' / (row['task'] + '.exec'))
        for row in tasks['sessions']]
    origins = [{'kind': 'javaexec', 'commit': tasks['commit'], 'run': tasks['run'],
        'manifestSha256': javaexec.digest(args.javaexec / 'manifest.json'), 'sessions': len(rows)}]
    inputs = {'linux': args.linux, 'windows': args.windows, 'firmware': args.firmware}
    for kind, root in inputs.items():
        executions, origin = load_integration(root, jar, kind)
        rows.extend(executions)
        origins.append(origin)
    for manifest in args.local_measurement:
        executions, origin = load_local(manifest, jar, args.sources.resolve().parents[2])
        rows.extend(executions)
        origins.append(origin)
    return write_combined(args, jar, rows, origins)


def write_combined(args, jar, rows, origins, *, cohort=None):
    # Classify the complete source inventory before exposing any combined counters.
    source_names = {path.relative_to(args.sources).as_posix() for path in args.sources.rglob('*.java')}
    classification = inventory(args.inventory, source_names)
    args.output.mkdir(parents=True, exist_ok=False)
    summary = {'schema': 1, 'status': 'INCOMPLETE',
        'scope': 'Local combined Java baseline' if cohort is None else 'Combined Java from one CI commit and run',
        'hostedAcceptance': False, 'origins': origins, 'productionJarSha256': javaexec.digest(jar),
        'inventorySha256': javaexec.digest(args.inventory), 'nativeCMeasured': False}
    if cohort is not None:
        summary['cohort'] = cohort
    javaexec.save(args.output / 'summary.json', summary)
    manifest = args.output / 'sessions.tsv'
    lines, hashes = [], {}
    for layer, session, path in rows:
        fields = (layer, session, str(path.resolve(strict=True)))
        if any(any(character in field for character in '\t\r\n') for field in fields):
            raise ValueError('invalid session manifest field')
        if fields[2] in hashes:
            raise ValueError('duplicate execution path')
        hashes[fields[2]] = javaexec.digest(path)
        lines.append('\t'.join(fields) + '\n')
    manifest.write_text(''.join(lines))
    command = [str(args.java), '-cp', args.jacoco_classpath.read_text().strip(),
        str(HERE / 'ReportCombinedCoverage.java'), str(jar), str(args.javaexec / 'test-classes.jar'),
        str(manifest), str(args.sources), str(args.output / 'xml')]
    with (args.output / 'verification.log').open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
    if (javaexec.digest(jar) != summary['productionJarSha256']
            or any(javaexec.digest(path) != digest for path, digest in hashes.items())):
        raise ValueError('execution data changed while reporting')
    layers = {}
    population = None
    for layer in ('javaexec', 'headless', 'native-java', 'windows', 'combined'):
        xml = args.output / 'xml' / (layer + '.xml')
        document = ET.parse(xml).getroot()
        sources = {package.get('name') + '/' + source.get('name'): counters(source)
            for package in document.findall('package') for source in package.findall('sourcefile')}
        if set(sources) != source_names or add(sources.values()) != counters(document):
            raise ValueError('report does not retain the full production source denominator')
        counts = {name: {metric: sum(value.values()) for metric, value in item.items()}
            for name, item in sources.items()}
        if population is not None and counts != population:
            raise ValueError('coverage populations differ between layers')
        population = counts
        layers[layer] = {'counters': counters(document), 'sources': sources,
            'productionClasses': len(document.findall('./package/class')), 'xmlSha256': javaexec.digest(xml)}
    groups = {}
    for group, names in classification['groups'].items():
        target = None if group == 'remainingProduction' else classification['targets']['eachCriticalGroup']
        groups[group] = {'sources': len(names),
            'metrics': assessed(add(layers['combined']['sources'][name] for name in names), target)}
    summary.update(status='LOCAL_BASELINE' if cohort is None else 'VERIFIED_HOSTED_MEASUREMENT',
        sessions=len(rows), layers=layers, groups=groups,
        overall=assessed(layers['combined']['counters'], classification['targets']['overall']))
    javaexec.save(args.output / 'summary.json', summary)
    print(json.dumps({key: summary[key] for key in ('status', 'hostedAcceptance', 'sessions', 'overall', 'groups')}))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('jar', 'javaexec', 'expected-tasks', 'linux', 'windows', 'firmware',
            'inventory', 'sources', 'java', 'jacoco-classpath', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--local-measurement', type=Path, action='append', default=[],
        help='Optional local integration manifest binding raw collections and harness hashes')
    parser.add_argument('--local-baseline', action='store_true', required=True,
        help='Acknowledge mixed run origins; this command does not establish hosted acceptance')
    report(parser.parse_args())


if __name__ == '__main__':
    main()

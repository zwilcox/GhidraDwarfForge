#!/usr/bin/env python3
"""Report verified integration JVMs by layer, without altering the JavaExec badge."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('integration_coverage',
    HERE.parent / 'integration/integration_coverage.py')
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


def report(args):
    jar = args.jar.resolve(strict=True)
    root = args.collections.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipts = sorted(root.glob('*/receipt.json'))
    if not receipts or {p.parent for p in receipts} != set(root.iterdir()):
        raise ValueError('missing or unexpected integration coverage collection')
    groups = {}
    suites = set()
    for receipt in receipts:
        record = coverage.validate_collection(receipt.parent, jar)
        if record['layer'] not in ('native-java', 'headless', 'windows'):
            raise ValueError('unknown integration layer')
        if record['layer'] == 'windows' and record['host'] != 'nt':
            raise ValueError('Windows coverage must execute on Windows')
        suites.add(record['suite'])
        groups.setdefault(record['layer'], []).append((receipt.parent, record))
    if not set(args.require_suite) <= suites:
        raise ValueError('required integration coverage suite did not run: ' +
            repr(sorted(set(args.require_suite) - suites)))
    classpath = args.jacoco_classpath.read_text().strip()
    summary = {'schema': 1, 'status': 'INCOMPLETE', 'commit': args.commit,
        'scope': 'Integration Java by layer; separate from JavaExec coverage and native C',
        'productionJarSha256': coverage.digest(jar), 'layers': {}}
    run, job = os.environ.get('GITHUB_RUN_ID'), os.environ.get('GITHUB_JOB')
    if args.fixture_report:
        summary['fixtureOnly'] = True
    elif run is not None or job is not None:
        if (os.environ.get('GITHUB_ACTIONS') != 'true' or not re.fullmatch(r'[1-9][0-9]*', run or '')
                or not re.fullmatch(r'[A-Za-z0-9_-]+', job or '') or not re.fullmatch(r'[0-9a-f]{40}', args.commit)):
            raise ValueError('incomplete CI integration provenance')
        summary['cohort'] = {'commit': args.commit, 'run': run, 'job': job}
    coverage.save(output / 'summary.json', summary)
    for layer, collections in sorted(groups.items()):
        manifest = output / (layer + '-sessions.txt')
        executions = [directory / row['file'] for directory, record in collections
            for row in record['sessions']]
        manifest.write_text(''.join(str(path) + '\n' for path in executions))
        xml = output / (layer + '.xml')
        command = [str(args.java), '-cp', classpath, str(HERE / 'ReportIntegrationCoverage.java'),
            str(jar), str(manifest), str(args.sources.resolve()), str(xml), layer]
        with (output / (layer + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        document = ET.parse(xml).getroot()
        counters = {row.attrib['type']: {'covered': int(row.attrib['covered']),
            'missed': int(row.attrib['missed'])} for row in document.findall('counter')}
        sources = {}
        for package in document.findall('package'):
            for source in package.findall('sourcefile'):
                sources[package.attrib['name'] + '/' + source.attrib['name']] = {
                    row.attrib['type']: {'covered': int(row.attrib['covered']), 'missed': int(row.attrib['missed'])}
                    for row in source.findall('counter') if row.attrib['type'] in ('LINE', 'BRANCH')}
        summary['layers'][layer] = {'sessions': len(executions),
            'suites': sorted({record['suite'] for _, record in collections}),
            'unmeasuredForcedHalts': [{'suite': record['suite'], **row}
                for _, record in collections for row in record.get('unmeasuredForcedHalts', [])],
            'productionClasses': len(document.findall('.//class')), 'counters': counters,
            'sources': sources, 'xmlSha256': coverage.digest(xml),
            'receipts': {directory.name: coverage.digest(directory / 'receipt.json')
                for directory, _ in collections}}
    summary['status'] = 'PASS'
    coverage.save(output / 'summary.json', summary)
    lines = ['# Integration Java coverage', '',
        'These measurements retain every production class and keep execution layers separate. '
        'They are not added to the JavaExec badge; percentages cannot be added across layers. '
        'Native C and uninstrumented child processes are not measured.', '',
        'Production JAR SHA-256: `' + summary['productionJarSha256'] + '`.', '',
        'A passing report verifies collection integrity and the recorded harness oracles. '
        'It does not replace the complete CI gate or establish coverage of every behavior.', '']
    for layer, value in summary['layers'].items():
        lines.extend(['## ' + layer, '',
            f'{value["sessions"]} measured JVM sessions; {value["productionClasses"]} production classes. '
            f'{len(value["unmeasuredForcedHalts"])} explicitly unmeasured halt controls. '
            'See each oracle receipt for additional unmeasured nested processes.', '',
            'Suites: ' + ', '.join('`' + name + '`' for name in value['suites']) + '.', '',
            '| Source | Covered / total lines | Covered / total branches |',
            '| --- | ---: | ---: |'])
        for source, counters in sorted(value['sources'].items()):
            cells = []
            for metric in ('LINE', 'BRANCH'):
                counter = counters.get(metric, {'covered': 0, 'missed': 0})
                total = counter['covered'] + counter['missed']
                cells.append(f'{counter["covered"]} / {total}' if total else 'not applicable')
            lines.append('| ' + source + ' | ' + ' | '.join(cells) + ' |')
        lines.append('')
    (output / 'README.md').write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({'status': 'PASS', 'layers': {name: value['counters']
        for name, value in summary['layers'].items()}}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('jar', 'collections', 'output', 'java', 'jacoco-classpath', 'sources'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--require-suite', action='append', required=True)
    parser.add_argument('--fixture-report', action='store_true',
        help='Synthetic reporter controls only; never accepted as hosted measurements')
    report(parser.parse_args())


if __name__ == '__main__':
    main()

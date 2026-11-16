#!/usr/bin/env python3
"""Render verified Java probe-union measurements without changing the legacy badge."""
import argparse
import hashlib
import html
import importlib.util
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('combined_policy', ROOT / 'src/test/coverage/combined-report.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
changed = policy.module('changed_publication', ROOT / 'src/test/coverage/changed-code.py')
LAYERS = ('combined', 'javaexec', 'headless', 'native-java', 'windows')
LABELS = {'combined': 'Combined Java', 'javaexec': 'JavaExec', 'headless': 'Headless Ghidra',
    'native-java': 'Native-Java integration', 'windows': 'Windows Java'}
PUBLIC_FILES = ('README.md', 'summary.json', 'lines.svg', 'branches.svg', 'uncovered-decisions.json',
    *(layer + '.md' for layer in LAYERS))


def read_xml(path):
    payload = policy.javaexec.regular(path, 32 * 1024 * 1024).read_bytes()
    if b'<!ENTITY' in payload:
        raise ValueError('entity declarations are not coverage data')
    root = ET.fromstring(payload)
    if root.tag != 'report':
        raise ValueError('not a JaCoCo report')
    sources, decisions = {}, {}
    for package in root.findall('package'):
        name = package.get('name', '')
        if not re.fullmatch(r'ghidradwarfforge(?:/[A-Za-z_][A-Za-z0-9_]*)*', name):
            raise ValueError('invalid measured production package')
        for source in package.findall('sourcefile'):
            filename = source.get('name', '')
            key = name + '/' + filename
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]*\.java', filename) or key in sources:
                raise ValueError('invalid or duplicate measured source')
            sources[key] = policy.counters(source)
            rows, seen = [], set()
            line_counts = {'LINE': {'covered': 0, 'missed': 0}, 'BRANCH': {'covered': 0, 'missed': 0}}
            for row in source.findall('line'):
                fields = [row.get(field, '') for field in ('nr', 'mi', 'ci', 'mb', 'cb')]
                if any(not re.fullmatch(r'0|[1-9][0-9]{0,9}', value) for value in fields):
                    raise ValueError('invalid measured line counters')
                number, mi, ci, mb, cb = map(int, fields)
                if number == 0 or number in seen or (mi + ci == 0 and mb + cb):
                    raise ValueError('duplicate or inconsistent measured line')
                seen.add(number)
                if mi + ci:
                    line_counts['LINE']['covered' if ci else 'missed'] += 1
                line_counts['BRANCH']['covered'] += cb
                line_counts['BRANCH']['missed'] += mb
                if (mi and not ci) or mb:
                    rows.append({'line': number, 'lineCovered': ci > 0,
                        'coveredBranches': cb, 'missedBranches': mb})
            if line_counts != sources[key]:
                raise ValueError('source counters do not match measured line decisions')
            decisions[key] = sorted(rows, key=lambda row: row['line'])
    counters = policy.counters(root)
    if not sources or policy.add(sources.values()) != counters:
        raise ValueError('source counters do not account for measured population')
    return {'counters': counters, 'sources': sources,
        'productionClasses': len(root.findall('./package/class')),
        'xmlSha256': hashlib.sha256(payload).hexdigest()}, decisions


def verify(directory, inventory, sources, repository, commit, run_id, local_preview=False):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or not re.fullmatch(r'[0-9a-f]{40}', commit) or not isinstance(run_id, int) or run_id <= 0):
        raise ValueError('invalid combined report provenance')
    record = json.loads(policy.javaexec.regular(directory / 'summary.json', 4 * 1024 * 1024).read_text())
    names = {path.relative_to(sources).as_posix() for path in sources.rglob('*.java')}
    classification = policy.inventory(inventory, names)
    expected_status = 'LOCAL_BASELINE' if local_preview else 'VERIFIED_HOSTED_MEASUREMENT'
    if (record.get('schema') != 1 or record.get('status') != expected_status or record.get('fixtureOnly')
            or record.get('inventorySha256') != policy.javaexec.digest(inventory)
            or not re.fullmatch(r'[0-9a-f]{64}', record.get('productionJarSha256', ''))
            or record.get('nativeCMeasured') is not False or set(record.get('layers', {})) != set(LAYERS)):
        raise ValueError('invalid or differently scoped combined measurement')
    if not local_preview:
        cohort = {'commit': commit, 'run': str(run_id)}
        if record.get('cohort') != cohort:
            raise ValueError('combined measurement does not belong to this CI run')
        origins = record.get('origins', [])
        expected = {'javaexec', 'linux', 'linux_host', 'windows', 'firmware'}
        if (len(origins) != len(expected) or {origin.get('kind') for origin in origins} != expected
                or any(origin.get('commit') != commit or origin.get('run') != str(run_id) for origin in origins)
                or sum(origin.get('sessions', 0) for origin in origins) != record.get('sessions')):
            raise ValueError('combined measurement has mixed or incomplete origins')
    layers, populations, decisions = {}, [], None
    for layer in LAYERS:
        measured, gaps = read_xml(directory / 'xml' / (layer + '.xml'))
        if measured != record['layers'][layer] or set(measured['sources']) != names:
            raise ValueError('combined counters, XML, or source population changed: ' + layer)
        layers[layer] = measured
        populations.append(({name: {metric: sum(values.values()) for metric, values in counters.items()}
            for name, counters in measured['sources'].items()}, measured['productionClasses']))
        if layer == 'combined':
            decisions = gaps
    if not populations[0][1] or any(population != populations[0] for population in populations[1:]):
        raise ValueError('execution layers have different production denominators')
    overall = policy.assessed(layers['combined']['counters'], classification['targets']['overall'])
    groups = {}
    for group, members in classification['groups'].items():
        target = None if group == 'remainingProduction' else classification['targets']['eachCriticalGroup']
        groups[group] = {'sources': len(members), 'metrics': policy.assessed(
            policy.add(layers['combined']['sources'][name] for name in members), target)}
    if record.get('overall') != overall or record.get('groups') != groups:
        raise ValueError('combined target assessment changed')
    code = None
    if not local_preview:
        declared = record.get('changedCode', {})
        code = changed.report(sources.resolve().parents[2], declared.get('baseCommit', ''), commit,
            directory / 'xml/combined.xml', classification['targets']['changedCode'])
        if code != declared:
            raise ValueError('changed-code measurement does not match source history and XML')
    applicable = list(overall.values())
    for group in ('binaryAndLocationCorrectness', 'fileTransactionsAndValidation'):
        applicable.extend(groups[group]['metrics'].values())
    targets_met = all(value['targetMet'] is True for value in applicable) and code is not None and code['targetsMet']
    if not local_preview and record.get('targetsMet') != targets_met:
        raise ValueError('combined target gate result changed')
    result = {'schema': 1, 'scope': 'Combined Java probe union with the complete production denominator',
        'measurement': 'LOCAL_PREVIEW' if local_preview else 'SINGLE_CI_RUN',
        'publicationEligible': not local_preview and targets_met, 'repository': repository, 'commit': commit,
        'runId': None if local_preview else run_id, 'sessions': record['sessions'],
        'productionJarSha256': record['productionJarSha256'], 'inventorySha256': record['inventorySha256'],
        'origins': record['origins'], 'layers': layers, 'overall': overall, 'groups': groups,
        'changedCode': code, 'targetsMet': targets_met, 'nativeCMeasured': False}
    gaps = {'schema': 1, 'productionJarSha256': result['productionJarSha256'],
        'xmlSha256': layers['combined']['xmlSha256'],
        'meaning': 'Unexecuted lines or decision outcomes in this measurement. This alone does not establish missing tests or missing assertions. JaCoCo excludes exception-handler edges.',
        'groups': {group: {name: decisions[name] for name in sorted(members) if decisions[name]}
            for group, members in classification['groups'].items()}}
    return result, gaps


def display(value):
    if value['percent'] is None:
        return 'not applicable'
    return f'{value["percent"]}% ({value["covered"]:,}/{value["covered"] + value["missed"]:,})'


def badge(label, value, threshold_met):
    text = 'n/a' if value is None else value + '%'
    color = '#4c1' if threshold_met else '#dfb317'
    title = html.escape(label + ': ' + text)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="230" height="20" role="img" aria-label="{title}">
<title>{title}</title><rect width="170" height="20" fill="#555"/><rect x="170" width="60" height="20" fill="{color}"/>
<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
<text x="85" y="14">{html.escape(label)}</text><text x="200" y="14">{text}</text></g></svg>
'''


def generate(directory, output, inventory, sources, repository, commit, run_id, local_preview=False):
    result, gaps = verify(directory, inventory, sources, repository, commit, run_id, local_preview)
    output.mkdir(parents=True, exist_ok=False)
    policy.javaexec.save(output / 'summary.json', result)
    policy.javaexec.save(output / 'uncovered-decisions.json', gaps)
    for name, metric in (('lines', 'LINE'), ('branches', 'BRANCH')):
        value = result['overall'][metric]
        label = ('Local Java ' if local_preview else 'Combined Java ') + name
        (output / (name + '.svg')).write_text(badge(label, value['percent'], value['targetMet']), encoding='utf-8')
    lines = ['# Combined Java coverage', '',
        '**Local preview; mixed measurement origins; not eligible for publication.**' if local_preview else
        f'Single-run measurement for [{commit}](https://github.com/{repository}/commit/{commit}); [CI run {run_id}](https://github.com/{repository}/actions/runs/{run_id}).', '',
        'This unions matching JaCoCo execution probes. It does not add or average percentages. Every production Java class remains in each denominator, including GUI/framework code and classes that were never loaded. Native C/libdwarf, Python, shell and external libraries are outside this Java metric.', '',
        f'{result["sessions"]} measured JVM sessions; {result["layers"]["combined"]["productionClasses"]} production classes; {len(result["layers"]["combined"]["sources"])} source files.', '',
        '| Measurement | Lines | Branches |', '| --- | ---: | ---: |']
    for layer in LAYERS:
        measured = policy.assessed(result['layers'][layer]['counters'], None)
        lines.append(f'| [{LABELS[layer]}]({layer}.md) | {display(measured["LINE"])} | {display(measured["BRANCH"])} |')
        page = ['# ' + LABELS[layer] + ' coverage', '',
            'Complete production denominator; this execution layer overlaps other layers. See [combined coverage](README.md) for scope and provenance.', '',
            '| Source | Lines | Branches |', '| --- | ---: | ---: |']
        for name, counters in sorted(result['layers'][layer]['sources'].items()):
            measured = policy.assessed(counters, None)
            url = f'https://github.com/{repository}/blob/{commit}/src/main/java/{name}'
            page.append(f'| [{name}]({url}) | {display(measured["LINE"])} | {display(measured["BRANCH"])} |')
        (output / (layer + '.md')).write_text('\n'.join(page) + '\n', encoding='utf-8')
    lines += ['', '## Accepted targets', '', '| Scope | Lines | Branches |', '| --- | ---: | ---: |']
    for name, metrics in [('Overall', result['overall']), *[(name, group['metrics'])
            for name, group in result['groups'].items() if name != 'remainingProduction']]:
        cells = [display(metrics[key]) + ' / target ' + str(metrics[key]['target']) + '%' for key in ('LINE', 'BRANCH')]
        lines.append('| ' + name + ' | ' + ' | '.join(cells) + ' |')
    lines += ['', '**All accepted coverage targets met: ' + ('yes' if result['targetsMet'] else 'no') + '.**', '',
        'See [uncovered decisions](uncovered-decisions.json) for source-line gaps grouped by responsibility. A missed outcome alone does not prove a missing test or assertion. JaCoCo branch counters exclude exception handling; failure, cancellation and recovery assertions require separate review.', '',
        'Headless execution does not establish interactive GUI behavior. Independent validators, debugger assertions, unchanged inputs, deterministic output and actual host/GUI checks remain required.', '',
        'Intentional forced-halt tests and uninstrumented nested JVMs may have behavioral evidence without measured probes. The retained origins in summary.json disclose forced-halt controls; these are not counted as covered executions.', '',
        'The existing JavaExec badge retains its original scope. Reports on the publication branch are written only after the protected main validation gate; PR artifacts remain provisional.', '',
        'Production JAR SHA-256: `' + result['productionJarSha256'] + '`.', '']
    if result['changedCode'] is not None:
        code = result['changedCode']
        lines += ['## Changed executable Java', '',
            f'Compared with `{code["baseCommit"]}`: {code["status"]}.', '',
            'Lines: ' + display(code['LINE']) + '; branches: ' + display(code['BRANCH']) + '.', '',
            'Targets: 90% lines, 85% branches minimum, 90% branches preferred. No executable changes are reported as not applicable, never as 100%.', '']
    (output / 'README.md').write_text('\n'.join(lines), encoding='utf-8')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('directory', 'output', 'inventory', 'sources'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--local-preview', action='store_true')
    args = vars(parser.parse_args())
    result = generate(**args)
    print(json.dumps({key: result[key] for key in ('measurement', 'publicationEligible', 'overall')}))


if __name__ == '__main__':
    main()

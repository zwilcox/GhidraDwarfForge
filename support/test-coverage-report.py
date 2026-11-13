#!/usr/bin/env python3
"""Convert a JaCoCo report into a measured badge and a commit-linked coverage report."""
import argparse
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import html
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

SCOPE = 'Production Java line coverage from extension-build JavaExec tests'
LIMIT = 32 * 1024 * 1024


def counter(node, allow_empty=False):
    values = node.findall("counter[@type='LINE']")
    if allow_empty and not values and len(node) == 0:
        return (0, 0)
    if len(values) != 1:
        raise ValueError('expected exactly one LINE counter')
    value = values[0]
    fields = [value.get(name, '') for name in ('covered', 'missed')]
    if any(not re.fullmatch(r'0|[1-9][0-9]{0,9}', text) for text in fields):
        raise ValueError('invalid line counter')
    return tuple(map(int, fields))


def percentage(covered, missed):
    if covered + missed == 0:
        return None
    return str((Decimal(100) * covered / (covered + missed)).quantize(Decimal('0.1'), rounding=ROUND_HALF_UP))


def generate(xml_path, tasks_directory, output, repository, commit, run_id):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[0-9a-f]{40}', commit) or run_id <= 0:
        raise ValueError('invalid report provenance')
    if xml_path.stat().st_size > LIMIT:
        raise ValueError('coverage XML exceeds 32 MiB')
    payload = xml_path.read_bytes()
    if b'<!ENTITY' in payload:
        raise ValueError('entity declarations are not coverage data')
    root = ET.fromstring(payload)
    if root.tag != 'report':
        raise ValueError('not a JaCoCo report')
    covered, missed = counter(root)
    if covered + missed == 0:
        raise ValueError('no measured source population; coverage is unavailable')
    tasks = []
    for path in sorted(tasks_directory.glob('*.json')):
        record = json.loads(path.read_text())
        if set(record) != {'task', 'complete'} or record['complete'] is not True or record['task'] != path.stem or not re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', path.stem):
            raise ValueError('incomplete or invalid instrumented task record')
        tasks.append(path.stem)
    if not tasks:
        raise ValueError('no completed instrumented tests')
    rows = []
    total_covered = total_missed = 0
    seen = set()
    for package in root.findall('package'):
        name = package.get('name', '')
        if not re.fullmatch(r'ghidradwarfforge(?:/[A-Za-z_][A-Za-z0-9_]*)*', name) or name in seen:
            raise ValueError('unexpected or duplicate production package')
        seen.add(name)
        pc, pm = counter(package)
        total_covered += pc
        total_missed += pm
        source_covered = source_missed = 0
        source_names = set()
        for source in package.findall('sourcefile'):
            filename = source.get('name', '')
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]*\.java', filename) or filename in source_names:
                raise ValueError('invalid source filename')
            source_names.add(filename)
            sc, sm = counter(source, allow_empty=True)
            source_covered += sc
            source_missed += sm
            rows.append({'source': name + '/' + filename, 'covered': sc, 'missed': sm, 'percent': percentage(sc, sm)})
        if (source_covered, source_missed) != (pc, pm):
            raise ValueError('source counters do not account for the package population')
    if (total_covered, total_missed) != (covered, missed) or not rows:
        raise ValueError('package counters do not account for the report population')
    percent = percentage(covered, missed)
    summary = {'schema': 1, 'scope': SCOPE, 'repository': repository, 'commit': commit, 'runId': run_id,
        'metric': 'LINE', 'covered': covered, 'missed': missed, 'percent': percent,
        'jacocoVersion': '0.8.16', 'xmlSha256': hashlib.sha256(payload).hexdigest(),
        'tasks': tasks, 'sources': sorted(rows, key=lambda row: row['source'])}
    output.mkdir(parents=True, exist_ok=True)
    (output / 'summary.json').write_text(json.dumps(summary, indent=4) + '\n')
    label, value = 'Java test coverage', percent + '%'
    color = '#4c1' if Decimal(percent) >= 80 else '#dfb317' if Decimal(percent) >= 50 else '#e05d44'
    title = html.escape(label + ': ' + value)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="206" height="20" role="img" aria-label="{title}">
<title>{title}</title><rect width="146" height="20" fill="#555"/><rect x="146" width="60" height="20" fill="{color}"/>
<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
<text x="73" y="14">{label}</text><text x="176" y="14">{value}</text></g></svg>
'''
    (output / 'test-coverage.svg').write_text(svg)
    run_url = f'https://github.com/{repository}/actions/runs/{run_id}'
    lines = ['# Java test code coverage', '', f'**{percent}% line coverage** — {covered:,} covered / {covered + missed:,} total production Java lines.', '',
        f'Source: [{commit}](https://github.com/{repository}/commit/{commit}). [CI run and downloadable JaCoCo HTML report]({run_url}).', '',
        'This measures Java code exercised by the instrumented `JavaExec` tests in the Linux extension-build job. All compiled `src/main/java` classes are in the denominator, including unexecuted classes. It is separate from exported source/type/variable evidence coverage.', '',
        'Native C/libdwarf, Python/shell tests, Ghidra scripts, external libraries, and independently launched headless/integration JVMs are not instrumented. Their Java entry points remain in the denominator when they belong to `src/main/java`. JaCoCo applies its standard generated-bytecode filters. The published report branch holds the last fully validated main result; artifacts from other runs are provisional measurements.', '',
        f'JaCoCo 0.8.16; XML SHA-256: `{summary["xmlSha256"]}`.', '', '## Measured source files', '',
        '| Source | Covered | Missed | Line coverage |', '| --- | ---: | ---: | ---: |']
    for row in summary['sources']:
        url = f'https://github.com/{repository}/blob/{commit}/src/main/java/{row["source"]}'
        value = row['percent'] + '%' if row['percent'] is not None else 'not applicable'
        lines.append(f'| [{row["source"]}]({url}) | {row["covered"]} | {row["missed"]} | {value} |')
    lines += ['', '## Instrumented test tasks', '', *['- `' + task + '`' for task in tasks], '']
    (output / 'README.md').write_text('\n'.join(lines))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--xml', type=Path, required=True)
    parser.add_argument('--tasks', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    args = parser.parse_args()
    result = generate(args.xml, args.tasks, args.output, args.repository, args.commit, args.run_id)
    print('test-code-coverage=' + result['percent'] + '% tasks=' + str(len(result['tasks'])))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Summarize one complete Forge export from `jfr print --json` phase events."""

import argparse
from datetime import datetime
from decimal import Decimal
import json
from pathlib import Path
import re

PHASES = {'export', 'decompilation-and-source', 'types-and-storage',
    'native-production', 'elf-packaging'}


def duration_ns(value):
    match = re.fullmatch(r'PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?', value)
    if not match or not any(match.groups()):
        raise ValueError('invalid JFR duration: ' + value)
    hours, minutes, seconds = (Decimal(part or '0') for part in match.groups())
    nanos = (hours * 3600 + minutes * 60 + seconds) * 1_000_000_000
    if nanos != int(nanos):
        raise ValueError('duration exceeds nanosecond precision')
    return int(nanos)


def instant_ns(value):
    match = re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?(Z|[+-]\d\d:\d\d)', value)
    if not match:
        raise ValueError('invalid JFR instant: ' + value)
    whole, fraction, offset = match.groups()
    seconds = int(datetime.fromisoformat(whole + offset.replace('Z', '+00:00')).timestamp())
    return seconds * 1_000_000_000 + int((fraction or '').ljust(9, '0'))


def summarize(recording):
    rows = {}
    threads = set()
    for event in recording['recording']['events']:
        if event['type'] != 'ghidradwarfforge.ExportPhase':
            continue
        values = event['values']
        phase = values['phase']
        if phase not in PHASES or phase in rows or values['completed'] is not True:
            raise ValueError('unknown, duplicate or incomplete export phase: ' + phase)
        start = instant_ns(values['startTime'])
        duration = duration_ns(values['duration'])
        rows[phase] = {'startNanoseconds': start, 'durationNanoseconds': duration}
        threads.add(values['eventThread']['javaThreadId'])
    if rows.keys() != PHASES or len(threads) != 1:
        raise ValueError('expected one complete export on one thread')
    outer = rows['export']
    end = outer['startNanoseconds'] + outer['durationNanoseconds']
    previous_end = outer['startNanoseconds']
    children = sorted((row for phase, row in rows.items() if phase != 'export'),
        key=lambda row: row['startNanoseconds'])
    for row in children:
        child_end = row['startNanoseconds'] + row['durationNanoseconds']
        if row['startNanoseconds'] < previous_end or child_end > end:
            raise ValueError('overlapping phases or phase outside export')
        previous_end = child_end
    return {'schemaVersion': 1, 'status': 'PASS',
        'phases': {phase: {**row, 'elapsedSeconds': row['durationNanoseconds'] / 1e9}
            for phase, row in sorted(rows.items())},
        'unattributedExportSeconds': (outer['durationNanoseconds'] -
            sum(row['durationNanoseconds'] for row in children)) / 1e9,
        'scope': 'One profiled export; elapsed wall time including waits, not CPU. '
            'Outer export includes child phases. Startup/project opening are outside export. '
            'Native production includes Java DIE construction, JNA/native work and section materialization.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('jfr_json', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = summarize(json.loads(args.jfr_json.read_text()))
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=4)
        stream.write('\n')


if __name__ == '__main__':
    main()

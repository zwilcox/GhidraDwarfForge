#!/usr/bin/env python3
"""Summarize complete successful CI attempts without treating wall time as billing."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() is None:
        raise ValueError('CI timestamps require a timezone')
    return result


def seconds(start, end):
    duration = (timestamp(end) - timestamp(start)).total_seconds()
    if duration < 0:
        raise ValueError('negative job/step duration')
    return duration


def summarize(run, page, inventory, *, attempt):
    if run.get('status') != 'completed' or run.get('conclusion') != 'success':
        raise ValueError('timing comparisons require a successful complete run')
    jobs = page.get('jobs')
    if (not isinstance(jobs, list) or not jobs or len(jobs) != page.get('total_count')
            or len({job['id'] for job in jobs}) != len(jobs)
            or len({job['name'] for job in jobs}) != len(jobs)):
        raise ValueError('missing, truncated or duplicate job inventory')
    setup = {row['name'] for row in inventory['steps'] if row['kind'] == 'setup'}
    required_targets = set(inventory['targets'])
    observed_targets = set()
    rows = []
    skipped = []
    for job in jobs:
        if (job.get('run_id') != run['id'] or job.get('head_sha') != run['head_sha']
                or job.get('run_attempt') != attempt or job.get('status') != 'completed'):
            raise ValueError('job belongs to another or unsuccessful attempt')
        name = job['name']
        if (name == 'publish-test-coverage' and run['event'] == 'pull_request'
                and job.get('conclusion') == 'skipped'):
            skipped.append(name)
            continue
        if job.get('conclusion') != 'success':
            raise ValueError('job belongs to another or unsuccessful attempt')
        target_match = re.fullmatch(r'target-preflight \(([^)]+)\)', name)
        group_match = re.fullmatch(r'target-integration \(([^,]+), ([^)]+)\)', name)
        target = target_match.group(1) if target_match else group_match.group(1) if group_match else None
        if target:
            if target not in required_targets:
                raise ValueError('unknown target lane')
            observed_targets.add(target)
        elapsed = seconds(job['started_at'], job['completed_at'])
        step_rows = []
        for step in job['steps']:
            if step['conclusion'] == 'skipped':
                continue
            if step['status'] != 'completed' or step['conclusion'] != 'success':
                raise ValueError('failed step inside nominally successful job')
            duration = seconds(step['started_at'], step['completed_at'])
            step_name = re.sub(r'^\[target-[0-9]{3}\] ', '', step['name'])
            # API prefixes unnamed actions with Run; named setup steps are exact.
            normalized_name = step_name.removeprefix('Run ')
            step_rows.append({'name': step_name, 'seconds': duration,
                'setup': bool(target and normalized_name in setup)})
        rows.append({'job': name, 'id': job['id'], 'target': target,
            'group': group_match.group(2) if group_match else None,
            'seconds': elapsed,
            'setupSeconds': sum(step['seconds'] for step in step_rows if step['setup']),
            'steps': step_rows})
    if observed_targets != required_targets:
        raise ValueError('successful workflow omits a required architecture')
    completed = [job for job in jobs if job['conclusion'] == 'success']
    first = min(completed, key=lambda job: timestamp(job['started_at']))['started_at']
    last = max(completed, key=lambda job: timestamp(job['completed_at']))['completed_at']
    architectures = {}
    for target in sorted(required_targets):
        selected = [job for job in jobs if job['name'].startswith('target-preflight (' + target + ')')
            or job['name'].startswith('target-integration (' + target + ', ')]
        started = min(selected, key=lambda job: timestamp(job['started_at']))['started_at']
        completed = max(selected, key=lambda job: timestamp(job['completed_at']))['completed_at']
        architectures[target] = {'elapsedSeconds': seconds(started, completed),
            'jobWallSeconds': sum(row['seconds'] for row in rows if row['target'] == target),
            'setupSeconds': sum(row['setupSeconds'] for row in rows if row['target'] == target)}
    return {'schema': 1, 'status': 'SUCCESSFUL_ATTEMPT_TIMING',
        'run': run['id'], 'attempt': attempt, 'commit': run['head_sha'],
        'event': run['event'], 'url': run['html_url'],
        'workflowWallSeconds': seconds(first, last),
        'jobWallSeconds': sum(row['seconds'] for row in rows),
        'architectures': architectures, 'jobs': rows, 'expectedSkippedJobs': skipped,
        'limitations': ['Job wall seconds are not GitHub billed minutes.',
            'Workflow wall time spans first job start to last job completion in this attempt; earlier failed attempts are excluded.',
            'Setup includes named target toolchain, debugger/emulator, artifact, Java, Ghidra and coverage preparation steps; nested downloads inside test commands remain test time.',
            'Grouped timing does not prove group completeness; require integration-plan admission separately.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--jobs', type=Path, required=True)
    parser.add_argument('--attempt', type=int, required=True)
    parser.add_argument('--inventory', type=Path, default=Path('support/ci/integration-groups.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = summarize(json.loads(args.run.read_text()), json.loads(args.jobs.read_text()),
        json.loads(args.inventory.read_text()), attempt=args.attempt)
    result['inputSha256'] = {name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in [('run', args.run), ('jobs', args.jobs), ('inventory', args.inventory)]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=4) + '\n')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Admit the current attempt's complete architecture group execution from GitHub."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import urllib.request


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('integration_plan', HERE / 'integration-plan.py')
plan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(plan)


def all_jobs(request, base):
    rows, expected = [], None
    for page in range(1, 11):
        result = request(base + '?per_page=100&page=' + str(page))
        total = result.get('total_count')
        batch = result.get('jobs')
        if (type(total) is not int or not 0 < total <= 1000 or not isinstance(batch, list)
                or not 0 < len(batch) <= 100 or (expected is not None and total != expected)):
            raise ValueError('incomplete or changing CI job inventory')
        expected = total
        rows.extend(batch)
        if len(rows) >= total:
            if len(rows) != total or len({row['id'] for row in rows}) != total:
                raise ValueError('duplicate or excessive CI job inventory')
            return rows
    raise ValueError('CI job inventory exceeds pagination bound')


def verify(request, repository, inventory, commit, head_commit, run, attempt):
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository)
            or not re.fullmatch(r'[0-9a-f]{40}', commit)
            or not re.fullmatch(r'[0-9a-f]{40}', head_commit) or run <= 0 or attempt <= 0):
        raise ValueError('invalid grouped CI request identity')
    base = 'https://api.github.com/repos/' + repository + '/actions/runs/' + str(run)
    metadata = request(base)
    if (metadata.get('id') != run or metadata.get('head_sha') != head_commit
            or metadata.get('run_attempt') != attempt or metadata.get('path') != '.github/workflows/ci.yml'):
        raise ValueError('stale or mismatched grouped CI run')
    jobs = all_jobs(request, base + '/attempts/' + str(attempt) + '/jobs')
    result = plan.verify_jobs(inventory, jobs, commit=commit, head_commit=head_commit, run=run, attempt=attempt)
    result['repository'] = repository
    return result


def api(url):
    request = urllib.request.Request(url, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = response.read(16 * 1024 * 1024 + 1)
    if len(payload) > 16 * 1024 * 1024:
        raise ValueError('excessive GitHub API response')
    return json.loads(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, default=HERE / 'integration-groups.json')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(api, os.environ['GITHUB_REPOSITORY'], json.loads(args.inventory.read_text()),
        os.environ['GITHUB_SHA'], os.environ['SOURCE_HEAD_COMMIT'],
        int(os.environ['GITHUB_RUN_ID']), int(os.environ['GITHUB_RUN_ATTEMPT']))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=4) + '\n')
    print('Complete integration group execution: PASS')


if __name__ == '__main__':
    main()

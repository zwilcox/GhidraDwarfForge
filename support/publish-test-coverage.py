#!/usr/bin/env python3
"""Publish validated main coverage with a normal commit on a dedicated report branch."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

BRANCH = 'reports/test-coverage'


def api(endpoint, method='GET', payload=None, missing=False):
    argv = ['gh', 'api', '--method', method, endpoint]
    if payload is not None:
        argv += ['--input', '-']
    result = subprocess.run(argv, input=None if payload is None else json.dumps(payload), text=True, capture_output=True)
    if result.returncode:
        if missing and '(HTTP 404)' in result.stderr:
            return None
        raise RuntimeError('GitHub coverage publication request failed: ' + result.stderr.strip())
    return json.loads(result.stdout)


def publish(directory, repository, commit, run_id, request=api, dry_run=False):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or not re.fullmatch(r'[0-9a-f]{40}', commit) or run_id <= 0:
        raise ValueError('invalid publication provenance')
    public = directory / 'public'
    summary = json.loads((public / 'summary.json').read_text())
    if summary.get('schema') != 1 or summary.get('repository') != repository or summary.get('commit') != commit or summary.get('runId') != run_id:
        raise ValueError('coverage report does not belong to this validated run')
    if summary.get('xmlSha256') != hashlib.sha256((directory / 'coverage.xml').read_bytes()).hexdigest():
        raise ValueError('coverage report XML hash changed')
    files = {}
    for name in ('README.md', 'summary.json', 'test-coverage.svg'):
        path = public / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError('invalid or excessive public coverage file')
        files[name] = path.read_text()
    # Recompute the badge and detailed report; a matching XML hash alone does
    # not prove that the summary percentage or rendered SVG came from that XML.
    spec = importlib.util.spec_from_file_location('coverage_report', Path(__file__).with_name('test-coverage-report.py'))
    renderer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(renderer)
    with tempfile.TemporaryDirectory(prefix='forge-coverage-verify-') as temporary:
        generated = Path(temporary)
        renderer.generate(directory / 'coverage.xml', directory / 'tasks', generated, repository, commit, run_id)
        if any((generated / name).read_text() != value for name, value in files.items()):
            raise ValueError('public coverage files do not match the measured XML and test population')
    if dry_run:
        return {'status': 'PREPARED_ONLY', 'branch': BRANCH, 'commit': commit, 'files': sorted(files)}
    if os.environ.get('GITHUB_REF') != 'refs/heads/main':
        raise ValueError('coverage publication is restricted to main')
    base = 'repos/' + repository
    current = request(base + '/git/ref/heads/main')
    if current['object']['sha'] != commit:
        return {'status': 'SKIPPED_SUPERSEDED_MAIN', 'commit': commit}
    prior = request(base + '/git/ref/heads/' + BRANCH, missing=True)
    tree = {'tree': [{'path': name, 'mode': '100644', 'type': 'blob', 'content': text} for name, text in files.items()]}
    parents = []
    if prior:
        parent = prior['object']['sha']
        parents.append(parent)
        tree['base_tree'] = request(base + '/git/commits/' + parent)['tree']['sha']
    created_tree = request(base + '/git/trees', method='POST', payload=tree)
    created_commit = request(base + '/git/commits', method='POST', payload={
        'message': f'Test code coverage for {commit}\n\nValidated CI run {run_id}.',
        'tree': created_tree['sha'], 'parents': parents})
    if prior:
        request(base + '/git/refs/heads/' + BRANCH, method='PATCH', payload={'sha': created_commit['sha'], 'force': False})
    else:
        request(base + '/git/refs', method='POST', payload={'ref': 'refs/heads/' + BRANCH, 'sha': created_commit['sha']})
    return {'status': 'PUBLISHED', 'branch': BRANCH, 'commit': created_commit['sha'], 'sourceCommit': commit}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run-id', type=int, required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    print(json.dumps(publish(args.directory, args.repository, args.commit, args.run_id, dry_run=args.dry_run), sort_keys=True))


if __name__ == '__main__':
    main()

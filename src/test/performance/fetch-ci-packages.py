#!/usr/bin/env python3
"""Fetch digest-bound packages/checkers from the sole production CI workflow."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import zipfile


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', path], timeout=60))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate_sha')
    parser.add_argument('baseline_sha')
    parser.add_argument('output', type=Path)
    parser.add_argument('--repository', default='zwilcox/GhidraDwarfForge')
    args = parser.parse_args()
    assert re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository)
    assert all(re.fullmatch('[0-9a-f]{40}', sha) for sha in (args.candidate_sha, args.baseline_sha))
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    prefix = 'repos/' + args.repository + '/actions/'
    roles = [('candidate', args.candidate_sha, 'ghidra-dwarf-forge-extension'),
        ('checker-windows', args.candidate_sha, 'dwarfdump-windows-validation'),
        ('checker-linux', args.candidate_sha, 'dwarfdump-linux-validation'),
        ('baseline', args.baseline_sha, 'ghidra-dwarf-forge-extension')]
    deadline = time.monotonic() + 3600
    receipts = {}
    for role, sha, name in roles:
        while True:
            runs = api(prefix + 'workflows/ci.yml/runs?head_sha=' + sha + '&per_page=30')['workflow_runs']
            runs = [run for run in runs if run['head_sha'] == sha and
                run['head_repository']['full_name'] == args.repository]
            selected = None
            for run in runs:
                artifacts = api(prefix + 'runs/' + str(run['id']) + '/artifacts?per_page=100')['artifacts']
                matches = [item for item in artifacts if item['name'] == name and not item['expired']]
                assert len(matches) <= 1, 'ambiguous artifact within one run'
                if matches:
                    selected = (run, matches[0])
                    break
            if selected:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError('No exact-head CI artifact: ' + role + ' ' + sha)
            if runs and all(run['status'] == 'completed' for run in runs):
                raise RuntimeError('Exact-head CI finished without required artifact: ' + role)
            print('waiting for exact-head CI artifact ' + role + ' ' + sha, flush=True)
            time.sleep(30)
        run, artifact = selected
        # Publication of an artifact is not full CI acceptance; preserve both
        # identities and the observed run state for the later integration audit.
        assert artifact.get('workflow_run', {}).get('head_sha', sha) == sha
        digest = artifact['digest']
        assert re.fullmatch('sha256:[0-9a-f]{64}', digest), artifact
        archive = root / (role + '.zip')
        with archive.open('xb') as stream:
            subprocess.run(['gh', 'api', prefix + 'artifacts/' + str(artifact['id']) + '/zip'],
                stdout=stream, check=True, timeout=300)
        with archive.open('rb') as stream:
            observed = hashlib.file_digest(stream, 'sha256').hexdigest()
        assert 'sha256:' + observed == digest, 'artifact archive digest mismatch'
        target = root / role
        target.mkdir()
        with zipfile.ZipFile(archive) as packed:
            for item in packed.infolist():
                destination = (target / item.filename).resolve()
                assert destination.is_relative_to(target) and '\\' not in item.filename
                assert (item.external_attr >> 16) & 0o170000 != 0o120000, 'archive symlink'
            packed.extractall(target)
        receipts[role] = {'requestedSha': sha, 'run': run, 'artifact': artifact, 'verifiedArchiveSha256': observed}
        (root / 'receipts.json').write_text(json.dumps(receipts, indent=4) + '\n')
        print('verified ' + role + ' run=' + str(run['id']) + ' artifact=' + str(artifact['id']), flush=True)


if __name__ == '__main__':
    main()

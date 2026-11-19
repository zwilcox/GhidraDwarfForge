#!/usr/bin/env python3
"""Seal and admit complete target/group coverage inputs without averaging counters.

Receipt integrity is checked here; real probe identities and complete behavioral
profiles remain checked by the existing Java and hosted coverage validators.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


plan = module('integration_group_plan', HERE / 'integration-plan.py')
coverage = module('integration_group_collector', REPO / 'src/test/integration/integration_coverage.py')
MAX_BYTES = 256 * 1024 * 1024


def read(path, limit=4 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError('invalid grouped coverage metadata file: ' + str(path))
    return json.loads(path.read_text())


def digest(path):
    return coverage.digest(path)


def inventory_digest(inventory):
    return hashlib.sha256(json.dumps(inventory, sort_keys=True,
        separators=(',', ':')).encode()).hexdigest()


def group_names(inventory, target):
    return {row['group'] for row in plan.matrix(inventory)['include'] if row['target'] == target}


def validate_identity(identity, inventory):
    if not isinstance(identity, dict) or set(identity) != {'commit', 'run', 'attempt', 'job', 'target', 'group'}:
        raise ValueError('invalid grouped coverage identity')
    environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_JOB': identity['job'],
        'GITHUB_SHA': identity['commit'], 'GITHUB_RUN_ID': identity['run'],
        'GITHUB_RUN_ATTEMPT': str(identity['attempt']), 'FORGE_CI_TARGET': identity['target'],
        'FORGE_CI_GROUP': identity['group']}
    if (type(identity['attempt']) is not int or coverage.ci_group_identity(environment) != identity
            or identity['group'] not in group_names(inventory, identity['target'])):
        raise ValueError('unknown or invalid integration group')


def collection_files(root, jar, identity):
    """Bound and authenticate every file, including empty uninstrumented groups."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('missing grouped coverage collections')
    files, sessions, collections, size = {}, set(), {}, 0
    directories = sorted(root.iterdir())
    if len(directories) > 1000:
        raise ValueError('excessive group collection count')
    for directory in directories:
        if (directory.is_symlink() or not directory.is_dir()
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', directory.name)):
            raise ValueError('invalid collection directory')
        paths = sorted(directory.iterdir())
        for path in paths:
            if (path.is_symlink() or not path.is_file()
                    or not 0 < path.stat().st_size <= coverage.MAX_EXEC_BYTES):
                raise ValueError('invalid grouped coverage payload')
            size += path.stat().st_size
            if size > MAX_BYTES:
                raise ValueError('grouped coverage exceeds size budget')
        record = coverage.validate_collection(directory, jar)
        if record.get('ciGroup') != identity:
            raise ValueError('collection belongs to a stale or different integration group: '
                + directory.name + ' actual=' + json.dumps(record.get('ciGroup'), sort_keys=True)
                + ' expected=' + json.dumps(identity, sort_keys=True))
        expected = {'receipt.json', 'oracle.json', *(row['file'] for row in record['sessions'])}
        if {path.name for path in paths} != expected:
            raise ValueError('unexpected grouped coverage file')
        for row in record['sessions']:
            if row['session'] in sessions:
                raise ValueError('duplicate grouped coverage session')
            sessions.add(row['session'])
        collections[directory.name] = {'suite': record['suite'], 'layer': record['layer'],
            'sessions': [row['session'] for row in record['sessions']]}
        files.update({directory.name + '/' + path.name: digest(path) for path in paths})
    return {'files': files, 'collections': collections, 'sessions': sorted(sessions)}


def seal(root, jar, inventory, identity):
    validate_identity(identity, inventory)
    if root.is_symlink() or (root.exists() and {p.name for p in root.iterdir()} - {'collections'}):
        raise ValueError('group bundle is not a fresh collection root')
    (root / 'collections').mkdir(parents=True, exist_ok=True)
    payload = collection_files(root / 'collections', jar, identity)
    manifest = {'schema': 1, 'status': 'SEALED_GROUP_COLLECTIONS', 'identity': identity,
        'inventorySha256': inventory_digest(inventory), 'productionJarSha256': digest(jar), **payload}
    coverage.save(root / 'group.json', manifest)
    return manifest


def verify_manifest(manifest, inventory, jar, identity):
    validate_identity(identity, inventory)
    if (manifest.get('schema') != 1 or manifest.get('status') != 'SEALED_GROUP_COLLECTIONS'
            or manifest.get('identity') != identity
            or manifest.get('inventorySha256') != inventory_digest(inventory)
            or manifest.get('productionJarSha256') != digest(jar)
            or not isinstance(manifest.get('files'), dict) or len(manifest['files']) > 10000
            or not isinstance(manifest.get('collections'), dict) or len(manifest['collections']) > 1000
            or not isinstance(manifest.get('sessions'), list) or len(manifest['sessions']) > 10000
            or set(manifest) != {'schema', 'status', 'identity', 'inventorySha256',
                'productionJarSha256', 'files', 'collections', 'sessions'}):
        raise ValueError('missing or mismatched grouped coverage manifest')


def admit(inputs, jar, inventory, *, commit, run, attempt, target):
    expected = group_names(inventory, target)
    if not expected or inputs.is_symlink() or not inputs.is_dir():
        raise ValueError('invalid target or grouped input root')
    roots = list(inputs.iterdir())
    if len(roots) != len(expected):
        raise ValueError('missing or extra integration coverage group')
    groups, sessions, collections, paths, size = {}, set(), set(), {}, 0
    for root in roots:
        if (root.is_symlink() or not root.is_dir()
                or {p.name for p in root.iterdir()} not in ({'group.json'}, {'collections', 'group.json'})):
            raise ValueError('invalid integration group artifact layout')
        manifest = read(root / 'group.json')
        group = manifest.get('identity', {}).get('group')
        if group not in expected or group in groups:
            raise ValueError('duplicate or unexpected integration coverage group')
        identity = {'commit': commit, 'run': run, 'attempt': attempt,
            'job': 'target-integration', 'target': target, 'group': group}
        verify_manifest(manifest, inventory, jar, identity)
        collection_root = root / 'collections'
        if not collection_root.exists() and not collection_root.is_symlink():
            # File-only artifact transport may omit empty directories. Accept
            # absence only when the authenticated manifest declares no data.
            payload = {'files': {}, 'collections': {}, 'sessions': []}
        else:
            payload = collection_files(collection_root, jar, identity)
        size += sum((root / 'collections' / name).stat().st_size for name in payload['files'])
        if size > MAX_BYTES:
            raise ValueError('target coverage exceeds size budget')
        if any(manifest[key] != payload[key] for key in payload):
            raise ValueError('group payload changed after sealing')
        if sessions.intersection(payload['sessions']) or collections.intersection(payload['collections']):
            raise ValueError('duplicate session or collection across integration groups')
        sessions.update(payload['sessions'])
        collections.update(payload['collections'])
        groups[group] = manifest
        paths.update({name: root / 'collections' / name for name in payload['collections']})
    return groups, paths


def merge(inputs, output, jar, inventory, **identity):
    groups, paths = admit(inputs, jar, inventory, **identity)
    output.mkdir(parents=True, exist_ok=False)
    (output / 'collections').mkdir()
    for name, path in sorted(paths.items()):
        # Collections are small and immutable; do not copy fixtures, toolchains
        # or production JARs into every group artifact.
        shutil.copytree(path, output / 'collections' / name)
    evidence = {'schema': 1, 'status': 'COMPLETE_GROUP_COLLECTIONS', **identity,
        'inventorySha256': inventory_digest(inventory), 'productionJarSha256': digest(jar),
        'groups': groups}
    coverage.save(output / 'groups.json', evidence)
    return evidence


def verify_merged(root, jar, inventory, *, commit, run, target):
    if root.is_symlink() or (root / 'collections').is_symlink() or not (root / 'collections').is_dir():
        raise ValueError('invalid merged coverage root')
    evidence = read(root / 'groups.json')
    attempt = evidence.get('attempt')
    groups = evidence.get('groups', {})
    if (evidence.get('schema') != 1 or evidence.get('status') != 'COMPLETE_GROUP_COLLECTIONS'
            or evidence.get('commit') != commit or evidence.get('run') != run
            or evidence.get('target') != target or type(attempt) is not int or attempt <= 0
            or evidence.get('inventorySha256') != inventory_digest(inventory)
            or evidence.get('productionJarSha256') != digest(jar)
            or not isinstance(groups, dict) or set(groups) != group_names(inventory, target)):
        raise ValueError('incomplete or mismatched merged group provenance')
    known, sessions, size = set(), set(), 0
    for group, manifest in groups.items():
        identity = {'commit': commit, 'run': run, 'attempt': attempt,
            'job': 'target-integration', 'target': target, 'group': group}
        verify_manifest(manifest, inventory, jar, identity)
        recorded_sessions, recorded_files = [], {}
        for name, metadata in manifest['collections'].items():
            if name in known or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', name):
                raise ValueError('duplicate or invalid merged collection')
            known.add(name)
            directory = root / 'collections' / name
            if directory.is_symlink() or not directory.is_dir():
                raise ValueError('missing merged collection directory')
            for path in directory.iterdir():
                if path.is_symlink() or not path.is_file() or path.stat().st_size > coverage.MAX_EXEC_BYTES:
                    raise ValueError('invalid merged payload')
                size += path.stat().st_size
                if size > MAX_BYTES:
                    raise ValueError('merged coverage exceeds size budget')
                recorded_files[name + '/' + path.name] = digest(path)
            record = coverage.validate_collection(directory, jar)
            actual = {'suite': record['suite'], 'layer': record['layer'],
                'sessions': [row['session'] for row in record['sessions']]}
            if record.get('ciGroup') != identity or actual != metadata:
                raise ValueError('merged collection group identity changed')
            recorded_sessions.extend(actual['sessions'])
        if (len(set(recorded_sessions)) != len(recorded_sessions)
                or sessions.intersection(recorded_sessions)):
            raise ValueError('duplicate merged session identity')
        sessions.update(recorded_sessions)
        if sorted(recorded_sessions) != manifest['sessions'] or recorded_files != manifest['files']:
            raise ValueError('merged grouped payload differs from sealed input')
    if {p.name for p in (root / 'collections').iterdir()} != known:
        raise ValueError('extra merged collections')
    return {'attempt': attempt, 'inventorySha256': evidence['inventorySha256'],
        'groupsSha256': digest(root / 'groups.json'),
        'groups': {name: {'collections': len(group['collections']), 'sessions': len(group['sessions'])}
            for name, group in sorted(groups.items())}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('seal', 'merge'))
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, default=HERE / 'integration-groups.json')
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    inventory = read(args.inventory)
    if args.command == 'seal':
        identity = coverage.ci_group_identity(os.environ)
        if identity is None or identity['target'] != args.target:
            raise ValueError('group sealing requires current CI group identity')
        seal(args.root, args.jar, inventory, identity)
    else:
        if not args.output:
            parser.error('merge requires --output')
        merge(args.root, args.output, args.jar, inventory, commit=os.environ['GITHUB_SHA'],
            run=os.environ['GITHUB_RUN_ID'], attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), target=args.target)


if __name__ == '__main__':
    main()

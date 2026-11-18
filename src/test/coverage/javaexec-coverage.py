#!/usr/bin/env python3
"""Retain complete JavaExec sessions and exact production/test class identities.

This verifies collection integrity. The combined Java reporter must additionally
verify JaCoCo class IDs, probe lengths and session IDs before admitting execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
from zipfile import ZipFile, ZipInfo


MAX_EXEC = 16 * 1024 * 1024
MAX_COLLECTION = 64 * 1024 * 1024
MAX_CLASSES = 64 * 1024 * 1024
TASK = re.compile(r'[A-Za-z][A-Za-z0-9]*')
CLASS = re.compile(r'(?:[A-Za-z_$][A-Za-z0-9_$]*/)*[A-Za-z_$][A-Za-z0-9_$]*\.class')


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=4) + '\n', encoding='utf-8')


def regular(path, limit):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError('missing, linked or excessive coverage file: ' + str(path))
    return path


def read(path):
    return json.loads(regular(path, 1024 * 1024).read_text(encoding='utf-8'))


def jar_classes(path):
    regular(path, MAX_CLASSES)
    with ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError('duplicate JAR members')
        entries = [item for item in archive.infolist() if item.filename.endswith('.class')]
        if not entries or sum(item.file_size for item in entries) > MAX_CLASSES:
            raise ValueError('empty or excessive class population')
        if any(not CLASS.fullmatch(item.filename) or (item.external_attr >> 16) & 0o170000 == 0o120000
                for item in entries):
            raise ValueError('invalid or linked class member')
        return {item.filename: archive.read(item) for item in entries}


def directory_classes(directories):
    result = {}
    total = 0
    for directory in directories:
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('missing or linked class directory')
        for path in sorted(directory.rglob('*.class')):
            name = path.relative_to(directory).as_posix()
            if not CLASS.fullmatch(name) or name in result:
                raise ValueError('invalid or duplicate compiled class')
            if any(parent.is_symlink() for parent in path.parents if parent != directory.parent):
                raise ValueError('linked compiled class directory')
            regular(path, MAX_CLASSES)
            total += path.stat().st_size
            if total > MAX_CLASSES:
                raise ValueError('compiled classes exceed bound')
            result[name] = path.read_bytes()
    if not result:
        raise ValueError('empty compiled class population')
    return result


def fingerprint(classes):
    value = hashlib.sha256()
    for name, content in sorted(classes.items()):
        value.update((name + '\n' + hashlib.sha256(content).hexdigest() + '\n').encode('utf-8'))
    return value.hexdigest()


def task_selection(tasks):
    if (not isinstance(tasks, list) or not 0 < len(tasks) <= 2048
            or any(not isinstance(task, str) or not TASK.fullmatch(task) for task in tasks)
            or len(tasks) != len(set(tasks))):
        raise ValueError('invalid required JavaExec task selection')
    return set(tasks)


def exact_files(directory, names):
    if directory.is_symlink() or not directory.is_dir() or {p.name for p in directory.iterdir()} != set(names):
        raise ValueError('missing or unexpected collection files: ' + str(directory))


def validate_records(tasks, receipts, executions, expected, production, tests, commit, run):
    expected = task_selection(expected)
    for directory, suffix in ((tasks, '.json'), (receipts, '.json'), (executions, '.exec')):
        exact_files(directory, {name + suffix for name in expected})
    if (not re.fullmatch(r'[0-9a-f]{40}', commit)
            or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', run)):
        raise ValueError('invalid collection provenance')
    if set(production) & set(tests):
        raise ValueError('test and production class populations overlap')
    production_id, test_id = fingerprint(production), fingerprint(tests)
    sessions = set()
    rows = []
    total = 0
    required_keys = {'schema', 'task', 'session', 'complete', 'commit', 'run', 'host',
        'jacocoVersion', 'productionFingerprint', 'testFingerprint', 'executionSha256'}
    for task in sorted(expected):
        marker = read(tasks / (task + '.json'))
        receipt = read(receipts / (task + '.json'))
        if marker != {'task': task, 'complete': True}:
            raise ValueError('JavaExec behavioral task did not complete: ' + task)
        if (set(receipt) != required_keys or receipt['schema'] != 1 or receipt['complete'] is not True
                or receipt['task'] != task or receipt['commit'] != commit or receipt['run'] != run
                or receipt['jacocoVersion'] != '0.8.16'
                or receipt['productionFingerprint'] != production_id or receipt['testFingerprint'] != test_id
                or not isinstance(receipt['host'], str) or not receipt['host'].strip()
                or not re.fullmatch(r'forge-javaexec-[0-9a-f]{32}', receipt['session'])):
            raise ValueError('invalid or stale JavaExec receipt: ' + task)
        if receipt['session'] in sessions:
            raise ValueError('duplicate JavaExec session')
        sessions.add(receipt['session'])
        execution = regular(executions / (task + '.exec'), MAX_EXEC)
        total += execution.stat().st_size
        if total > MAX_COLLECTION or digest(execution) != receipt['executionSha256']:
            raise ValueError('changed or excessive JavaExec execution data')
        rows.append({'task': task, 'session': receipt['session'], 'host': receipt['host'],
            'executionSha256': receipt['executionSha256'],
            'receiptSha256': digest(receipts / (task + '.json')),
            'taskSha256': digest(tasks / (task + '.json'))})
    return rows


def validate_collection(root, jar, expected, commit, run):
    exact_files(root, {'manifest.json', 'test-classes.jar', 'tasks', 'sessions', 'execution'})
    manifest = read(root / 'manifest.json')
    production, tests = jar_classes(jar), jar_classes(root / 'test-classes.jar')
    rows = validate_records(root / 'tasks', root / 'sessions', root / 'execution',
        expected, production, tests, commit, run)
    wanted = {'schema': 1, 'status': 'COLLECTED', 'layer': 'javaexec', 'commit': commit,
        'run': run, 'jacocoVersion': '0.8.16', 'productionJarSha256': digest(jar),
        'productionFingerprint': fingerprint(production), 'productionClasses': len(production),
        'testJarSha256': digest(root / 'test-classes.jar'), 'testFingerprint': fingerprint(tests),
        'testClasses': len(tests), 'sessions': rows}
    if manifest != wanted:
        raise ValueError('JavaExec manifest does not match the collected sessions')
    return manifest


def collect(args):
    expected = read(args.expected_tasks)
    production = jar_classes(args.jar)
    compiled = directory_classes(args.main_classes)
    tests = directory_classes(args.test_classes)
    if compiled != production:
        raise ValueError('packaged production JAR differs from tested compiled classes')
    rows = validate_records(args.tasks, args.sessions, args.executions, expected,
        production, tests, args.commit, args.run_id)
    args.output.mkdir(parents=True, exist_ok=False)
    save(args.output / 'manifest.json', {'schema': 1, 'status': 'INCOMPLETE'})
    with ZipFile(args.output / 'test-classes.jar', 'w') as archive:
        for name, content in sorted(tests.items()):
            entry = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, content)
    for source, destination, suffix in ((args.tasks, 'tasks', '.json'),
            (args.sessions, 'sessions', '.json'), (args.executions, 'execution', '.exec')):
        folder = args.output / destination
        folder.mkdir()
        for task in sorted(task_selection(expected)):
            shutil.copyfile(source / (task + suffix), folder / (task + suffix))
    save(args.output / 'manifest.json', {'schema': 1, 'status': 'COLLECTED', 'layer': 'javaexec',
        'commit': args.commit, 'run': args.run_id, 'jacocoVersion': '0.8.16',
        'productionJarSha256': digest(args.jar), 'productionFingerprint': fingerprint(production),
        'productionClasses': len(production), 'testJarSha256': digest(args.output / 'test-classes.jar'),
        'testFingerprint': fingerprint(tests), 'testClasses': len(tests), 'sessions': rows})
    try:
        manifest = validate_collection(args.output, args.jar, expected, args.commit, args.run_id)
    except Exception:
        save(args.output / 'manifest.json', {'schema': 1, 'status': 'INCOMPLETE'})
        raise
    print(json.dumps({'status': 'COLLECTED', 'sessions': len(manifest['sessions']),
        'productionClasses': len(production), 'testClasses': len(tests),
        'remaining': 'Verify raw JaCoCo identities and probes before reporting coverage'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('jar', 'tasks', 'sessions', 'executions', 'expected-tasks', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('main-classes', 'test-classes'):
        parser.add_argument('--' + name, type=Path, action='append', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--run-id', required=True)
    collect(parser.parse_args())


if __name__ == '__main__':
    main()

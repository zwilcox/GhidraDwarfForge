#!/usr/bin/env python3
"""Real JVM probe union across groups, using the tiny coverage-control fixture."""
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def prove(fixture_root, java, agent, classpath, run):
    spec = importlib.util.spec_from_file_location('real_group_controls',
        ROOT / 'support/ci/integration-coverage-groups.py')
    groups = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(groups)
    inventory = groups.read(ROOT / 'support/ci/integration-groups.json')
    root = fixture_root / 'group-controls'
    root.mkdir()
    inputs = root / 'inputs'
    inputs.mkdir()
    jar = fixture_root / 'production.jar'
    branches = {'primary': 'a', 'source': 'b'}
    identity = {'commit': 'a' * 40, 'run': '777', 'attempt': 1, 'target': 'x86_64'}

    def report(collections, label):
        destination = root / (label + '-report')
        run([os.sys.executable, '-B', HERE / 'integration-report.py', '--fixture-report',
            '--jar', jar, '--collections', collections, '--output', destination,
            '--java', java, '--jacoco-classpath', classpath,
            '--sources', fixture_root / 'source', '--commit', 'fixture-only',
            '--require-suite', 'real-group-control'], root / (label + '-report.log'))
        return groups.read(destination / 'summary.json')['layers']['native-java']

    for group in sorted(groups.group_names(inventory, 'x86_64')):
        group_root = inputs / group
        full_identity = dict(identity, group=group, job='target-integration')
        if group in branches:
            environment = {'GITHUB_ACTIONS': 'true', 'GITHUB_JOB': 'target-integration',
                'GITHUB_SHA': identity['commit'], 'GITHUB_RUN_ID': identity['run'],
                'GITHUB_RUN_ATTEMPT': '1', 'FORGE_CI_TARGET': 'x86_64', 'FORGE_CI_GROUP': group}
            with patch.dict(os.environ, environment):
                collection = groups.coverage.Collection('real-group-control', jar, 'native-java', environment={
                    'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent.resolve()),
                    'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(group_root / 'collections')})
                branch = branches[group]
                with collection.session([java, '-cp', jar, 'ghidradwarfforge.CollectorFixture', branch], branch) as command:
                    text = run(command, root / (group + '-java.log'))
                    if text.strip() != 'branch=' + branch:
                        raise AssertionError('grouped fixture behavioral oracle failed')
                oracle = root / (group + '-oracle.json')
                groups.coverage.save(oracle, {'status': 'PASS_REAL_GROUP_BRANCH', 'branch': branch})
                collection.finish(oracle)
            measured = report(group_root / 'collections', group)
            counter = measured['sources']['ghidradwarfforge/CollectorFixture.java']['BRANCH']
            if measured['sessions'] != 1 or counter != {'covered': 1, 'missed': 1}:
                raise AssertionError('individual group must cover only its actual branch')
        groups.seal(group_root, jar, inventory, full_identity)
        if group not in branches:
            # Exercise the layout after a file-only artifact upload/download.
            (group_root / 'collections').rmdir()
    merged = root / 'merged'
    groups.merge(inputs, merged, jar, inventory, **identity)
    evidence = groups.verify_merged(merged, jar, inventory,
        commit=identity['commit'], run=identity['run'], target='x86_64')
    measured = report(merged / 'collections', 'combined')
    sources = measured['sources']
    if (measured['sessions'] != 2 or measured['productionClasses'] != 2
            or sources['ghidradwarfforge/CollectorFixture.java']['BRANCH'] != {'covered': 2, 'missed': 0}
            or sources['ghidradwarfforge/UnloadedFixture.java']['LINE']['covered'] != 0
            or sources['ghidradwarfforge/UnloadedFixture.java']['LINE']['missed'] == 0):
        raise AssertionError('group union lost probes or unloaded production classes')
    groups.coverage.save(root / 'result.json', {'status': 'PASS_REAL_GROUP_PROBE_UNION',
        'scope': 'Tiny Java fixture; not a production target or full hosted cohort',
        'groups': len(evidence['groups']), 'sessions': 2, 'productionClasses': 2,
        'individualBranchesCovered': [1, 1], 'unionBranchesCovered': 2,
        'unloadedClassRetained': True})

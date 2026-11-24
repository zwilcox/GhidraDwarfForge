#!/usr/bin/env python3
import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location('timing', Path(__file__).with_name('workflow-timing.py'))
timing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(timing)
TARGETS = ['x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le']
INVENTORY = {'targets': TARGETS, 'steps': [{'name': 'Install tools', 'kind': 'setup'}]}
RUN = {'id': 9, 'head_sha': 'a' * 40, 'status': 'completed', 'conclusion': 'success',
    'event': 'push', 'html_url': 'https://example.invalid/run/9'}


def jobs():
    return {'total_count': 5, 'jobs': [{'id': i, 'name': f'target-preflight ({target})',
        'run_id': 9, 'head_sha': 'a' * 40, 'run_attempt': 2,
        'status': 'completed', 'conclusion': 'success',
        'started_at': '2026-11-18T12:00:00Z', 'completed_at': '2026-11-18T12:10:00Z',
        'steps': [
            {'name': 'Install tools', 'status': 'completed', 'conclusion': 'success',
                'started_at': '2026-11-18T12:00:00Z', 'completed_at': '2026-11-18T12:02:00Z'},
            {'name': 'Check behavior', 'status': 'completed', 'conclusion': 'success',
                'started_at': '2026-11-18T12:02:00Z', 'completed_at': '2026-11-18T12:10:00Z'},
            {'name': 'Other target', 'status': 'completed', 'conclusion': 'skipped',
                'started_at': None, 'completed_at': None}]} for i, target in enumerate(TARGETS)]}


def report(page, run=RUN):
    return timing.summarize(run, page, INVENTORY, attempt=2)


class TimingTests(unittest.TestCase):
    def test_parallel_wall_time_is_not_sum(self):
        result = report(jobs())
        self.assertEqual(600, result['workflowWallSeconds'])
        self.assertEqual(3000, result['jobWallSeconds'])
        self.assertEqual(120, result['architectures']['arm32']['setupSeconds'])

    def test_group_span_includes_wait_between_groups(self):
        page = jobs()
        page['jobs'][0]['name'] = 'target-integration (x86_64, primary)'
        child = copy.deepcopy(page['jobs'][0])
        child.update(id=99, name='target-integration (x86_64, source)',
            started_at='2026-11-18T12:20:00Z', completed_at='2026-11-18T12:30:00Z')
        child['steps'] = []
        page['jobs'].append(child)
        page['total_count'] += 1
        result = report(page)
        self.assertEqual(1800, result['architectures']['x86_64']['elapsedSeconds'])
        self.assertEqual(1200, result['architectures']['x86_64']['jobWallSeconds'])
        self.assertEqual(1800, result['workflowWallSeconds'])
        self.assertEqual(3600, result['jobWallSeconds'])

    def test_incomplete_or_failed_run_is_not_comparable(self):
        for field, value in [('status', 'in_progress'), ('conclusion', 'failure')]:
            run = dict(RUN)
            run[field] = value
            with self.assertRaisesRegex(ValueError, 'successful complete run'):
                report(jobs(), run)

    def test_truncated_duplicate_or_missing_architecture(self):
        page = jobs()
        page['total_count'] += 1
        with self.assertRaisesRegex(ValueError, 'truncated'):
            report(page)
        page = jobs()
        page['jobs'][1] = page['jobs'][0]
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            report(page)
        page = jobs()
        page['jobs'].pop()
        page['total_count'] -= 1
        with self.assertRaisesRegex(ValueError, 'omits a required architecture'):
            report(page)

    def test_mixed_attempt_and_commit(self):
        for field, value in [('head_sha', 'b' * 40), ('run_id', 8), ('run_attempt', 1),
                ('status', 'in_progress'), ('conclusion', 'failure')]:
            page = jobs()
            page['jobs'][0][field] = value
            with self.assertRaisesRegex(ValueError, 'another or unsuccessful attempt'):
                report(page)

    def test_failure_ignored_by_job_is_still_rejected(self):
        page = jobs()
        page['jobs'][0]['steps'][1]['conclusion'] = 'failure'
        with self.assertRaisesRegex(ValueError, 'failed step'):
            report(page)

    def test_negative_time_and_missing_timezone(self):
        with self.assertRaisesRegex(ValueError, 'negative'):
            timing.seconds('2026-11-18T12:01:00Z', '2026-11-18T12:00:00Z')
        with self.assertRaisesRegex(ValueError, 'timezone'):
            timing.timestamp('2026-11-18T12:00:00')

    def test_only_pr_publication_can_be_skipped(self):
        page = jobs()
        publication = copy.deepcopy(page['jobs'][0])
        publication.update(id=100, name='publish-test-coverage', conclusion='skipped',
            started_at=None, completed_at=None, steps=[])
        page['jobs'].append(publication)
        page['total_count'] += 1
        run = dict(RUN, event='pull_request')
        self.assertEqual(['publish-test-coverage'], report(page, run)['expectedSkippedJobs'])
        with self.assertRaisesRegex(ValueError, 'unsuccessful attempt'):
            report(page)
        publication['name'] = 'required-validation'
        with self.assertRaisesRegex(ValueError, 'unsuccessful attempt'):
            report(page, run)


if __name__ == '__main__':
    unittest.main()

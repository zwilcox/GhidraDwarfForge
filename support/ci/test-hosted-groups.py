#!/usr/bin/env python3
"""GitHub pagination and execution admission controls; API replies are fixtures."""
import copy
import importlib.util
from pathlib import Path
import unittest


HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


hosted = module('hosted_groups', 'verify-hosted-groups.py')
fixture = module('group_fixtures', 'test-integration-plan.py')


class HostedGroupTests(unittest.TestCase):
    def test_two_pages(self):
        calls = []
        def request(url):
            calls.append(url)
            return {'total_count': 101, 'jobs': [{'id': i} for i in
                (range(100) if url.endswith('page=1') else [100])]}
        self.assertEqual(101, len(hosted.all_jobs(request, 'https://example.invalid/jobs')))
        self.assertEqual(2, len(calls))

    def test_truncated_duplicate_and_changing_pages(self):
        for second in [{'total_count': 101, 'jobs': []},
                {'total_count': 101, 'jobs': [{'id': 0}]},
                {'total_count': 102, 'jobs': [{'id': 100}]}]:
            def request(url):
                return {'total_count': 101, 'jobs': [{'id': i} for i in range(100)]} if url.endswith('page=1') else second
            with self.subTest(second=second):
                with self.assertRaises(ValueError):
                    hosted.all_jobs(request, 'https://example.invalid/jobs')

    def test_excessive_inventory(self):
        with self.assertRaisesRegex(ValueError, 'job inventory'):
            hosted.all_jobs(lambda _: {'total_count': 1001, 'jobs': [{'id': 1}]}, 'https://example.invalid/jobs')

    def verify(self, jobs, metadata=None):
        run = {'id': fixture.RUN, 'head_sha': fixture.COMMIT,
            'run_attempt': fixture.ATTEMPT, 'path': '.github/workflows/ci.yml'}
        run.update(metadata or {})
        def request(url):
            if '/jobs?' not in url:
                return run
            self.assertIn('/attempts/2/jobs?', url)
            return {'total_count': len(jobs), 'jobs': jobs}
        return hosted.verify(request, 'fixture/fixture', fixture.INVENTORY,
            '2' * 40, fixture.COMMIT, fixture.RUN, fixture.ATTEMPT)

    def test_current_attempt_with_distinct_pr_merge_and_head(self):
        result = self.verify(fixture.successful_jobs())
        self.assertEqual('2' * 40, result['commit'])
        self.assertEqual(fixture.COMMIT, result['headCommit'])
        self.assertEqual(24, len(result['jobs']))

    def test_stale_run_metadata(self):
        for field, value in [('id', 1), ('head_sha', '3' * 40), ('run_attempt', 1),
                ('path', '.github/workflows/other.yml')]:
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, 'stale or mismatched'):
                    self.verify(fixture.successful_jobs(), {field: value})

    def test_missing_failed_and_cancelled_group_fail_admission(self):
        jobs = fixture.successful_jobs()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.verify(jobs[:-1])
        for conclusion in ['failure', 'cancelled', 'skipped']:
            failed = copy.deepcopy(jobs)
            failed[0]['conclusion'] = conclusion
            with self.assertRaisesRegex(ValueError, 'failed or unfinished'):
                self.verify(failed)


if __name__ == '__main__':
    unittest.main()

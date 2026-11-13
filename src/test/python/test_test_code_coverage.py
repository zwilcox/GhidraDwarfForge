"""Coverage accuracy and publication controls; no live GitHub writes."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'support' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


report = load('coverage_report_test', 'test-coverage-report.py')
publisher = load('coverage_publish_test', 'publish-test-coverage.py')
REPO = 'zwilcox/GhidraDwarfForge'
SHA = 'a' * 40


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='forge-coverage-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'tasks').mkdir()
        (self.root / 'tasks/exampleSmoke.json').write_text(json.dumps({'task': 'exampleSmoke', 'complete': True}))
        self.xml(1, 3)

    def xml(self, covered, missed):
        value = f'<counter type="LINE" covered="{covered}" missed="{missed}"/>'
        self.text = f'<report name="fixture"><package name="ghidradwarfforge"><sourcefile name="Example.java">{value}</sourcefile><sourcefile name="Constants.java"/>{value}</package>{value}</report>'
        (self.root / 'coverage.xml').write_text(self.text)

    def generate(self):
        return report.generate(self.root / 'coverage.xml', self.root / 'tasks', self.root / 'public', REPO, SHA, 123)

    def test_metric_denominator_and_empty_interface(self):
        value = self.generate()
        self.assertEqual(value['percent'], '25.0')
        self.assertEqual(value['sources'][0]['percent'], None)
        self.assertIn('25.0%', (self.root / 'public/test-coverage.svg').read_text())
        self.assertIn('/blob/' + SHA + '/src/main/java/', (self.root / 'public/README.md').read_text())

    def test_zero_coverage_is_not_full_coverage(self):
        self.xml(0, 12)
        self.assertEqual(self.generate()['percent'], '0.0')

    def test_no_measured_lines_is_unavailable(self):
        self.xml(0, 0)
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            self.generate()
        self.assertFalse((self.root / 'public/test-coverage.svg').exists())

    def test_missing_and_incomplete_test_sessions(self):
        marker = self.root / 'tasks/exampleSmoke.json'
        marker.write_text(json.dumps({'task': 'exampleSmoke', 'complete': False}))
        with self.assertRaises(ValueError):
            self.generate()
        marker.unlink()
        with self.assertRaisesRegex(ValueError, 'no completed'):
            self.generate()

    def test_malformed_and_inconsistent_counters(self):
        for bad in [self.text.replace('covered="1"', 'covered="-1"'), self.text.replace('</report>', '<counter type="LINE" covered="1" missed="3"/></report>'),
                self.text.replace('<package name="ghidradwarfforge">', '<package name="thirdparty">'),
                self.text.replace('Example.java', '../Example.java'),
                self.text.rsplit('<counter', 1)[0] + '<counter type="LINE" covered="2" missed="3"/></report>',
                '<!DOCTYPE report [<!ENTITY x "expanded">]>' + self.text]:
            with self.subTest(bad=bad):
                (self.root / 'coverage.xml').write_text(bad)
                with self.assertRaises(ValueError):
                    self.generate()

    def test_publication_provenance_and_tampering(self):
        self.generate()
        for name in ['README.md', 'summary.json', 'test-coverage.svg']:
            path = self.root / 'public' / name
            original = path.read_text()
            path.write_text(original + ' ')
            with self.assertRaises(ValueError):
                publisher.publish(self.root, REPO, SHA, 123, dry_run=True)
            path.write_text(original)
        with self.assertRaises(ValueError):
            publisher.publish(self.root, REPO, 'b' * 40, 123, dry_run=True)
        with self.assertRaises(ValueError):
            publisher.publish(self.root, REPO, SHA, 124, dry_run=True)
        (self.root / 'coverage.xml').write_text(self.text + ' ')
        with self.assertRaisesRegex(ValueError, 'hash changed'):
            publisher.publish(self.root, REPO, SHA, 123, dry_run=True)

    def test_dry_run_does_not_call_github(self):
        self.generate()
        def refuse(*args, **kwargs):
            self.fail('dry run touched GitHub')
        self.assertEqual(publisher.publish(self.root, REPO, SHA, 123, request=refuse, dry_run=True)['status'], 'PREPARED_ONLY')

    def test_non_main_cannot_publish(self):
        self.generate()
        with patch.dict(os.environ, {'GITHUB_REF': 'refs/pull/1/merge'}):
            with self.assertRaisesRegex(ValueError, 'restricted to main'):
                publisher.publish(self.root, REPO, SHA, 123)

    def test_superseded_main_never_writes(self):
        self.generate()
        calls = []
        def request(endpoint, **kwargs):
            calls.append(endpoint)
            self.assertFalse(kwargs)
            return {'object': {'sha': 'b' * 40}}
        with patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/main'}):
            self.assertEqual(publisher.publish(self.root, REPO, SHA, 123, request=request)['status'], 'SKIPPED_SUPERSEDED_MAIN')
        self.assertEqual(len(calls), 1)

    def test_publication_preserves_history_and_other_branch_files(self):
        self.generate()
        calls = []
        def request(endpoint, method='GET', payload=None, missing=False):
            calls.append((endpoint, method, payload))
            if endpoint.endswith('/ref/heads/main'):
                return {'object': {'sha': SHA}}
            if method == 'GET' and endpoint.endswith('/ref/heads/' + publisher.BRANCH):
                return {'object': {'sha': 'parent'}}
            if method == 'GET' and endpoint.endswith('/commits/parent'):
                return {'tree': {'sha': 'prior-tree'}}
            if endpoint.endswith('/trees'):
                self.assertEqual(payload['base_tree'], 'prior-tree')
                return {'sha': 'new-tree'}
            if endpoint.endswith('/commits'):
                self.assertEqual(payload['parents'], ['parent'])
                return {'sha': 'new-commit'}
            self.assertEqual(method, 'PATCH')
            self.assertEqual(payload, {'sha': 'new-commit', 'force': False})
            return {}
        with patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/main'}):
            self.assertEqual(publisher.publish(self.root, REPO, SHA, 123, request=request)['status'], 'PUBLISHED')
        self.assertEqual(len(calls), 6)

    def test_first_publication_creates_only_the_report_branch(self):
        self.generate()
        writes = []
        def request(endpoint, method='GET', payload=None, missing=False):
            if method == 'GET':
                if endpoint.endswith('/ref/heads/main'):
                    return {'object': {'sha': SHA}}
                self.assertTrue(endpoint.endswith('/ref/heads/' + publisher.BRANCH))
                self.assertTrue(missing)
                return None
            writes.append((endpoint, method, payload))
            if endpoint.endswith('/trees'):
                self.assertNotIn('base_tree', payload)
                self.assertEqual({item['path'] for item in payload['tree']},
                    {'README.md', 'summary.json', 'test-coverage.svg'})
                return {'sha': 'first-tree'}
            if endpoint.endswith('/commits'):
                self.assertEqual(payload['parents'], [])
                self.assertEqual(payload['tree'], 'first-tree')
                return {'sha': 'first-commit'}
            self.assertTrue(endpoint.endswith('/git/refs'))
            self.assertEqual(payload, {'ref': 'refs/heads/' + publisher.BRANCH, 'sha': 'first-commit'})
            return {}
        with patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/main'}):
            self.assertEqual(publisher.publish(self.root, REPO, SHA, 123, request=request)['status'], 'PUBLISHED')
        self.assertEqual([method for _, method, _ in writes], ['POST', 'POST', 'POST'])


if __name__ == '__main__':
    unittest.main()

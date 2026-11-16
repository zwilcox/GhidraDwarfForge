"""Synthetic report/publication controls. No hosted execution or GitHub writes are claimed."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render = load('combined_render_test', ROOT / 'support/combined-coverage-report.py')
publish = load('combined_publish_test', ROOT / 'support/publish-test-coverage.py')
legacy = load('legacy_render_test', ROOT / 'support/test-coverage-report.py')
REPOSITORY = 'zwilcox/GhidraDwarfForge'


class CombinedPublication(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-combined-publication-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = self.root / 'src/main/java'
        (self.sources / 'ghidradwarfforge').mkdir(parents=True)
        for name in 'ABC':
            (self.sources / ('ghidradwarfforge/' + name + '.java')).write_text(
                'package ghidradwarfforge;\nclass ' + name + ' {\n    int value = 1;\n}\n')
        self.git('init', '-q', '--initial-branch=fixture')
        self.git('add', 'src')
        self.git('commit', '-qm', 'Initial production fixture')
        self.base = self.git('rev-parse', 'HEAD')
        path = self.sources / 'ghidradwarfforge/A.java'
        path.write_text(path.read_text().replace('value = 1', 'value = 2'))
        self.git('add', 'src')
        self.git('commit', '-qm', 'Changed production fixture')
        self.commit = self.git('rev-parse', 'HEAD')
        self.inventory = self.root / 'inventory.json'
        self.policy = {'schema': 1, 'groups': {
            'binaryAndLocationCorrectness': ['ghidradwarfforge/A.java'],
            'fileTransactionsAndValidation': ['ghidradwarfforge/B.java'],
            'remainingProduction': ['ghidradwarfforge/C.java']},
            'targets': {'overall': {'line': 85, 'branch': 80},
                'eachCriticalGroup': {'line': 95, 'branch': 90}, 'changedCode': render.changed.TARGETS}}
        render.policy.javaexec.save(self.inventory, self.policy)
        self.directory = self.root / 'combined'
        (self.directory / 'xml').mkdir(parents=True)
        layers = {}
        for layer in render.LAYERS:
            self.xml(layer, complete=layer == 'combined')
            layers[layer], _ = render.read_xml(self.directory / 'xml' / (layer + '.xml'))
        self.record = {'schema': 1, 'status': 'VERIFIED_HOSTED_MEASUREMENT', 'nativeCMeasured': False,
            'cohort': {'commit': self.commit, 'run': '7'}, 'sessions': 5,
            'productionJarSha256': 'a' * 64, 'inventorySha256': render.policy.javaexec.digest(self.inventory),
            'origins': [{'kind': kind, 'commit': self.commit, 'run': '7', 'sessions': 1}
                for kind in ('javaexec', 'linux', 'linux_host', 'windows', 'firmware')], 'layers': layers}
        self.reassess()

    def git(self, *arguments):
        return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + str(self.root / 'absent-hooks'),
            *arguments], cwd=self.root, text=True).strip()

    def xml(self, layer, complete):
        document = ET.Element('report', name='synthetic counter fixture')
        package = ET.SubElement(document, 'package', name='ghidradwarfforge')
        for name in 'ABC':
            ET.SubElement(package, 'class', name='ghidradwarfforge/' + name)
            source = ET.SubElement(package, 'sourcefile', name=name + '.java')
            ET.SubElement(source, 'line', nr='3', mi='0', ci='3', mb='0' if complete else '1', cb='2' if complete else '1')
            ET.SubElement(source, 'counter', type='LINE', covered='1', missed='0')
            ET.SubElement(source, 'counter', type='BRANCH', covered='2' if complete else '1', missed='0' if complete else '1')
        for node in (package, document):
            ET.SubElement(node, 'counter', type='LINE', covered='3', missed='0')
            ET.SubElement(node, 'counter', type='BRANCH', covered='6' if complete else '3', missed='0' if complete else '3')
        ET.ElementTree(document).write(self.directory / 'xml' / (layer + '.xml'))

    def reassess(self):
        combined = self.record['layers']['combined']
        self.record['overall'] = render.policy.assessed(combined['counters'], self.policy['targets']['overall'])
        self.record['groups'] = {group: {'sources': len(members), 'metrics': render.policy.assessed(
            render.policy.add(combined['sources'][name] for name in members),
            None if group == 'remainingProduction' else self.policy['targets']['eachCriticalGroup'])}
            for group, members in self.policy['groups'].items()}
        self.record['changedCode'] = render.changed.report(self.root, self.base, self.commit,
            self.directory / 'xml/combined.xml', render.changed.TARGETS)
        self.record['targetsMet'] = all(value['targetMet'] is True for value in self.record['overall'].values())
        self.save()

    def save(self):
        render.policy.javaexec.save(self.directory / 'summary.json', self.record)

    def generate(self, local_preview=False):
        return render.generate(self.directory, self.directory / 'public', self.inventory, self.sources,
            REPOSITORY, self.commit, 7, local_preview)

    def verify(self):
        self.save()
        return render.verify(self.directory, self.inventory, self.sources, REPOSITORY, self.commit, 7)

    def prepare(self, directory=None, repository=REPOSITORY, commit=None, run_id=7):
        return publish.prepare_combined(directory or self.directory, repository, commit or self.commit, run_id,
            inventory=self.inventory, sources=self.sources)

    def test_complete_views_and_separate_badges(self):
        result = self.generate()
        self.assertTrue(result['publicationEligible'])
        self.assertEqual(result['overall']['LINE']['percent'], '100.0')
        files = self.prepare()
        self.assertEqual(set(files), {'combined/' + name for name in render.PUBLIC_FILES})
        self.assertIn('Combined Java branches: 100.0%', files['combined/branches.svg'])
        self.assertIn('50.0% (1/2)', files['combined/javaexec.md'])
        self.assertIn('50.0% (3/6)', files['combined/README.md'])
        self.assertIn('/blob/' + self.commit, files['combined/combined.md'])
        self.assertIn('exception', files['combined/README.md'])

    def test_local_preview_cannot_publish(self):
        self.record['status'] = 'LOCAL_BASELINE'
        del self.record['cohort']
        self.record['origins'][0]['commit'] = 'b' * 40
        self.save()
        result = self.generate(local_preview=True)
        self.assertFalse(result['publicationEligible'])
        self.assertIn('Local Java lines', (self.directory / 'public/lines.svg').read_text())
        with self.assertRaisesRegex(ValueError, 'differently scoped'):
            self.prepare()

    def test_unmet_targets_render_diagnostics_but_cannot_publish(self):
        self.xml('combined', complete=False)
        self.record['layers']['combined'], _ = render.read_xml(self.directory / 'xml/combined.xml')
        self.reassess()
        self.assertFalse(self.generate()['publicationEligible'])
        with self.assertRaisesRegex(ValueError, 'accepted targets'):
            self.prepare()
        gaps = json.loads((self.directory / 'public/uncovered-decisions.json').read_text())
        row = gaps['groups']['binaryAndLocationCorrectness']['ghidradwarfforge/A.java'][0]
        self.assertEqual(row, {'line': 3, 'lineCovered': True, 'coveredBranches': 1, 'missedBranches': 1})

    def test_changed_rendered_files_rejected(self):
        self.generate()
        for name in render.PUBLIC_FILES:
            path = self.directory / 'public' / name
            original = path.read_text()
            path.write_text(original + '\nforged')
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.prepare()
            path.write_text(original)

    def test_critical_failure_cannot_hide_behind_passing_overall_targets(self):
        path = self.directory / 'xml/combined.xml'
        document = ET.parse(path)
        source = document.getroot().find("./package/sourcefile[@name='B.java']")
        source.find('line').set('mb', '1')
        source.find('line').set('cb', '1')
        counter = source.find("counter[@type='BRANCH']")
        counter.set('covered', '1')
        counter.set('missed', '1')
        for node in (document.getroot(), document.getroot().find('package')):
            counter = node.find("counter[@type='BRANCH']")
            counter.set('covered', '5')
            counter.set('missed', '1')
        document.write(path)
        self.record['layers']['combined'], _ = render.read_xml(path)
        self.reassess()
        self.assertTrue(self.record['overall']['BRANCH']['targetMet'])
        self.assertTrue(self.record['changedCode']['targetsMet'])
        self.record['targetsMet'] = False
        self.save()
        self.assertFalse(self.generate()['publicationEligible'])
        with self.assertRaisesRegex(ValueError, 'accepted targets'):
            self.prepare()

    def test_no_changed_executable_scope_is_not_reported_as_full_coverage(self):
        self.base = self.commit
        self.reassess()
        self.generate()
        text = (self.directory / 'public/README.md').read_text()
        self.assertIn('NOT_APPLICABLE', text)
        self.assertIn('Lines: not applicable; branches: not applicable.', text)

    def test_symlink_public_file_rejected(self):
        self.generate()
        path = self.directory / 'public/branches.svg'
        moved = self.root / 'branches.svg'
        path.rename(moved)
        path.symlink_to(moved)
        with self.assertRaisesRegex(ValueError, 'publication file'):
            self.prepare()

    def test_missing_and_unexpected_public_files_rejected(self):
        self.generate()
        path = self.directory / 'public/lines.svg'
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'publication files'):
            self.prepare()
        path.write_bytes(original)
        (self.directory / 'public/unexpected.txt').write_text('extra')
        with self.assertRaisesRegex(ValueError, 'publication files'):
            self.prepare()

    def test_modified_metrics_and_gate_assessments_rejected(self):
        for section, key, value in ((self.record['overall']['LINE'], 'percent', '99.9'),
                (self.record, 'targetsMet', False), (self.record['changedCode'], 'targetsMet', False)):
            original = section[key]
            section[key] = value
            with self.assertRaises(ValueError):
                self.verify()
            section[key] = original

    def test_missing_mixed_and_wrong_ci_origins_rejected(self):
        for origin in (self.record['cohort'], self.record['origins'][0]):
            original = origin['run']
            origin['run'] = '8'
            with self.assertRaises(ValueError):
                self.verify()
            origin['run'] = original
        self.record['origins'].pop()
        with self.assertRaisesRegex(ValueError, 'incomplete origins'):
            self.verify()

    def test_changed_xml_and_wrong_population_rejected(self):
        path = self.directory / 'xml/combined.xml'
        path.write_text(path.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'XML, or source population changed'):
            self.verify()
        self.record['layers']['combined'], _ = render.read_xml(path)
        (self.sources / 'ghidradwarfforge/New.java').write_text('class New {}')
        with self.assertRaisesRegex(ValueError, 'every production source'):
            self.verify()

    def test_line_decisions_must_account_for_source_counters(self):
        path = self.directory / 'xml/combined.xml'
        path.write_text(path.read_text().replace('cb="2"', 'cb="1"', 1))
        with self.assertRaisesRegex(ValueError, 'measured line decisions'):
            self.verify()

    def test_duplicate_negative_and_entity_line_data_rejected(self):
        path = self.directory / 'xml/combined.xml'
        original = path.read_text()
        for invalid in (original.replace('nr="3"', 'nr="-3"', 1),
                original.replace('</sourcefile>', '<line nr="3" mi="0" ci="3" mb="0" cb="2"/></sourcefile>', 1),
                '<!DOCTYPE report [<!ENTITY x "expanded">]>' + original):
            path.write_text(invalid)
            with self.assertRaises(ValueError):
                self.verify()

    def test_both_reports_share_one_normal_publication_commit(self):
        self.generate()
        old = self.root / 'legacy'
        (old / 'tasks').mkdir(parents=True)
        (old / 'tasks/exampleSmoke.json').write_text('{"task":"exampleSmoke","complete":true}')
        (old / 'coverage.xml').write_bytes((self.directory / 'xml/javaexec.xml').read_bytes())
        legacy.generate(old / 'coverage.xml', old / 'tasks', old / 'public', REPOSITORY, self.commit, 7)
        calls = []

        def request(endpoint, method='GET', payload=None, missing=False):
            calls.append((endpoint, method, payload))
            if endpoint.endswith('/git/ref/heads/main'):
                return {'object': {'sha': self.commit}}
            if endpoint.endswith('/actions/runs/7'):
                return {'id': 7, 'path': '.github/workflows/ci.yml', 'head_sha': self.commit,
                    'head_branch': 'main', 'event': 'push', 'run_attempt': 2}
            if '/jobs?' in endpoint:
                return {'total_count': 1, 'jobs': [{'name': 'required-validation', 'status': 'completed',
                    'conclusion': 'success', 'head_sha': self.commit, 'run_attempt': 2}]}
            if endpoint.endswith('/git/ref/heads/reports/test-coverage'):
                return {'object': {'sha': 'previous-report'}}
            if endpoint.endswith('/git/commits/previous-report'):
                return {'tree': {'sha': 'previous-tree'}}
            if method == 'POST' and endpoint.endswith('/git/trees'):
                self.assertEqual(payload['base_tree'], 'previous-tree')
                self.assertEqual({item['path'] for item in payload['tree']},
                    {'README.md', 'summary.json', 'test-coverage.svg'} | {'combined/' + name for name in render.PUBLIC_FILES})
                return {'sha': 'new-tree'}
            if method == 'POST' and endpoint.endswith('/git/commits'):
                self.assertEqual(payload['parents'], ['previous-report'])
                return {'sha': 'new-report'}
            if method == 'PATCH':
                self.assertEqual(payload, {'sha': 'new-report', 'force': False})
                return {}
            self.fail('unexpected API call ' + endpoint)

        prepared = self.prepare()
        with patch.dict(os.environ, {'GITHUB_REF': 'refs/heads/main'}), patch.object(
                publish, 'prepare_combined', return_value=prepared):
            result = publish.publish(old, REPOSITORY, self.commit, 7, request=request, combined_directory=self.directory)
        self.assertEqual(result['status'], 'PUBLISHED')
        self.assertEqual(sum(method == 'PATCH' for _, method, _ in calls), 1)


class GateAdmission(unittest.TestCase):
    def test_only_exact_successful_main_attempt_admitted(self):
        sha = 'a' * 40
        run = {'id': 7, 'path': '.github/workflows/ci.yml', 'head_sha': sha,
            'head_branch': 'main', 'event': 'push', 'run_attempt': 2}
        gate = {'name': 'required-validation', 'head_sha': sha, 'run_attempt': 2,
            'status': 'completed', 'conclusion': 'success'}
        jobs = {'total_count': 1, 'jobs': [gate]}
        def request(endpoint):
            return jobs if '/jobs?' in endpoint else run
        publish.require_validated_run(request, 'repos/fixture/repo', sha, 7)
        for record, key, value in ((run, 'event', 'pull_request'), (run, 'head_sha', 'b' * 40),
                (run, 'head_branch', 'feature'), (run, 'path', 'another-workflow.yml'),
                (gate, 'run_attempt', 1), (gate, 'status', 'in_progress'), (gate, 'conclusion', 'failure'),
                (gate, 'conclusion', 'skipped'), (jobs, 'total_count', 2)):
            original = record[key]
            record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                publish.require_validated_run(request, 'repos/fixture/repo', sha, 7)
            record[key] = original


if __name__ == '__main__':
    unittest.main()

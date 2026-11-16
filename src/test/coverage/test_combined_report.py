"""Controls for full source classification and honest threshold arithmetic."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from zipfile import ZipFile


SPEC = importlib.util.spec_from_file_location('combined_report', Path(__file__).with_name('combined-report.py'))
report = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(report)


class ReportPolicy(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-combined-policy-')
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'inventory.json'
        self.sources = {'ghidradwarfforge/A.java', 'ghidradwarfforge/B.java', 'ghidradwarfforge/C.java'}
        self.policy = {'schema': 1, 'groups': {
            'binaryAndLocationCorrectness': ['ghidradwarfforge/A.java'],
            'fileTransactionsAndValidation': ['ghidradwarfforge/B.java'],
            'remainingProduction': ['ghidradwarfforge/C.java']},
            'targets': {'overall': {'line': 85, 'branch': 80}, 'eachCriticalGroup': {'line': 95, 'branch': 90}}}

    def inventory(self):
        self.path.write_text(json.dumps(self.policy))
        return report.inventory(self.path, self.sources)

    def test_all_sources_classified_with_no_overlap(self):
        self.assertEqual(self.inventory(), self.policy)

    def test_new_source_requires_explicit_classification(self):
        self.sources.add('ghidradwarfforge/New.java')
        with self.assertRaisesRegex(ValueError, 'every production source'):
            self.inventory()

    def test_duplicate_membership_is_not_a_weighting_workaround(self):
        self.policy['groups']['remainingProduction'].append('ghidradwarfforge/A.java')
        with self.assertRaisesRegex(ValueError, 'every production source'):
            self.inventory()

    def test_dropped_production_source_rejected(self):
        self.policy['groups']['remainingProduction'].clear()
        with self.assertRaisesRegex(ValueError, 'every production source'):
            self.inventory()

    def test_weakened_target_is_not_silently_accepted(self):
        self.policy['targets']['eachCriticalGroup']['branch'] = 80
        with self.assertRaisesRegex(ValueError, 'accepted milestone'):
            self.inventory()

    def test_rounding_cannot_turn_a_miss_into_a_pass(self):
        values = {'LINE': {'covered': 8496, 'missed': 1504}, 'BRANCH': {'covered': 7996, 'missed': 2004}}
        result = report.assessed(values, {'line': 85, 'branch': 80})
        self.assertEqual((result['LINE']['percent'], result['BRANCH']['percent']), ('85.0', '80.0'))
        self.assertFalse(result['LINE']['targetMet'])
        self.assertFalse(result['BRANCH']['targetMet'])

    def test_exact_boundary_passes_and_empty_branch_scope_is_na(self):
        values = {'LINE': {'covered': 85, 'missed': 15}, 'BRANCH': {'covered': 0, 'missed': 0}}
        result = report.assessed(values, {'line': 85, 'branch': 80})
        self.assertTrue(result['LINE']['targetMet'])
        self.assertIsNone(result['BRANCH']['percent'])
        self.assertIsNone(result['BRANCH']['targetMet'])
        self.assertIsNone(report.assessed(values, None)['LINE']['targetMet'])

    def test_source_group_uses_counter_totals_not_average_percentages(self):
        small = {'LINE': {'covered': 1, 'missed': 0}, 'BRANCH': {'covered': 1, 'missed': 0}}
        large = {'LINE': {'covered': 0, 'missed': 99}, 'BRANCH': {'covered': 0, 'missed': 99}}
        result = report.assessed(report.add([small, large]), {'line': 85, 'branch': 80})
        self.assertEqual(result['LINE']['percent'], '1.0')
        self.assertEqual(result['BRANCH']['percent'], '1.0')

    def test_duplicate_negative_and_fractional_counters_rejected(self):
        for xml in (
            '<x><counter type="LINE" covered="1" missed="0"/><counter type="LINE" covered="1" missed="0"/></x>',
            '<x><counter type="LINE" covered="-1" missed="0"/></x>',
            '<x><counter type="BRANCH" covered="1.5" missed="0"/></x>'):
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                report.counters(ET.fromstring(xml))


class LocalMeasurements(unittest.TestCase):
    """Receipt controls use fixture bytes; the real-JVM verifier checks bytecode."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-local-measurement-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.jar = self.root / 'production.jar'
        with ZipFile(self.jar, 'w') as archive:
            archive.writestr('ghidradwarfforge/Fixture.class', b'receipt fixture')
        agent = self.root / 'agent.jar'
        agent.write_bytes(b'agent receipt fixture')
        self.harness = self.root / 'harness.py'
        self.harness.write_text('assert observed == expected\n')
        collection = report.integration.Collection('local-test', self.jar, 'native-java', environment={
            'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(self.root / 'collections'),
            'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent)})
        with collection.session(['java', 'Harness'], 'oracle'):
            (collection.root / collection.record['sessions'][0]['file']).write_bytes(b'execution receipt fixture')
        oracle = self.root / 'oracle.json'
        oracle.write_text('{"status":"PASS_BEHAVIOR"}')
        collection.finish(oracle)
        self.collection = collection
        self.manifest = self.root / 'measurement.json'
        self.value = {'schema': 1, 'kind': 'local-integration', 'checkoutCommit': 'a' * 40,
            'run': 'local-check', 'directory': 'collections',
            'receipts': {collection.root.name: report.javaexec.digest(collection.root / 'receipt.json')},
            'harnessSha256': {'harness.py': report.javaexec.digest(self.harness)}}

    def load(self):
        self.manifest.write_text(json.dumps(self.value))
        return report.load_local(self.manifest, self.jar, self.root)

    def test_local_origin_preserved_without_hosted_claim(self):
        rows, origin = self.load()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 'native-java')
        self.assertEqual(origin['kind'], 'local-integration')
        self.assertFalse(origin['hostedAcceptance'])
        self.assertEqual(origin['suites'], ['local-test'])
        self.assertNotIn('artifactId', origin)

    def test_changed_harness_rejected(self):
        self.harness.write_text('pass\n')
        with self.assertRaisesRegex(ValueError, 'harness changed'):
            self.load()

    def snapshot(self):
        subprocess.run(['git', 'init', '-q', '--initial-branch=fixture'], cwd=self.root, check=True)
        subprocess.run(['git', 'add', 'harness.py'], cwd=self.root, check=True)
        subprocess.run(['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=' + str(self.root / 'absent-hooks'),
            'commit', '-qm', 'Measured harness snapshot'], cwd=self.root, check=True)
        self.value['harnessSnapshotCommit'] = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()

    def test_exact_archived_harness_can_survive_later_source_edits(self):
        self.snapshot()
        self.harness.write_text('new oracle, not the one previously measured\n')
        rows, origin = self.load()
        self.assertEqual(len(rows), 1)
        self.assertEqual(origin['harnessSnapshotCommit'], self.value['harnessSnapshotCommit'])
        self.assertFalse(origin['hostedAcceptance'])

    def test_archived_harness_must_match_measured_hashes(self):
        self.snapshot()
        self.value['harnessSha256']['harness.py'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'harness changed'):
            self.load()

    def test_missing_harness_snapshot_rejected(self):
        self.snapshot()
        self.value['harnessSnapshotCommit'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'unavailable'):
            self.load()

    def test_changed_receipt_rejected(self):
        path = self.collection.root / 'receipt.json'
        path.write_text(path.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'receipt changed'):
            self.load()

    def test_extra_collection_rejected(self):
        (self.root / 'collections/unrecorded').mkdir()
        with self.assertRaisesRegex(ValueError, 'unexpected collection'):
            self.load()

    def test_failed_oracle_rejected_even_if_manifest_rebound(self):
        oracle = self.collection.root / 'oracle.json'
        oracle.write_text('{"status":"FAIL"}')
        self.collection.record['evidenceSha256'] = report.javaexec.digest(oracle)
        self.collection._save()
        self.value['receipts'][self.collection.root.name] = report.javaexec.digest(self.collection.root / 'receipt.json')
        with self.assertRaisesRegex(ValueError, 'oracle did not pass'):
            self.load()

    def test_missing_origins_and_escaping_paths_rejected(self):
        for key, value in (('checkoutCommit', ''), ('run', ''), ('directory', '../collections'),
                ('receipts', {}), ('harnessSha256', {}),
                ('harnessSha256', {'../harness.py': '0' * 64})):
            with self.subTest(key=key, value=value):
                original = self.value[key]
                self.value[key] = value
                with self.assertRaises(ValueError):
                    self.load()
                self.value[key] = original


if __name__ == '__main__':
    unittest.main()

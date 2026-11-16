"""Synthetic receipt controls; these fixtures are not evidence of host execution."""
import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile


SPEC = importlib.util.spec_from_file_location('hosted_combined', Path(__file__).with_name('hosted-combined-report.py'))
hosted = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hosted)


class CohortAdmission(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-hosted-receipts-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.jar = self.root / 'production.jar'
        with ZipFile(self.jar, 'w') as archive:
            archive.writestr('ghidradwarfforge/Fixture.class', b'receipt fixture, not bytecode')
        agent = self.root / 'agent.jar'
        agent.write_bytes(b'receipt fixture, not an agent')
        self.job = self.root / 'job'
        self.records = {}
        coverage = hosted.combined.integration
        for suite in sorted(hosted.REQUIRED['linux_host'][2]):
            collection = coverage.Collection(suite, self.jar, 'native-java', environment={
                'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(self.job / 'collections'),
                'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent)})
            collection.record['host'] = 'posix'  # Encoding fixture, never a claim about this test host.
            with collection.session(['java', 'Main'], suite):
                (collection.root / collection.record['sessions'][0]['file']).write_bytes(b'not real probes')
            oracle = self.root / (suite + '.json')
            coverage.save(oracle, {'status': 'PASS_FIXTURE', 'privileged': 'PASS', 'unprivileged': 'PASS'})
            collection.finish(oracle)
            self.records[suite] = collection
        report = self.job / 'report'
        report.mkdir()
        xml = report / 'native-java.xml'
        xml.write_text('<report/>')  # The Java verifier, not this metadata loader, checks actual probes.
        self.summary = {'schema': 1, 'status': 'PASS', 'commit': 'a' * 40,
            'productionJarSha256': coverage.digest(self.jar),
            'cohort': {'commit': 'a' * 40, 'run': '7', 'job': 'extension-build'},
            'layers': {'native-java': {'xmlSha256': coverage.digest(xml), 'sessions': 3, 'productionClasses': 1,
                'suites': sorted(self.records), 'unmeasuredForcedHalts': [],
                'receipts': {record.root.name: coverage.digest(record.root / 'receipt.json')
                    for record in self.records.values()}}}}

    def load(self):
        hosted.files.save(self.job / 'report/summary.json', self.summary)
        return hosted.load_job(self.job, self.jar, 'linux_host', 'a' * 40, '7')

    def rebind(self, record):
        record._save()
        self.summary['layers']['native-java']['receipts'][record.root.name] = hosted.files.digest(record.root / 'receipt.json')

    def test_complete_same_cohort_inventory(self):
        rows, origin = self.load()
        self.assertEqual(len(rows), 3)
        self.assertEqual(origin['run'], '7')
        self.assertEqual(origin['job'], 'extension-build')

    def test_mixed_runs_commits_jobs_and_synthetic_reports_rejected(self):
        for key, value in (('run', '8'), ('commit', 'b' * 40), ('job', 'windows-host')):
            with self.subTest(key=key):
                original = self.summary['cohort'][key]
                self.summary['cohort'][key] = value
                with self.assertRaisesRegex(ValueError, 'cohort'):
                    self.load()
                self.summary['cohort'][key] = original
        self.summary['fixtureOnly'] = True
        with self.assertRaisesRegex(ValueError, 'cohort'):
            self.load()

    def test_privileged_visibility_cannot_be_silently_skipped(self):
        record = self.records['linux-metadata-visibility']
        oracle = record.root / 'oracle.json'
        hosted.files.save(oracle, {'status': 'PASS_FIXTURE', 'privileged': 'NOT_RUN', 'unprivileged': 'PASS'})
        record.record['evidenceSha256'] = hosted.files.digest(oracle)
        self.rebind(record)
        with self.assertRaisesRegex(ValueError, 'both real privilege modes'):
            self.load()

    def test_wrong_execution_host_rejected(self):
        record = self.records['linux-directory-sync']
        record.record['host'] = 'nt'
        self.rebind(record)
        with self.assertRaisesRegex(ValueError, 'execution host'):
            self.load()

    def test_missing_collection_rejected(self):
        record = self.records['linux-directory-sync']
        del self.summary['layers']['native-java']['receipts'][record.root.name]
        with self.assertRaises(ValueError):
            self.load()

    def test_required_suite_cannot_be_replaced(self):
        record = self.records['linux-directory-sync']
        record.record['suite'] = 'unrelated'
        self.rebind(record)
        self.summary['layers']['native-java']['suites'] = sorted([
            'unrelated', 'linux-file-metadata', 'linux-metadata-visibility'])
        with self.assertRaisesRegex(ValueError, 'required CI integration suite'):
            self.load()

    def test_counts_and_halt_disclosures_must_match_raw_receipts(self):
        layer = self.summary['layers']['native-java']
        for key, value in (('sessions', 4), ('productionClasses', 99),
                ('unmeasuredForcedHalts', [{'exitCode': 73}])):
            with self.subTest(key=key):
                original = layer[key]
                layer[key] = value
                with self.assertRaises(ValueError):
                    self.load()
                layer[key] = original

    def test_changed_job_report_rejected(self):
        (self.job / 'report/native-java.xml').write_text('<changed/>')
        with self.assertRaisesRegex(ValueError, 'layer report changed'):
            self.load()


class AttachmentOracleAdmission(unittest.TestCase):
    def fixture(self, role):
        # Receipt-shape controls only; never evidence of actual privileged execution.
        cases = [mode + '-' + boundary for mode in ('initial', 'refresh')
            for boundary in ('PREPARED', 'TARGET_REPLACED', 'BEFORE_COMMIT', 'COMMITTED')] if role == 'exec' else []
        record = {'suite': 'linux-attachment-' + role.replace('.', '-'),
            'unmeasuredForcedHalts': [{'label': case, 'exitCode': 89} for case in cases]}
        oracle = {'host': 'production Linux ext4 host', 'target': 'x86_64', 'role': role,
            'entryPoint': 'AttachmentHelper', 'validator': 'production-live', 'runtime': True,
            'unmeasuredNestedChildren': [{'case': case, 'crashExit': 89, 'recoveryHelperMeasured': False}
                for case in cases]}
        return record, oracle

    def test_requires_real_host_helper_validator_and_debugger_for_each_role(self):
        for role in ('exec', 'pie', 'exec.no-build-id'):
            record, oracle = self.fixture(role)
            hosted.attachment_oracle(record, oracle)
            for field, value in (('host', 'limited Linux test host'), ('target', 'aarch64'),
                    ('role', 'unrelated'), ('entryPoint', 'test bridge'),
                    ('validator', 'captured-test-adapter'), ('runtime', False)):
                with self.subTest(role=role, field=field):
                    with self.assertRaisesRegex(ValueError, 'real privileged host'):
                        hosted.attachment_oracle(record, {**oracle, field: value})

    def test_missing_duplicate_or_claimed_measured_children_rejected(self):
        record, oracle = self.fixture('exec')
        for fault in ('missing', 'duplicate', 'exit', 'measured', 'missing-halt', 'wrong-halt'):
            changed_record, changed_oracle = copy.deepcopy((record, oracle))
            rows = changed_oracle['unmeasuredNestedChildren']
            if fault == 'missing':
                rows.pop()
            elif fault == 'duplicate':
                rows[1] = rows[0]
            elif fault == 'exit':
                rows[0]['crashExit'] = 0
            elif fault == 'measured':
                rows[0]['recoveryHelperMeasured'] = True
            elif fault == 'missing-halt':
                changed_record['unmeasuredForcedHalts'].pop()
            else:
                changed_record['unmeasuredForcedHalts'][0]['exitCode'] = 0
            with self.subTest(fault=fault):
                with self.assertRaisesRegex(ValueError, 'unmeasured recovery children'):
                    hosted.attachment_oracle(changed_record, changed_oracle)


class TargetGate(unittest.TestCase):
    def test_all_overall_and_critical_targets_required(self):
        def metrics():
            return {'LINE': {'targetMet': True}, 'BRANCH': {'targetMet': True}}
        summary = {'overall': metrics(), 'groups': {name: {'metrics': metrics()} for name in
            ('binaryAndLocationCorrectness', 'fileTransactionsAndValidation')}}
        self.assertTrue(hosted.targets_met(summary))
        for scope in [summary['overall'], *[value['metrics'] for value in summary['groups'].values()]]:
            for metric in scope.values():
                for failure in (False, None):
                    metric['targetMet'] = failure
                    self.assertFalse(hosted.targets_met(summary))
                metric['targetMet'] = True


class ReportDependencies(unittest.TestCase):
    def test_changed_or_unrecorded_tool_jars_rejected(self):
        with tempfile.TemporaryDirectory(prefix='forge-report-tools-') as temporary:
            root = Path(temporary)
            (root / 'tools').mkdir()
            tool = root / 'tools/tool.jar'
            tool.write_bytes(b'fixture, actual Java compilation verifies the dependency APIs')
            hosted.files.save(root / 'tools.json', {'schema': 1, 'jacocoVersion': '0.8.16',
                'files': {'tool.jar': hosted.files.digest(tool)}})
            self.assertEqual(hosted.tools_classpath(root), str(tool.resolve()))
            tool.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'changed or excessive'):
                hosted.tools_classpath(root)


if __name__ == '__main__':
    unittest.main()

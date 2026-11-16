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


class GuiOracleAdmission(unittest.TestCase):
    def test_headless_or_incomplete_gui_claims_rejected(self):
        record = {'suite': 'gui-script-manager', 'sessions': [{}]}
        oracle = {'status': 'PASS_INTERACTIVE_GUI_MEASUREMENT', 'mode': 'default', 'mainJvmSessions': 1,
            'desktop': 'owned Xvfb and Openbox; actual Swing interactions',
            'outcome': {'requiredChecks': ['script-manager-export-selection=PASS', 'script-manager-export-cancellation=PASS',
                'script-manager-structural-validation=PASS', 'script-manager-gdb=PASS']},
            'unmeasuredNestedJvmKinds': ['geometry calibration', 'report CLI', 'attachment helper']}
        hosted.gui_oracle(record, oracle)
        for key, value in (('status', 'PASS_HEADLESS'), ('mode', 'unwind'), ('mainJvmSessions', 2),
                ('desktop', 'headless JVM'), ('outcome', {'requiredChecks': ['script-manager-export-selection=PASS']}),
                ('unmeasuredNestedJvmKinds', [])):
            with self.subTest(field=key), self.assertRaisesRegex(ValueError, 'actual interactive completion'):
                hosted.gui_oracle(record, {**oracle, key: value})
        with self.assertRaisesRegex(ValueError, 'actual interactive completion'):
            hosted.gui_oracle({**record, 'sessions': []}, oracle)


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


class LexicalOracleAdmission(unittest.TestCase):
    def fixture(self, role='exec', gap=False, calls=False, lines=None):
        labels = ['import', *(['export-baseline'] if lines is not None else []), 'export-first', 'export-repeat']
        record = {'sessions': [{'label': label} for label in labels]}
        oracle = {'status': 'PASS_LEXICAL_SHADOW_MEASUREMENT', 'oracleStatus': 'LEXICAL_SHADOW_PASS',
            'target': 'x86_64', 'javaRuntime': 21, 'role': role, 'discontiguous': gap, 'calls': calls,
            'sourceLines': lines, 'observations': 8, 'outputPair': ['a' * 64, 'b' * 64],
            'protected': {'fixture': 'c' * 64}, 'sourceInventory': {'part.c': 'd' * 64} if lines else None,
            'measurement': {'directAnalyzerSessions': len(labels), 'unmeasuredNestedDrivers': []}}
        if lines is None and gap:
            oracle['controls'] = ['stale', 'coalesced', 'native-decompiler-failure', 'copy-cancellation']
            oracle['measurement']['unmeasuredNestedDrivers'] = ['negative', 'failure']
        elif lines is None and role == 'pie-rebased':
            oracle.update(coverageCuration='PASS', coverageStaging='PASS')
            oracle['measurement']['unmeasuredNestedDrivers'] = [
                'coverage-staging', 'coverage-limit', 'coverage-byte-limit', 'coverage-curation']
        return record, oracle

    def test_all_existing_profiles_required(self):
        cases = []
        for role in ('exec', 'pie', 'pie-rebased'):
            for gap, calls, lines in ((False, False, None), (True, False, None), (True, True, None), (True, True, 8)):
                record, oracle = self.fixture(role, gap, calls, lines)
                cases.append(hosted.lexical_oracle(record, oracle))
        hosted.lexical_cohort(cases)
        for missing in range(len(cases)):
            with self.subTest(missing=cases[missing]), self.assertRaisesRegex(ValueError, 'every existing role'):
                hosted.lexical_cohort(cases[:missing] + cases[missing + 1:])
        with self.assertRaises(ValueError):
            hosted.lexical_cohort(cases + cases[:1])

    def test_missing_or_mislabeled_runtime_evidence_rejected(self):
        record, oracle = self.fixture()
        for key, value in (('status', 'PASS'), ('oracleStatus', 'PASS'), ('target', 'aarch64'),
                ('javaRuntime', 25), ('role', 'unknown'), ('discontiguous', 0), ('calls', True),
                ('sourceLines', 8.0), ('observations', 0), ('outputPair', []), ('protected', {}),
                ('measurement', {'directAnalyzerSessions': 3, 'unmeasuredNestedDrivers': ['unknown']})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                hosted.lexical_oracle(record, {**oracle, key: value})
        for sessions in ([], record['sessions'][1:], list(reversed(record['sessions']))):
            with self.assertRaises(ValueError):
                hosted.lexical_oracle({'sessions': sessions}, oracle)
        record, oracle = self.fixture(gap=True, calls=True, lines=8)
        with self.assertRaises(ValueError):
            hosted.lexical_oracle(record, {**oracle, 'sourceInventory': {}})

    def test_negative_controls_and_unmeasured_children_are_disclosed(self):
        for args, key in ((('exec', True, True, None), 'controls'),
                (('pie-rebased', False, False, None), 'coverageStaging')):
            record, oracle = self.fixture(*args)
            with self.assertRaises(ValueError):
                hosted.lexical_oracle(record, {**oracle, key: None})
            oracle['measurement']['unmeasuredNestedDrivers'] = []
            with self.assertRaises(ValueError):
                hosted.lexical_oracle(record, oracle)


class ObjectOracleAdmission(unittest.TestCase):
    def fixture(self, role='exec', mode='inferred'):
        returning = mode == 'return'
        suite = 'object-return' if returning else 'object-parameter'
        marker = 'OBJECT_RETURN' if returning else 'OBJECT_PARAMETER'
        record = {'suite': suite, 'layer': 'headless',
            'sessions': [{'label': label} for label in ('import', 'export-first', 'export-repeat')]}
        children = ['failure'] if mode == 'explicit' else ['cancellation'] if mode in ('stale', 'conflict') else []
        oracle = {'status': 'PASS_' + marker + '_MEASUREMENT', 'oracleStatus': marker + '_PASS',
            'target': 'x86_64', 'javaRuntime': 21, 'role': role, 'outputPair': ['a' * 64, 'b' * 64],
            'protected': {'fixture': 'c' * 64}, 'explicitBinding': mode == 'explicit',
            'bindingControl': mode if mode in ('stale', 'conflict') else None,
            'measurement': {'directAnalyzerSessions': 3, 'unmeasuredNestedDrivers': children},
            'observations': [{'status': 'PASS', 'aggregate': [10, 4, 21], 'ordinaryReturn': 42,
                'exitCodes': [0], 'bias': 0x100000} for _ in range(2)] if returning else [
                {'objectValue': 7, 'amount': 3}, {'ordinaryName': 'this', 'ordinaryValue': 41}]}
        return record, oracle

    def test_full_existing_matrix_required(self):
        cases = [hosted.object_oracle(*self.fixture(role, mode)) for role in ('exec', 'pie', 'pie-rebased')
            for mode in ('inferred', 'explicit', 'stale', 'conflict', 'return')]
        hosted.object_cohort(cases)
        for missing in range(len(cases)):
            with self.subTest(missing=cases[missing]), self.assertRaisesRegex(ValueError, 'every existing'):
                hosted.object_cohort(cases[:missing] + cases[missing + 1:])
        with self.assertRaises(ValueError):
            hosted.object_cohort(cases[:-1] + cases[:1])

    def test_incomplete_or_changed_analyzer_evidence_rejected(self):
        record, oracle = self.fixture()
        for field, value in (('status', 'PASS'), ('oracleStatus', 'PASS'), ('target', 'aarch64'),
                ('javaRuntime', 25), ('role', 'shared'), ('outputPair', []), ('protected', {}),
                ('explicitBinding', 1), ('bindingControl', 'unknown'), ('observations', [])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                hosted.object_oracle(record, {**oracle, field: value})
        with self.assertRaises(ValueError):
            hosted.object_oracle({**record, 'layer': 'native-java'}, oracle)
        with self.assertRaises(ValueError):
            hosted.object_oracle({**record, 'sessions': record['sessions'][1:]}, oracle)

    def test_debugger_values_and_pie_bias_are_required(self):
        for mode, field, value in (('inferred', 'objectValue', 8), ('return', 'aggregate', [0, 0, 0]),
                ('return', 'ordinaryReturn', 0), ('return', 'exitCodes', [1]), ('return', 'bias', 0)):
            record, oracle = self.fixture('pie', mode)
            oracle['observations'][0][field] = value
            with self.subTest(mode=mode, field=field), self.assertRaises(ValueError):
                hosted.object_oracle(record, oracle)

    def test_failure_and_cancellation_children_cannot_be_claimed_measured(self):
        for mode in ('explicit', 'stale', 'conflict'):
            record, oracle = self.fixture(mode=mode)
            oracle['measurement']['unmeasuredNestedDrivers'] = []
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                hosted.object_oracle(record, oracle)


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

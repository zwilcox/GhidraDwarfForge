"""Synthetic receipt controls; these fixtures are not evidence of host execution."""
import importlib.util
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import subprocess
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
            label = 'controlled-native-failures' if suite == 'linux-file-metadata' else suite
            with collection.session(['java', 'Main'], label):
                (collection.root / collection.record['sessions'][0]['file']).write_bytes(b'not real probes')
            oracle = self.root / (suite + '.json')
            evidence = {'status': 'PASS_FIXTURE', 'privileged': 'PASS', 'unprivileged': 'PASS'}
            if suite == 'linux-file-metadata':
                with collection.session(['java', 'Main'], 'controlled-application-failures'):
                    (collection.root / collection.record['sessions'][-1]['file']).write_bytes(b'not real probes')
                # Schema fixture only: these replies never represent native execution.
                evidence = {'status': 'PASS', 'observations': ['synthetic schema control'],
                    'controlledFailures': {'status': 'PASS_CONTROLLED_LIBC_FAILURES', 'cases': [
                        {'name': name, 'faultHits': 1,
                            'opened': 0 if index < 2 else 1, 'closed': 0 if index < 2 else 1,
                            'sourceUnchanged': True, 'diagnostic': 'synthetic failure diagnostic'}
                        for index, name in enumerate(hosted.metadata_failures.CASES)]},
                    'applicationFailures': {'status': 'PASS_CONTROLLED_LIBC_APPLICATION_FAILURES', 'cases': [
                        {'name': name, 'faultHits': 1, 'opened': 1 if index == 0 else 2,
                            'closed': 1 if index == 0 else 2, 'sourceUnchanged': True,
                            'stageEffectChecked': True, 'retryPassed': True, 'diagnostic': 'synthetic failure'}
                        for index, name in enumerate(hosted.metadata_failures.APPLICATION_CASES)]}}
            coverage.save(oracle, evidence)
            collection.finish(oracle)
            self.records[suite] = collection
        report = self.job / 'report'
        report.mkdir()
        xml = report / 'native-java.xml'
        xml.write_text('<report/>')  # The Java verifier, not this metadata loader, checks actual probes.
        self.summary = {'schema': 1, 'status': 'PASS', 'commit': 'a' * 40,
            'productionJarSha256': coverage.digest(self.jar),
            'cohort': {'commit': 'a' * 40, 'run': '7', 'job': 'extension-build'},
            'layers': {'native-java': {'xmlSha256': coverage.digest(xml), 'sessions': 4, 'productionClasses': 1,
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
        self.assertEqual(len(rows), 4)
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

    def test_metadata_failure_case_cannot_be_omitted_from_rebound_receipt(self):
        record = self.records['linux-file-metadata']
        oracle = record.root / 'oracle.json'
        evidence = hosted.files.read(oracle)
        evidence['controlledFailures']['cases'].pop()
        hosted.files.save(oracle, evidence)
        record.record['evidenceSha256'] = hosted.files.digest(oracle)
        self.rebind(record)
        with self.assertRaisesRegex(ValueError, 'complete controlled failure cases'):
            self.load()

    def test_missing_collection_rejected(self):
        record = self.records['linux-directory-sync']
        del self.summary['layers']['native-java']['receipts'][record.root.name]
        with self.assertRaises(ValueError):
            self.load()

    def test_application_failure_case_cannot_be_omitted_from_rebound_receipt(self):
        record = self.records['linux-file-metadata']
        oracle = record.root / 'oracle.json'
        evidence = hosted.files.read(oracle)
        evidence['applicationFailures']['cases'].pop()
        hosted.files.save(oracle, evidence)
        record.record['evidenceSha256'] = hosted.files.digest(oracle)
        self.rebind(record)
        with self.assertRaisesRegex(ValueError, 'complete application failures'):
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
        for key, value in (('sessions', 5), ('productionClasses', 99),
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
            'unmeasuredForcedHalts': [{'label': case, 'exitCode': 89} for case in cases],
            'sessions': [], 'launcherInvocations': []}
        children = []
        for index, case in enumerate(cases):
            identity = 'forge-integration-' + format(index + 1, '032x')
            label = 'native-recovery-helper-' + case
            record['sessions'].append({'label': label, 'session': identity, 'status': 'ORACLE_PASSED'})
            record['launcherInvocations'].append({'label': label, 'sessions': [identity], 'status': 'ORACLE_PASSED'})
            children.append({'case': case, 'crashExit': 89, 'recoveryHelperMeasured': True,
                'recoveryHelperExit': 0, 'recoveryOutcome': 'ROLLED_BACK', 'recoverySession': identity})
        if cases:
            record['sessions'].append({'label': 'native-recovery', 'session': 'forge-integration-' + 'f' * 32,
                'status': 'ORACLE_PASSED'})
        oracle = {'host': 'production Linux ext4 host', 'target': 'x86_64', 'role': role,
            'entryPoint': 'AttachmentHelper', 'validator': 'production-live', 'runtime': True,
            'recoveryChildren': children}
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

    def test_missing_duplicate_or_unmeasured_children_rejected(self):
        record, oracle = self.fixture('exec')
        for fault in ('missing', 'duplicate', 'exit', 'unmeasured', 'helper-failed', 'helper-halted',
                'helper-boolean', 'wrong-outcome', 'missing-halt', 'wrong-halt', 'historical-schema'):
            changed_record, changed_oracle = copy.deepcopy((record, oracle))
            rows = changed_oracle['recoveryChildren']
            if fault == 'missing':
                rows.pop()
            elif fault == 'duplicate':
                rows[1] = rows[0]
            elif fault == 'exit':
                rows[0]['crashExit'] = 0
            elif fault == 'unmeasured':
                rows[0]['recoveryHelperMeasured'] = False
            elif fault in ('helper-failed', 'helper-halted', 'helper-boolean'):
                rows[0]['recoveryHelperExit'] = {'helper-failed': 1, 'helper-halted': 89, 'helper-boolean': False}[fault]
            elif fault == 'wrong-outcome':
                rows[0]['recoveryOutcome'] = 'COMMITTED'
            elif fault == 'missing-halt':
                changed_record['unmeasuredForcedHalts'].pop()
            elif fault == 'wrong-halt':
                changed_record['unmeasuredForcedHalts'][0]['exitCode'] = 0
            else:
                changed_oracle['unmeasuredNestedChildren'] = changed_oracle.pop('recoveryChildren')
            with self.subTest(fault=fault):
                with self.assertRaisesRegex(ValueError, 'measured recovery helpers'):
                    hosted.attachment_oracle(changed_record, changed_oracle)

    def test_recovery_measurement_requires_distinct_completed_bound_sessions(self):
        record, oracle = self.fixture('exec')
        for fault in ('missing-session', 'duplicate-session-label', 'missing-launcher', 'duplicate-launcher',
                'session-incomplete', 'launcher-incomplete', 'parent-missing', 'parent-incomplete',
                'parent-reused', 'no-binding', 'wrong-binding', 'wrong-launcher-binding', 'two-launcher-sessions',
                'shared-session', 'invalid-session', 'unexpected-helper'):
            r, o = copy.deepcopy((record, oracle))
            if fault == 'missing-session':
                r['sessions'].pop(0)
            elif fault == 'duplicate-session-label':
                r['sessions'][1]['label'] = r['sessions'][0]['label']
            elif fault == 'missing-launcher':
                r['launcherInvocations'].pop()
            elif fault == 'duplicate-launcher':
                r['launcherInvocations'].append(r['launcherInvocations'][0])
            elif fault == 'session-incomplete':
                r['sessions'][0]['status'] = 'INCOMPLETE'
            elif fault == 'launcher-incomplete':
                r['launcherInvocations'][0]['status'] = 'INCOMPLETE'
            elif fault == 'parent-missing':
                r['sessions'].pop()
            elif fault == 'parent-incomplete':
                r['sessions'][-1]['status'] = 'INCOMPLETE'
            elif fault == 'parent-reused':
                r['sessions'][-1]['session'] = r['sessions'][0]['session']
            elif fault == 'no-binding':
                o['recoveryChildren'][0].pop('recoverySession')
            elif fault == 'wrong-binding':
                o['recoveryChildren'][0]['recoverySession'] = r['sessions'][1]['session']
            elif fault == 'wrong-launcher-binding':
                r['launcherInvocations'][0]['sessions'] = [r['sessions'][1]['session']]
            elif fault == 'two-launcher-sessions':
                r['launcherInvocations'][0]['sessions'].append(r['sessions'][1]['session'])
            elif fault == 'unexpected-helper':
                r['sessions'].append(dict(r['sessions'][0], label='native-recovery-helper-unexpected'))
            else:
                identity = r['sessions'][1]['session'] if fault == 'shared-session' else 'not-a-session'
                r['sessions'][0]['session'] = identity
                r['launcherInvocations'][0]['sessions'] = [identity]
                o['recoveryChildren'][0]['recoverySession'] = identity
            with self.subTest(fault=fault):
                with self.assertRaisesRegex(ValueError, 'recovery'):
                    hosted.attachment_oracle(r, o)

    def test_non_exec_roles_cannot_claim_recovery_sessions(self):
        for role in ('pie', 'exec.no-build-id'):
            record, oracle = self.fixture(role)
            children, _ = self.fixture('exec')
            for field in ('sessions', 'launcherInvocations', 'unmeasuredForcedHalts'):
                with self.subTest(role=role, field=field):
                    with self.assertRaisesRegex(ValueError, 'recovery'):
                        hosted.attachment_oracle({**record, field: children[field]}, oracle)


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


class ReportFinalization(unittest.TestCase):
    """Real policy/Git/XML wiring; synthetic counters are not JVM execution evidence."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='forge-hosted-policy-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'src/main/java/ghidradwarfforge/Fixture.java'
        self.source.parent.mkdir(parents=True)
        self.source.write_text('package ghidradwarfforge;\nclass Fixture {\n    int value = 1;\n}\n')
        self.git('init', '-q', '--initial-branch=fixture')
        self.git('add', 'src')
        self.git('commit', '-qm', 'fixture baseline')
        base = self.git('rev-parse', 'HEAD')
        self.source.write_text(self.source.read_text().replace('value = 1', 'value = flag ? 2 : 3'))
        self.git('add', 'src')
        self.git('commit', '-qm', 'fixture changed decision')
        self.args = SimpleNamespace(sources=self.root / 'src/main/java', base_commit=base,
            commit=self.git('rev-parse', 'HEAD'), run_id='7', repository='fixture/fixture',
            inventory=Path(__file__).with_name('critical-sources.json'), output=self.root / 'report')
        (self.args.output / 'xml').mkdir(parents=True)
        self.write_xml(0, 2)

    def git(self, *args):
        return subprocess.check_output(['git', '-c', 'user.name=Coverage fixture',
            '-c', 'user.email=coverage@example.invalid', '-c', 'commit.gpgsign=false',
            '-c', 'core.hooksPath=' + str(self.root / 'absent-hooks'), *args], cwd=self.root, text=True).strip()

    def write_xml(self, missed, covered):
        (self.args.output / 'xml/combined.xml').write_text(
            '<report><package name="ghidradwarfforge"><sourcefile name="Fixture.java">'
            f'<line nr="3" mi="0" ci="1" mb="{missed}" cb="{covered}"/>'
            '</sourcefile></package></report>')

    def finish(self, overall=True, critical=True):
        def metrics(value):
            return {'LINE': {'targetMet': value}, 'BRANCH': {'targetMet': value}}
        result = {'overall': metrics(overall), 'groups': {name: {'metrics': metrics(critical)} for name in
            ('binaryAndLocationCorrectness', 'fileTransactionsAndValidation')}}
        renderer = Mock()
        with patch.object(hosted.combined, 'module', return_value=renderer):
            status = hosted.finish_report(self.args, result)
        renderer.generate.assert_called_once_with(self.args.output, self.args.output / 'public',
            self.args.inventory, self.args.sources, self.args.repository, self.args.commit, 7)
        saved = json.loads((self.args.output / 'summary.json').read_text())
        self.assertEqual(saved, result)
        return status, saved

    def test_checked_in_inventory_drives_real_changed_code_gate(self):
        status, saved = self.finish()
        self.assertEqual(status, 0)
        self.assertTrue(saved['targetsMet'])
        self.assertEqual(saved['changedCode']['LINE']['target'], 90)
        self.assertEqual(saved['changedCode']['BRANCH']['target'], 85)
        self.assertEqual(saved['changedCode']['preferredBranchTarget'], 90)
        self.assertEqual(saved['changedCode']['files']['ghidradwarfforge/Fixture.java']['changedLines'], [3])

    def test_unmet_overall_or_critical_targets_keep_reports_but_fail(self):
        for overall, critical in ((False, True), (True, False)):
            with self.subTest(overall=overall, critical=critical):
                status, saved = self.finish(overall, critical)
                self.assertEqual(status, 1)
                self.assertFalse(saved['targetsMet'])
                self.assertTrue(saved['changedCode']['targetsMet'])

    def test_changed_branch_gap_fails_even_when_aggregate_targets_pass(self):
        self.write_xml(1, 1)
        status, saved = self.finish()
        self.assertEqual(status, 1)
        self.assertFalse(saved['targetsMet'])
        self.assertEqual(saved['changedCode']['BRANCH']['percent'], '50.0')

    def test_weakened_checked_in_policy_is_rejected(self):
        policy = json.loads(self.args.inventory.read_text())
        policy['targets']['substantialChangedLogic']['branchMinimum'] = 80
        self.args.inventory = self.root / 'weakened.json'
        self.args.inventory.write_text(json.dumps(policy))
        with self.assertRaisesRegex(ValueError, 'accepted milestone'):
            self.finish()


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


class FormatterOracleAdmission(unittest.TestCase):
    def fixture(self, role='exec', compression='none', companions=True, lines=None):
        labels = ['prepare', 'default-before', 'enabled', 'repeat', 'default-after',
            'restored-enabled', 'cancellation', 'missing-key', 'wrong-kind']
        record = {'suite': 'formatter-export', 'layer': 'headless',
            'sessions': [{'label': label, 'session': 'fixture-' + label} for label in labels],
            'launcherInvocations': [{'label': label, 'sessions': ['fixture-' + label]}
                for label in labels if label not in ('prepare', 'cancellation')]}
        oracle = {'status': 'PASS_BASIC_PRODUCTION_FORMATTERS', 'target': 'x86_64',
            'role': role, 'compression': compression, 'allCompanions': companions, 'sourceLines': lines,
            'lldb': True, 'gdbVersion': 'GNU gdb fixture; no real execution claimed',
            'measurement': {'directAnalyzerSessions': 2, 'wrapperAnalyzerSessions': 7,
                'exportRoute': 'production-wrapper'},
            'enabledSha256': ['a' * 64, 'b' * 64, 'c' * 64], 'defaultSha256': ['d' * 64, 'b' * 64],
            'testedSources': {'fixture': 'e' * 64}, 'originalSha256': 'f' * 64, 'selectionSha256': '0' * 64}
        return record, oracle

    def test_every_existing_formatter_profile_required(self):
        cases = [hosted.formatter_oracle(*self.fixture(*args)) for args in [
            ('exec', 'none', True, None), ('pie', 'zlib', False, None), ('pie', 'zlib', True, 8)]]
        hosted.formatter_cohort(cases)
        for index in range(3):
            with self.assertRaises(ValueError):
                hosted.formatter_cohort(cases[:index] + cases[index + 1:])
        with self.assertRaises(ValueError):
            hosted.formatter_cohort(cases[:-1] + cases[:1])

    def test_local_or_changed_workflow_cannot_claim_hosted_acceptance(self):
        record, oracle = self.fixture()
        for field, value in [('lldb', False), ('lldb', 1), ('target', 'arm32'), ('status', 'PASS'),
                ('role', 'shared'), ('compression', 'unknown'), ('sourceLines', 8.0),
                ('allCompanions', 1), ('measurement', {'directAnalyzerSessions': 9}),
                ('enabledSha256', []), ('defaultSha256', ['a' * 64, 'x' * 64]),
                ('testedSources', {}), ('originalSha256', None), ('gdbVersion', 'unavailable')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                hosted.formatter_oracle(record, {**oracle, field: value})
        with self.assertRaises(ValueError):
            hosted.formatter_oracle({**record, 'layer': 'native-java'}, oracle)

    def test_wrapper_invocations_cannot_be_missing_duplicated_or_misattributed(self):
        for mutation in ('missing-session', 'missing-wrapper', 'duplicate-wrapper', 'foreign-session'):
            record, oracle = self.fixture()
            if mutation == 'missing-session':
                record['sessions'].pop()
            elif mutation == 'missing-wrapper':
                record['launcherInvocations'].pop()
            elif mutation == 'duplicate-wrapper':
                record['launcherInvocations'][-1] = record['launcherInvocations'][0]
            else:
                record['launcherInvocations'][0]['sessions'] = ['fixture-prepare']
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                hosted.formatter_oracle(record, oracle)


class CallAbiOracleAdmission(unittest.TestCase):
    def fixture(self, suite='calling-convention', role='exec', profile='gcc'):
        custom = suite == 'custom-call-storage'
        record = {'suite': suite, 'layer': 'headless',
            'sessions': [{'label': label} for label in ('import', 'fixed', 'repeat')]}
        oracle = {'status': 'PASS_CALL_ABI_MEASUREMENT', 'target': 'x86_64', 'role': role,
            'compilerProfile': profile, 'previousPackageCompared': False, 'protectedUnchanged': True,
            'rebaseDelta': 0x2000000 if role == 'pie-rebased' else 0,
            'hashes': ['a' * 64, 'b' * 64], 'inputSha256': 'c' * 64, 'protected': {'fixture': 'd' * 64},
            'measurement': {'directAnalyzerSessions': 3, 'unmeasuredPreviousComparisons': []}, 'observations': []}
        for variant in ('compiler', 'fixed'):
            fixed = variant == 'fixed'
            observation = {'status': 'PASS', 'variant': variant, 'exitCodes': [0], 'ordinaryCalls': []}
            for name in ['sysv_function', 'microsoft_function', *(['custom_return'] if custom else [])]:
                observation['ordinaryCalls'].append({'name': name,
                    'entryValues': [1227] if name == 'custom_return' else [1, 2, 3, 4],
                    'returnedRegisterValue': 1234,
                    'gdbReturnUnavailable': fixed and (name != 'sysv_function' or profile == 'windows')})
            for name, blocked, value in [('Microsoft', fixed, 4389),
                    ('Sysv', fixed and profile == 'windows', 1234), ('Return', fixed, 7)]:
                observation['injected' + name + 'Value'] = None if blocked else value
                observation['injected' + name + 'Error'] = 'does not follow the target calling convention' if blocked else None
            oracle['observations'].append(observation)
        return record, oracle

    def test_all_nine_existing_profiles_required(self):
        cases = [hosted.call_abi_oracle(*self.fixture(suite, role, profile))
            for role in ('exec', 'pie', 'pie-rebased') for suite, profile in (
                ('calling-convention', 'gcc'), ('custom-call-storage', 'gcc'), ('custom-call-storage', 'windows'))]
        hosted.call_abi_cohort(cases)
        for index in range(len(cases)):
            with self.assertRaises(ValueError):
                hosted.call_abi_cohort(cases[:index] + cases[index + 1:])
        with self.assertRaises(ValueError):
            hosted.call_abi_cohort(cases[:-1] + cases[:1])

    def test_missing_provenance_and_previous_package_comparison_rejected(self):
        record, oracle = self.fixture(role='pie-rebased')
        for field, value in [('status', 'PASS'), ('target', 'aarch64'), ('role', 'shared'),
                ('previousPackageCompared', True), ('protectedUnchanged', False), ('rebaseDelta', 0),
                ('rebaseDelta', float(0x2000000)), ('hashes', []), ('protected', {}), ('inputSha256', None),
                ('observations', []), ('measurement', {'directAnalyzerSessions': 4, 'unmeasuredPreviousComparisons': []})]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                hosted.call_abi_oracle(record, {**oracle, field: value})
        with self.assertRaises(ValueError):
            hosted.call_abi_oracle({**record, 'sessions': record['sessions'][:-1]}, oracle)
        with self.assertRaises(ValueError):
            hosted.call_abi_oracle({**record, 'layer': 'windows'}, oracle)

    def test_ordinary_calls_must_keep_arguments_returns_and_restrictions(self):
        for field, value in [('entryValues', [0, 0, 0, 0]), ('returnedRegisterValue', 7),
                ('gdbReturnUnavailable', False), ('name', 'other')]:
            record, oracle = self.fixture('custom-call-storage', 'pie', 'windows')
            oracle['observations'][1]['ordinaryCalls'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                hosted.call_abi_oracle(record, oracle)

    def test_injected_call_restrictions_and_compiler_limitations_are_required(self):
        for variant, field, value in [(1, 'injectedMicrosoftError', None), (1, 'injectedReturnValue', 7),
                (1, 'injectedSysvError', 'unrelated error'), (0, 'injectedMicrosoftValue', 1234),
                (0, 'injectedReturnError', 'unexpected failure'), (1, 'exitCodes', [1])]:
            record, oracle = self.fixture('custom-call-storage', 'exec', 'windows')
            oracle['observations'][variant][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                hosted.call_abi_oracle(record, oracle)


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


class BuildIdIdentityAdmission(unittest.TestCase):
    """Receipt fixtures only; the integration harness proves real OS behavior."""

    def setUp(self):
        cases = [
            ('absent', 'original has no build ID'),
            ('malformed', 'GNU build-ID size'),
            ('ambiguous', 'conflicting GNU build IDs'),
            ('baseline', None),
            ('different-original', 'different original bytes'),
            ('hardlink', 'hardlink'),
            ('selected-alias', 'alias'),
            *[('invalid-id-' + str(index), 'build ID must be canonical') for index in range(6)],
        ]
        self.record = {'suite': 'build-id-identity', 'layer': 'native-java',
            'sessions': [{'label': name} for name, _ in cases]}
        self.oracle = {'status': 'PASS', 'host': 'linux',
            'checks': [{'name': name, 'exit': 0 if error is None else 1, 'expectedError': error}
                for name, error in cases],
            'protectedInputs': {name: 'a' * 64 for name in ('original', 'sidecar', 'source', 'report')}}

    def test_complete_receipt(self):
        hosted.build_id_identity_oracle(self.record, self.oracle)

    def test_model_host_cannot_claim_production_linux(self):
        self.oracle['host'] = 'model'
        with self.assertRaisesRegex(ValueError, 'measured Linux refusal'):
            hosted.build_id_identity_oracle(self.record, self.oracle)

    def test_omitted_or_unmeasured_refusal_rejected(self):
        for field, value in [('checks', self.oracle), ('sessions', self.record)]:
            with self.subTest(field=field):
                old = value[field]
                value[field] = old[:-1]
                with self.assertRaisesRegex(ValueError, 'every measured'):
                    hosted.build_id_identity_oracle(self.record, self.oracle)
                value[field] = old

    def test_failed_baseline_and_wrong_refusal_rejected(self):
        for index, field, value in [(3, 'exit', 1), (0, 'exit', 0),
                (0, 'exit', True), (0, 'expectedError', 'unrelated process failure')]:
            with self.subTest(index=index, field=field, value=value):
                oracle = copy.deepcopy(self.oracle)
                oracle['checks'][index][field] = value
                with self.assertRaisesRegex(ValueError, 'every measured'):
                    hosted.build_id_identity_oracle(self.record, oracle)

    def test_input_preservation_evidence_required(self):
        for replacement in [{}, {'original': 'a' * 64},
                dict(self.oracle['protectedInputs'], sidecar='invalid')]:
            with self.subTest(replacement=replacement):
                self.oracle['protectedInputs'] = replacement
                with self.assertRaisesRegex(ValueError, 'preserved input'):
                    hosted.build_id_identity_oracle(self.record, self.oracle)


if __name__ == '__main__':
    unittest.main()

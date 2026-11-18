import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('windows_backup_admission',
    Path(__file__).with_name('windows-backup-failure-admission.py'))
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


class WindowsBackupFailureAdmission(unittest.TestCase):
    def fixture(self):
        # Parser fixtures only; not native execution or coverage artifacts.
        record = {'suite': 'windows-host-primitives', 'layer': 'windows', 'host': 'nt',
            'sessions': [{'label': 'controlled-backup-failures', 'status': 'ORACLE_PASSED'}]}
        rows = [{'name': name, 'faultHits': 1, 'opened': opens, 'closed': opens, 'aborts': opens, 'contextReleased': True,
            'sourceUnchanged': True, 'retryPassed': True,
            'diagnostic': 'fixture failure'} for name, opens in admission.CASES]
        return record, {'status': 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES',
            'backupFailures': {'status': 'PASS_CONTROLLED_WINDOWS_BACKUP_FAILURES',
                'cases': rows, 'handlesBefore': 100, 'handlesAfter': 100,
                'fragmentedReadPassed': True, 'emptyDataPassed': True, 'namedStreamObserved': True},
            'backupFixture': {'status': 'PASS_NATIVE_BACKUP_FIXTURE_PRESERVATION',
                'sha256': {name: 'a' * 64 for name in ('source', 'named-source', 'named-source:notes', 'empty')}}}

    def test_complete_shape(self):
        admission.oracle(*self.fixture())

    def test_actual_windows_required(self):
        record, evidence = self.fixture()
        for key, value in [('suite', 'fake'), ('layer', 'javaexec'), ('host', 'posix')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'actual Windows'):
                admission.oracle({**record, key: value}, evidence)
        with self.assertRaisesRegex(ValueError, 'actual Windows'):
            admission.oracle(record, {**evidence, 'status': 'FAILED'})

    def test_missing_or_corrupt_controls_rejected(self):
        record, evidence = self.fixture()
        for fault in ('missing', 'null', 'wrong-status', 'short', 'duplicate', 'reordered', 'not-a-row'):
            changed = copy.deepcopy(evidence)
            result = changed['backupFailures']
            if fault == 'missing':
                changed.pop('backupFailures')
            elif fault == 'null':
                changed['backupFailures'] = None
            elif fault == 'wrong-status':
                result['status'] = 'FAILED'
            elif fault == 'short':
                result['cases'].pop()
            elif fault == 'duplicate':
                result['cases'][1] = result['cases'][0]
            elif fault == 'reordered':
                result['cases'].reverse()
            else:
                result['cases'][0] = None
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'complete controlled'):
                admission.oracle(record, changed)

    def test_each_fault_requires_cleanup_preservation_and_retry(self):
        record, evidence = self.fixture()
        for index, row in enumerate(evidence['backupFailures']['cases']):
            for key in ('faultHits', 'opened', 'closed', 'aborts', 'contextReleased', 'sourceUnchanged', 'retryPassed', 'diagnostic'):
                values = [True, row[key] + 1] if type(row[key]) is int else [False, None]
                for value in values:
                    changed = copy.deepcopy(evidence)
                    changed['backupFailures']['cases'][index][key] = value
                    with self.subTest(case=row['name'], key=key, value=value):
                        with self.assertRaisesRegex(ValueError, 'cleanup, preservation or retry'):
                            admission.oracle(record, changed)

    def test_handle_count_required(self):
        record, evidence = self.fixture()
        for key in ('handlesBefore', 'handlesAfter'):
            for value in (None, True, 0, -1, 101):
                changed = copy.deepcopy(evidence)
                changed['backupFailures'][key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'stable process handle'):
                    admission.oracle(record, changed)

    def test_positive_native_controls_required(self):
        record, evidence = self.fixture()
        for key in ('fragmentedReadPassed', 'emptyDataPassed', 'namedStreamObserved'):
            for value in (None, False, 1):
                changed = copy.deepcopy(evidence)
                changed['backupFailures'][key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'positive native controls'):
                    admission.oracle(record, changed)

    def test_completed_session_required(self):
        record, evidence = self.fixture()
        for sessions in (None, [], [None], record['sessions'] * 2,
                [{'label': 'controlled-backup-failures', 'status': 'INCOMPLETE'}],
                [{'label': 'wrong', 'status': 'ORACLE_PASSED'}]):
            with self.subTest(sessions=sessions), self.assertRaisesRegex(ValueError, 'completed isolated session'):
                admission.oracle({**record, 'sessions': sessions}, evidence)

    def test_independent_payload_preservation_required(self):
        record, evidence = self.fixture()
        for fixture in (None, {}, {'status': 'FAILED'},
                {**evidence['backupFixture'], 'sha256': {}},
                {**evidence['backupFixture'], 'sha256': {**evidence['backupFixture']['sha256'], 'extra': 'a' * 64}}):
            with self.subTest(fixture=fixture), self.assertRaisesRegex(ValueError, 'independent payload preservation'):
                admission.oracle(record, {**evidence, 'backupFixture': fixture})
        for name in evidence['backupFixture']['sha256']:
            for value in (None, True, 'bad', 'G' * 64):
                changed = copy.deepcopy(evidence)
                changed['backupFixture']['sha256'][name] = value
                with self.subTest(name=name, value=value), self.assertRaisesRegex(ValueError, 'independent payload preservation'):
                    admission.oracle(record, changed)


if __name__ == '__main__':
    unittest.main()

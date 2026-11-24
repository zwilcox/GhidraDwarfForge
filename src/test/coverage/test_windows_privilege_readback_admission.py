import copy
import importlib.util
from pathlib import Path
import unittest

from windows_host_admission import WindowsHostCases

SPEC = importlib.util.spec_from_file_location('windows_privilege_readback_admission',
    Path(__file__).with_name('windows-privilege-readback-admission.py'))
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


class WindowsPrivilegeReadbackAdmission(WindowsHostCases, unittest.TestCase):
    oracle = staticmethod(admission.oracle)

    def fixture(self):
        # Parser fixtures only; not native execution or coverage artifacts.
        record = {'suite': 'windows-host-primitives', 'layer': 'windows', 'host': 'nt',
            'sessions': [{'label': 'privilege', 'status': 'ORACLE_PASSED'}]}
        rows = [{'name': name, 'faultHits': 1,
            'tokenUnchanged': True, 'retryPassed': True, 'scopeRestored': True,
            'diagnostic': 'fixture failure'} for name in admission.CASES]
        return record, {'status': 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES',
            'privilegeReadback': {'status': 'PASS_WINDOWS_PRIVILEGE_READBACK_FAILURES',
                'closeCases': [{'name': name, 'diagnostic': 'fixture close failure',
                    'originalStateRestored': True, 'realHandlesClosed': 1,
                    'suppressedCloseFailure': name.endswith('-and-close')} for name in admission.CLOSE_CASES],
                'cases': rows, 'handlesBefore': 100, 'handlesAfter': 100}}

    def test_complete_shape(self):
        admission.oracle(*self.fixture())

    def test_missing_or_corrupt_controls_rejected(self):
        record, evidence = self.fixture()
        for fault in ('missing', 'null', 'wrong-status', 'short', 'duplicate', 'reordered', 'not-a-row'):
            changed = copy.deepcopy(evidence)
            result = changed['privilegeReadback']
            if fault == 'missing':
                changed.pop('privilegeReadback')
            elif fault == 'null':
                changed['privilegeReadback'] = None
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
        for index, row in enumerate(evidence['privilegeReadback']['cases']):
            for key in ('faultHits', 'tokenUnchanged', 'retryPassed', 'scopeRestored', 'diagnostic'):
                values = [True, row[key] + 1] if type(row[key]) is int else [False, None]
                for value in values:
                    changed = copy.deepcopy(evidence)
                    changed['privilegeReadback']['cases'][index][key] = value
                    with self.subTest(case=row['name'], key=key, value=value):
                        with self.assertRaisesRegex(ValueError, 'cleanup, preservation or retry'):
                            admission.oracle(record, changed)

    def test_handle_count_required(self):
        record, evidence = self.fixture()
        for key in ('handlesBefore', 'handlesAfter'):
            for value in (None, True, 0, -1, 101):
                changed = copy.deepcopy(evidence)
                changed['privilegeReadback'][key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'stable process handle'):
                    admission.oracle(record, changed)

    def test_close_inventory_required(self):
        record, evidence = self.fixture()
        for fault in ('missing', 'null', 'short', 'duplicate', 'reordered', 'not-a-row'):
            changed = copy.deepcopy(evidence)
            result = changed['privilegeReadback']
            if fault == 'missing':
                result.pop('closeCases')
            elif fault == 'null':
                result['closeCases'] = None
            elif fault == 'short':
                result['closeCases'].pop()
            elif fault == 'duplicate':
                result['closeCases'][1] = result['closeCases'][0]
            elif fault == 'reordered':
                result['closeCases'].reverse()
            else:
                result['closeCases'][0] = None
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'complete restoration/close'):
                admission.oracle(record, changed)

    def test_each_close_requires_restoration_handle_release_and_precedence(self):
        record, evidence = self.fixture()
        for index, row in enumerate(evidence['privilegeReadback']['closeCases']):
            for key, values in (
                    ('originalStateRestored', (False, None, 1)),
                    ('realHandlesClosed', (0, 2, None, True, 1.0)),
                    ('suppressedCloseFailure', (not row['suppressedCloseFailure'], None, int(row['suppressedCloseFailure']))),
                    ('diagnostic', ('', ' ', None, True))):
                for value in values:
                    changed = copy.deepcopy(evidence)
                    changed['privilegeReadback']['closeCases'][index][key] = value
                    with self.subTest(case=row['name'], key=key, value=value):
                        with self.assertRaisesRegex(ValueError, 'restoration, handle release or error precedence'):
                            admission.oracle(record, changed)

    def test_completed_session_required(self):
        record, evidence = self.fixture()
        for sessions in (None, [], [None], record['sessions'] * 2,
                [{'label': 'privilege', 'status': 'INCOMPLETE'}],
                [{'label': 'wrong', 'status': 'ORACLE_PASSED'}]):
            with self.subTest(sessions=sessions), self.assertRaisesRegex(ValueError, 'completed isolated session'):
                admission.oracle({**record, 'sessions': sessions}, evidence)


if __name__ == '__main__':
    unittest.main()

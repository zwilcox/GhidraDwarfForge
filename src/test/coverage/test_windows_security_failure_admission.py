import copy
import importlib.util
from pathlib import Path
import unittest

from windows_host_admission import WindowsHostCases

SPEC = importlib.util.spec_from_file_location('windows_security_admission',
    Path(__file__).with_name('windows-security-failure-admission.py'))
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


class WindowsSecurityFailureAdmission(WindowsHostCases, unittest.TestCase):
    oracle = staticmethod(admission.oracle)

    def fixture(self):
        # Parser fixtures only; not native execution or coverage artifacts.
        record = {'suite': 'windows-host-primitives', 'layer': 'windows', 'host': 'nt',
            'sessions': [{'label': 'controlled-security-failures', 'status': 'ORACLE_PASSED'}]}
        rows = [{'name': name, 'faultHits': 1, 'opened': opens, 'closed': opens,
            'sourceUnchanged': True, 'retryPassed': True,
            'diagnostic': 'fixture failure'} for name, opens in admission.CASES]
        return record, {'status': 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES',
            'securityFailures': {'status': 'PASS_CONTROLLED_WINDOWS_SECURITY_FAILURES',
                'cases': rows, 'handlesBefore': 100, 'handlesAfter': 100}}

    def test_complete_shape(self):
        admission.oracle(*self.fixture())

    def test_missing_or_corrupt_controls_rejected(self):
        record, evidence = self.fixture()
        for fault in ('missing', 'null', 'wrong-status', 'short', 'duplicate', 'reordered', 'not-a-row'):
            changed = copy.deepcopy(evidence)
            result = changed['securityFailures']
            if fault == 'missing':
                changed.pop('securityFailures')
            elif fault == 'null':
                changed['securityFailures'] = None
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
        for index, row in enumerate(evidence['securityFailures']['cases']):
            for key in ('faultHits', 'opened', 'closed', 'sourceUnchanged', 'retryPassed', 'diagnostic'):
                values = [True, row[key] + 1] if type(row[key]) is int else [False, None]
                for value in values:
                    changed = copy.deepcopy(evidence)
                    changed['securityFailures']['cases'][index][key] = value
                    with self.subTest(case=row['name'], key=key, value=value):
                        with self.assertRaisesRegex(ValueError, 'cleanup, preservation or retry'):
                            admission.oracle(record, changed)

    def test_handle_count_required(self):
        record, evidence = self.fixture()
        for key in ('handlesBefore', 'handlesAfter'):
            for value in (None, True, 0, -1, 101):
                changed = copy.deepcopy(evidence)
                changed['securityFailures'][key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'stable process handle'):
                    admission.oracle(record, changed)

    def test_completed_session_required(self):
        record, evidence = self.fixture()
        for sessions in (None, [], [None], record['sessions'] * 2,
                [{'label': 'controlled-security-failures', 'status': 'INCOMPLETE'}],
                [{'label': 'wrong', 'status': 'ORACLE_PASSED'}]):
            with self.subTest(sessions=sessions), self.assertRaisesRegex(ValueError, 'completed isolated session'):
                admission.oracle({**record, 'sessions': sessions}, evidence)


if __name__ == '__main__':
    unittest.main()

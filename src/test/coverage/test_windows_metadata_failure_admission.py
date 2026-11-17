import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('windows_metadata_admission',
    Path(__file__).with_name('windows-metadata-failure-admission.py'))
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


class WindowsMetadataFailureAdmission(unittest.TestCase):
    def fixture(self):
        # Schema fixtures only: these are never admitted as native coverage artifacts.
        record = {'suite': 'windows-host-primitives', 'layer': 'windows', 'host': 'nt',
            'sessions': [{'label': label, 'status': 'ORACLE_PASSED'} for label in sorted(admission.SESSIONS)]}
        rows = []
        for name in admission.CASES:
            opened = 0 if name.startswith('open-') else 2 if name == 'close-error-after-release' else 1
            allocated = 0 if name in admission.NO_ALLOCATION else 1
            rows.append({'name': name, 'faultHits': 1, 'opened': opened, 'closed': opened,
                'allocated': allocated, 'freed': allocated, 'sourceUnchanged': True,
                'diagnostic': 'fixture expected failure'})
        return record, {'status': 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES', 'hostChecks': 1, 'transactionChecks': 1,
            'controlledFailures': {'status': 'PASS_CONTROLLED_WINDOWS_FAILURES', 'cases': rows,
                'handlesBefore': 100, 'handlesAfter': 100},
            'unmeasuredNestedChildren': [{'case': str(index), 'exitCode': 89} for index in range(8)],
            'lockContendersMeasured': False}

    def test_complete_shape(self):
        admission.oracle(*self.fixture())

    def test_actual_windows_and_existing_host_oracles_required(self):
        record, evidence = self.fixture()
        for key, value in [('suite', 'fake'), ('layer', 'javaexec'), ('host', 'posix')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'real Windows'):
                admission.oracle({**record, key: value}, evidence)
        for key, value in [('status', 'FAILED'), ('hostChecks', 0), ('hostChecks', True), ('transactionChecks', None)]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'real Windows'):
                admission.oracle(record, {**evidence, key: value})

    def test_missing_old_or_corrupt_controls_rejected(self):
        record, evidence = self.fixture()
        for fault in ('missing', 'null', 'wrong-status', 'short', 'duplicate', 'reordered', 'not-a-row'):
            changed = copy.deepcopy(evidence)
            result = changed['controlledFailures']
            if fault == 'missing':
                changed.pop('controlledFailures')
            elif fault == 'null':
                changed['controlledFailures'] = None
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

    def test_each_fault_requires_resource_cleanup_and_preservation(self):
        record, evidence = self.fixture()
        for index, row in enumerate(evidence['controlledFailures']['cases']):
            for key in ('faultHits', 'opened', 'closed', 'allocated', 'freed', 'sourceUnchanged', 'diagnostic'):
                values = [True, row[key] + 1] if type(row[key]) is int else [False, None]
                for value in values:
                    changed = copy.deepcopy(evidence)
                    changed['controlledFailures']['cases'][index][key] = value
                    with self.subTest(case=row['name'], key=key, value=value):
                        with self.assertRaisesRegex(ValueError, 'hit, cleanup or preservation'):
                            admission.oracle(record, changed)

    def test_handle_count_required(self):
        record, evidence = self.fixture()
        for key in ('handlesBefore', 'handlesAfter'):
            for value in (None, True, 0, -1, 101):
                changed = copy.deepcopy(evidence)
                changed['controlledFailures'][key] = value
                with self.subTest(key=key, value=value), self.assertRaisesRegex(ValueError, 'stable process handle'):
                    admission.oracle(record, changed)

    def test_seven_completed_isolated_sessions_required(self):
        record, evidence = self.fixture()
        for fault in ('missing', 'duplicate', 'wrong-label', 'incomplete', 'nested', 'halt'):
            changed = copy.deepcopy(record)
            if fault == 'missing':
                changed['sessions'].pop()
            elif fault == 'duplicate':
                changed['sessions'][1] = changed['sessions'][0]
            elif fault == 'wrong-label':
                changed['sessions'][0]['label'] = 'unknown'
            elif fault == 'incomplete':
                changed['sessions'][0]['status'] = 'INCOMPLETE'
            else:
                changed['launcherInvocations' if fault == 'nested' else 'unmeasuredForcedHalts'] = [{}]
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'seven completed'):
                admission.oracle(changed, evidence)

    def test_nested_process_disclosure_retained(self):
        record, evidence = self.fixture()
        for fault in ('missing', 'duplicate', 'wrong-exit', 'false-measurement'):
            changed = copy.deepcopy(evidence)
            if fault == 'missing':
                changed.pop('unmeasuredNestedChildren')
            elif fault == 'duplicate':
                changed['unmeasuredNestedChildren'][1] = changed['unmeasuredNestedChildren'][0]
            elif fault == 'wrong-exit':
                changed['unmeasuredNestedChildren'][0]['exitCode'] = 0
            else:
                changed['lockContendersMeasured'] = True
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'nested-process disclosure'):
                admission.oracle(record, changed)


if __name__ == '__main__':
    unittest.main()

import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('metadata_admission',
    Path(__file__).with_name('linux-metadata-failure-admission.py'))
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


class MetadataFailureAdmission(unittest.TestCase):
    def fixture(self):
        # Schema fixtures, never native execution or coverage evidence.
        record = {'suite': 'linux-file-metadata', 'layer': 'native-java', 'host': 'posix',
            'sessions': [{'label': 'controlled-native-failures', 'status': 'ORACLE_PASSED'}]}
        rows = []
        for name in admission.CASES:
            descriptors = 0 if name in ('open-error', 'stat-error') else 1
            rows.append({'name': name, 'faultHits': 1, 'opened': descriptors, 'closed': descriptors,
                'sourceUnchanged': True, 'diagnostic': 'fixture expected failure'})
        return record, {'status': 'PASS', 'observations': ['fixture-only'],
            'controlledFailures': {'status': 'PASS_CONTROLLED_LIBC_FAILURES', 'cases': rows}}

    def test_complete_shape(self):
        admission.oracle(*self.fixture())

    def test_host_and_real_suite_required(self):
        record, evidence = self.fixture()
        for key, value in [('suite', 'fake'), ('layer', 'javaexec'), ('host', 'nt')]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'real Linux'):
                admission.oracle({**record, key: value}, evidence)
        for key, value in [('status', 'FAILED'), ('observations', [])]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'real Linux'):
                admission.oracle(record, {**evidence, key: value})

    def test_old_missing_or_reordered_controls_rejected(self):
        record, evidence = self.fixture()
        for fault in ('old', 'null', 'missing', 'duplicate', 'reorder', 'wrong-name', 'wrong-status'):
            changed = copy.deepcopy(evidence)
            rows = changed['controlledFailures']['cases']
            if fault == 'old':
                changed.pop('controlledFailures')
            elif fault == 'null':
                changed['controlledFailures'] = None
            elif fault == 'missing':
                rows.pop()
            elif fault == 'duplicate':
                rows[1] = rows[0]
            elif fault == 'reorder':
                rows.reverse()
            elif fault == 'wrong-name':
                rows[0]['name'] = 'unrelated'
            else:
                changed['controlledFailures']['status'] = 'FAILED'
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'complete controlled'):
                admission.oracle(record, changed)

    def test_hit_cleanup_and_preservation_required_for_every_case(self):
        record, evidence = self.fixture()
        for index, row in enumerate(evidence['controlledFailures']['cases']):
            for key, value in [('faultHits', 0), ('faultHits', 2), ('faultHits', True),
                    ('opened', row['opened'] + 1), ('closed', row['closed'] + 1), ('closed', False),
                    ('sourceUnchanged', False), ('diagnostic', '')]:
                changed = copy.deepcopy(evidence)
                changed['controlledFailures']['cases'][index][key] = value
                with self.subTest(case=row['name'], key=key, value=value):
                    with self.assertRaisesRegex(ValueError, 'reached, released or preservation'):
                        admission.oracle(record, changed)

    def test_completed_isolated_session_required(self):
        record, evidence = self.fixture()
        for field, value in [('sessions', []), ('sessions', record['sessions'] * 2),
                ('sessions', [{'label': 'controlled-native-failures', 'status': 'INCOMPLETE'}]),
                ('sessions', [{'label': 'unrelated', 'status': 'ORACLE_PASSED'}]),
                ('unmeasuredForcedHalts', [{}]), ('launcherInvocations', [{}])]:
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'completed isolated'):
                admission.oracle({**record, field: value}, evidence)


if __name__ == '__main__':
    unittest.main()

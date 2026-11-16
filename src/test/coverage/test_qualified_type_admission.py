"""Synthetic receipt rejection tests; these do not count as production execution."""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('qualified_type_admission',
    Path(__file__).with_name('qualified-type-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture():
    record = {'suite': 'qualified-type-producer', 'layer': 'native-java', 'host': 'posix',
        'productionJarSha256': 'a' * 64, 'sessions': [{'label': 'producer'}], 'unmeasuredForcedHalts': []}
    evidence = {'status': 'PASS_QUALIFIED_TYPE_PRODUCER', 'host': 'linux', 'target': 'x86_64', 'role': 'exec',
        'productionJarSha256': 'a' * 64, 'globals': list(admission.GLOBALS),
        'compilerGdb': 'PASS', 'exportedGdb': 'PASS', 'validators': ['readelf', 'llvm', 'strict'],
        'deterministic': True, 'inputPreserved': True, 'sidecarSha256': 'b' * 64, 'sourceSha256': 'c' * 64,
        'typeOracle': {'globals': list(admission.GLOBALS), 'negativeControls': admission.expected_controls(),
            'constVoidChain': ['DW_TAG_pointer_type', 'DW_TAG_const_type'], 'constVoidHasNoTarget': True},
        'nativeSha256': {'consumer': 'd' * 64, 'producer': 'e' * 64},
        'harnessSha256': {name: 'f' * 64 for name in admission.SOURCES},
        'protected': {'jar': 'a' * 64, 'consumer': 'd' * 64, 'producer': 'e' * 64,
            **{name: 'f' * 64 for name in admission.SOURCES}, 'input': '1' * 64, 'reference': '2' * 64}}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_complete_cohort(self):
        self.assertEqual(len(admission.expected_controls()), 59)
        admission.cohort([admission.oracle(*fixture())])
        for cases in ([], [('linux', 'x86_64')] * 2, [('linux', 'aarch64')]):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                admission.cohort(cases)

    def test_profile_and_session(self):
        for key, value in [('suite', 'other'), ('layer', 'headless'), ('host', 'nt'),
                ('productionJarSha256', '0' * 64), ('sessions', []),
                ('sessions', [{'label': 'producer'}, {'label': 'producer'}]),
                ('unmeasuredForcedHalts', [{'label': 'producer'}])]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('status', 'PASS'), ('host', 'windows'), ('target', 'aarch64'), ('role', 'pie')]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_behavior(self):
        for key, value in [('compilerGdb', 'SKIPPED'), ('exportedGdb', 'SKIPPED'),
                ('validators', ['llvm']), ('deterministic', False), ('inputPreserved', False),
                ('globals', []), ('sourceSha256', ''), ('sidecarSha256', '')]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_type_chain_and_all_controls(self):
        for index in range(59):
            with self.subTest(index=index):
                self.reject(lambda r, e: e['typeOracle']['negativeControls'].pop(index))
        self.reject(lambda r, e: e['typeOracle']['negativeControls'].reverse())
        self.reject(lambda r, e: e['typeOracle'].update(globals=[]))
        self.reject(lambda r, e: e['typeOracle'].update(constVoidChain=['DW_TAG_pointer_type']))
        self.reject(lambda r, e: e['typeOracle'].update(constVoidHasNoTarget=False))

    def test_provenance(self):
        for name in admission.SOURCES:
            self.reject(lambda r, e: e['harnessSha256'].pop(name))
            self.reject(lambda r, e: e['harnessSha256'].update({name: ''}))
        for name in fixture()[1]['protected']:
            self.reject(lambda r, e: e['protected'].pop(name))
            self.reject(lambda r, e: e['protected'].update({name: ''}))
        for name in ('consumer', 'producer'):
            self.reject(lambda r, e: e['nativeSha256'].pop(name))
            self.reject(lambda r, e: e['nativeSha256'].update({name: '9' * 64}))


if __name__ == '__main__':
    unittest.main()

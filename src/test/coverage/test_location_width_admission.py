"""Synthetic coverage-receipt faults; not native execution evidence."""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('location_width_admission',
    Path(__file__).with_name('location-width-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(target='mips32be', mode='stable'):
    record = {'suite': 'location-width-producer', 'layer': 'native-java', 'host': 'posix',
        'productionJarSha256': 'a' * 64, 'sessions': [{'label': 'producer'}]}
    evidence = {'status': 'PASS_LOCATION_WIDTH_PRODUCER', 'target': target, 'mode': mode,
        'productionJarSha256': 'a' * 64, 'rejectedOverflowExports': 0 if target in ('x86_64', 'aarch64') else 4,
        'validators': ['readelf', 'llvm', 'strict'], 'compilerGdb': 'PASS', 'exportedGdb': 'PASS',
        'deterministic': True, 'inputPreserved': True, 'sidecarSha256': 'b' * 64,
        'harnessSha256': {name: 'c' * 64 for name in admission.SOURCES},
        'nativeSha256': {'consumer': 'd' * 64, 'producer': 'e' * 64},
        'protectedSha256': {'jar': 'a' * 64, 'consumer': 'd' * 64, 'producer': 'e' * 64,
            **{name: 'c' * 64 for name in admission.SOURCES}, 'input': 'f' * 64, 'reference': '1' * 64}}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_all_forms_for_each_target(self):
        for target in admission.TARGETS:
            cases = [admission.oracle(*fixture(target, mode)) for mode in admission.MODES]
            admission.cohort(cases, target)
            for i in range(4):
                with self.subTest(target=target, missing=i), self.assertRaises(ValueError):
                    admission.cohort(cases[:i] + cases[i + 1:], target)
            with self.assertRaises(ValueError):
                admission.cohort(cases + cases[:1], target)
            other = 'x86_64' if target != 'x86_64' else 'aarch64'
            with self.assertRaises(ValueError):
                admission.cohort(cases, other)

    def test_profile_session_and_width(self):
        for key, value in [('suite', 'other'), ('host', 'nt'), ('layer', 'headless'),
                ('productionJarSha256', '0' * 64), ('sessions', []), ('unmeasuredForcedHalts', [{}])]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('status', 'PASS'), ('target', 'unknown'), ('mode', 'unknown'),
                ('rejectedOverflowExports', 0), ('rejectedOverflowExports', 3), ('productionJarSha256', '')]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_behavior_and_provenance(self):
        for key, value in [('validators', ['llvm']), ('compilerGdb', 'SKIPPED'), ('exportedGdb', 'FAIL'),
                ('deterministic', False), ('inputPreserved', False), ('sidecarSha256', '')]:
            self.reject(lambda r, e: e.update({key: value}))
        for field in ('harnessSha256', 'nativeSha256', 'protectedSha256'):
            for key in fixture()[1][field]:
                self.reject(lambda r, e: e[field].pop(key))
                self.reject(lambda r, e: e[field].update({key: ''}))


if __name__ == '__main__':
    unittest.main()

"""Synthetic admission faults; not native or debugger execution evidence."""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('callable_admission',
    Path(__file__).with_name('callable-type-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture():
    record = {'suite': 'callable-type-producer', 'layer': 'native-java', 'host': 'posix',
        'productionJarSha256': 'a' * 64, 'sessions': [{'label': 'producer'}], 'unmeasuredForcedHalts': []}
    evidence = {'status': 'PASS_CALLABLE_TYPE_PRODUCER', 'host': 'linux', 'target': 'x86_64', 'role': 'exec',
        'productionJarSha256': 'a' * 64, 'deterministic': True, 'inputPreserved': True,
        'variants': [{'mode': mode, 'negativeControls': [] if mode == 'compiler' else list(admission.CONTROLS),
            'gdb': 'PASS', 'validators': ['readelf', 'llvm', 'strict'], 'sidecarSha256': 'b' * 64}
            for mode in ('compiler', 'normal', 'unknown', 'blocked')],
        'nativeSha256': {'consumer': 'c' * 64, 'producer': 'd' * 64},
        'harnessSha256': {name: 'e' * 64 for name in admission.SOURCES},
        'protected': {'jar': 'a' * 64, 'consumer': 'c' * 64, 'producer': 'd' * 64,
            **{name: 'e' * 64 for name in admission.SOURCES}, 'input': 'f' * 64, 'reference': '1' * 64}}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_exact_cohort(self):
        admission.cohort([admission.oracle(*fixture())])
        for cases in ([], [('linux', 'x86_64')] * 2, [('linux', 'aarch64')]):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                admission.cohort(cases)

    def test_profile_and_session(self):
        for key, value in [('suite', 'other'), ('layer', 'headless'), ('host', 'nt'),
                ('productionJarSha256', '0' * 64), ('sessions', []),
                ('sessions', [{'label': 'producer'}] * 2), ('unmeasuredForcedHalts', [{}])]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('status', 'PASS'), ('host', 'windows'), ('target', 'aarch64'),
                ('role', 'pie'), ('deterministic', False), ('inputPreserved', False)]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_every_mode_and_control_required(self):
        for value in (None, [], [{}], [{}, {}, {}, {}, {}]):
            self.reject(lambda r, e: e.update(variants=value))
        self.reject(lambda r, e: e['variants'].reverse())
        for mode in range(4):
            for key, value in [('mode', 'other'), ('gdb', 'SKIPPED'),
                    ('validators', ['llvm']), ('sidecarSha256', '')]:
                with self.subTest(mode=mode, key=key):
                    self.reject(lambda r, e: e['variants'][mode].update({key: value}))
            if mode:
                for control in range(len(admission.CONTROLS)):
                    self.reject(lambda r, e: e['variants'][mode]['negativeControls'].pop(control))

    def test_native_and_input_provenance(self):
        for name in ('consumer', 'producer'):
            self.reject(lambda r, e: e['nativeSha256'].pop(name))
            self.reject(lambda r, e: e['nativeSha256'].update({name: '0' * 64}))
        for name in admission.SOURCES:
            self.reject(lambda r, e: e['harnessSha256'].pop(name))
            self.reject(lambda r, e: e['harnessSha256'].update({name: ''}))
        for name in fixture()[1]['protected']:
            self.reject(lambda r, e: e['protected'].pop(name))
            self.reject(lambda r, e: e['protected'].update({name: ''}))


if __name__ == '__main__':
    unittest.main()

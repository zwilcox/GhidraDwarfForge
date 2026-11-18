"""Synthetic metadata rejection controls; these fixtures contribute no coverage evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('producer_failure_admission',
    Path(__file__).with_name('producer-failure-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture():
    record = {'suite': 'producer-failures', 'layer': 'native-java', 'host': 'posix',
        'productionJarSha256': 'a' * 64, 'sessions': [{'label': mode} for mode in admission.MODES],
        'unmeasuredForcedHalts': []}
    evidence = {'status': 'PASS_ISOLATED_PRODUCER_FAILURES', 'target': 'x86_64', 'host': 'linux',
        'sourceCommit': 'af7b278c6aa2ae9daad94fb7f8bffdc0e9980993',
        'sourceArchiveSha256': admission.ARCHIVE_SHA256, 'headersSha256': dict(admission.HEADERS),
        'productionJarSha256': 'a' * 64, 'shimSha256': 'b' * 64,
        'nativeSha256': {'consumer': 'c' * 64, 'producer': 'd' * 64},
        'protected': {'jar': 'a' * 64, 'consumer': 'c' * 64, 'producer': 'd' * 64,
            'archive': admission.ARCHIVE_SHA256, 'input': 'e' * 64},
        'harnessSha256': {name: 'f' * 64 for name in admission.SOURCES},
        'controls': [{'mode': mode, 'faults': 2, 'starts': 2 if mode.startswith('init-') else 4,
            'finishes': 2 if mode.startswith('init-') else 4, 'existingPreserved': True,
            'absentPreserved': True, 'retryIdentical': True, 'validators': ['readelf', 'llvm', 'strict'],
            'gdb': 'PASS', 'sidecarSha256': '1' * 64, 'sourceSha256': '2' * 64} for mode in admission.MODES]}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_complete_cohort(self):
        admission.cohort([admission.oracle(*fixture())])
        for cases in ([], [('linux', 'x86_64')] * 2, [('linux', 'aarch64')]):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                admission.cohort(cases)

    def test_wrong_profile(self):
        for key, value in [('suite', 'other'), ('layer', 'headless'), ('host', 'nt')]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('status', 'PASS'), ('target', 'aarch64'), ('host', 'windows')]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_missing_and_reordered_faults(self):
        for index in range(len(admission.MODES)):
            with self.subTest(index=index):
                self.reject(lambda r, e: r['sessions'].pop(index))
                self.reject(lambda r, e: e['controls'].pop(index))
                self.reject(lambda r, e: e['controls'].append(copy.deepcopy(e['controls'][index])))
        self.reject(lambda r, e: r['sessions'].reverse())
        self.reject(lambda r, e: e['controls'].reverse())
        self.reject(lambda r, e: r.update(unmeasuredForcedHalts=[{'label': 'crashed-child'}]))

    def test_lifecycle_and_behavior(self):
        for index in range(len(admission.MODES)):
            for key, value in [('faults', 1), ('faults', True), ('starts', 0), ('finishes', 0),
                    ('existingPreserved', False), ('absentPreserved', False), ('retryIdentical', False),
                    ('validators', ['readelf', 'llvm']), ('gdb', 'SKIPPED'),
                    ('sidecarSha256', ''), ('sourceSha256', '')]:
                with self.subTest(index=index, key=key):
                    self.reject(lambda r, e: e['controls'][index].update({key: value}))

    def test_pinned_headers_and_build(self):
        for name in admission.HEADERS:
            self.reject(lambda r, e: e['headersSha256'].pop(name))
            self.reject(lambda r, e: e['headersSha256'].update({name: '0' * 64}))
        for key in ('sourceCommit', 'sourceArchiveSha256', 'productionJarSha256', 'shimSha256'):
            self.reject(lambda r, e: e.update({key: ''}))
        self.reject(lambda r, e: r.update(productionJarSha256='9' * 64))

    def test_protected_inputs_and_harness(self):
        for name in admission.SOURCES:
            self.reject(lambda r, e: e['harnessSha256'].pop(name))
            self.reject(lambda r, e: e['harnessSha256'].update({name: 'not-a-hash'}))
        for name in ('jar', 'consumer', 'producer', 'archive', 'input'):
            self.reject(lambda r, e: e['protected'].pop(name))
            self.reject(lambda r, e: e['protected'].update({name: ''}))
        self.reject(lambda r, e: e['nativeSha256'].update(consumer='8' * 64))
        self.reject(lambda r, e: e['nativeSha256'].pop('producer'))


if __name__ == '__main__':
    unittest.main()

"""Synthetic admission controls, not evidence of Ghidra or GDB execution."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location('entry_admission', Path(__file__).with_name('function-entry-admission.py'))
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


def fixture(aliases):
    record = {'suite': 'function-entry-alias-export' if aliases else 'function-entry-export',
        'layer': 'headless', 'host': 'posix', 'productionJarSha256': 'a' * 64,
        'sessions': [{'label': label} for label in admission.LABELS]}
    evidence = {'status': 'PASS_FUNCTION_ENTRY_MEASUREMENT', 'target': 'x86_64', 'aliases': aliases,
        'productionJarSha256': 'a' * 64, 'oracleLogSha256': 'b' * 64,
        'protected': {str(n): 'c' * 64 for n in range(18)},
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'], 'cases': []}
    for index, label in enumerate(admission.LABELS):
        evidence['cases'].append({'label': label, 'rebaseDelta': 0x2000000 if index % 3 == 1 else 0,
            'checks': ['static-entry-ranges-and-gap=PASS',
                'true-entry-breakpoints-backward-bodies-values-stepping=PASS'],
            'strictStatus': 'PASS', 'uncorroboratedErrors': 0, 'inputSha256': 'd' * 64,
            'sidecarSha256': 'e' * 64, 'sourceSha256': 'f' * 64,
            'aliasSha256': '1' * 64 if aliases else None,
            'receipts': {name: '2' * 64 for name in admission.RECEIPTS}})
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        for aliases in (False, True):
            record, evidence = fixture(aliases)
            edit(record, evidence)
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                admission.oracle(record, evidence)

    def test_complete_modes(self):
        for aliases in (False, True):
            admission.oracle(*fixture(aliases))

    def test_wrong_measurement_and_missing_sessions(self):
        for key, value in [('suite', 'other'), ('layer', 'native-java'), ('host', 'nt'),
                ('productionJarSha256', '0' * 64), ('sessions', []),
                ('sessions', [{'label': label} for label in reversed(admission.LABELS)])]:
            self.reject(lambda r, e: r.update({key: value}))

    def test_wrong_or_incomplete_oracle(self):
        for key, value in [('status', 'PASS'), ('target', 'aarch64'), ('aliases', 0),
                ('oracleLogSha256', ''), ('protected', {}), ('validators', ['readelf']),
                ('cases', []), ('cases', [None] * 6)]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_every_case_requires_debugger_and_validators(self):
        for index in range(6):
            for key, value in [('label', 'other'), ('rebaseDelta', True), ('checks', []),
                    ('strictStatus', 'FAILED'), ('uncorroboratedErrors', 1), ('uncorroboratedErrors', False),
                    ('inputSha256', ''), ('sidecarSha256', None), ('sourceSha256', 'g' * 64),
                    ('aliasSha256', ''), ('receipts', {})]:
                self.reject(lambda r, e: e['cases'][index].update({key: value}))
            for receipt in admission.RECEIPTS:
                self.reject(lambda r, e: e['cases'][index]['receipts'].pop(receipt))

    def test_repeat_and_rebase_identity(self):
        for offset in (0, 3):
            for key in ('inputSha256', 'sidecarSha256', 'sourceSha256'):
                self.reject(lambda r, e: e['cases'][offset + 2].update({key: '0' * 64}))
            self.reject(lambda r, e: e['cases'][offset + 1].update(inputSha256='0' * 64))


if __name__ == '__main__':
    unittest.main()

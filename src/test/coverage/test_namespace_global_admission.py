"""Receipt rejection controls; these do not count as production execution."""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('namespace_admission',
    Path(__file__).with_name('namespace-global-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(target='x86_64'):
    symbols = {name: 0x1000 + index * 4 for index, name in enumerate(admission.VALUES)}
    symbols.update({'marker': 0x2000, 'marker.size': 16})
    record = {'suite': 'namespace-globals', 'layer': 'native-java', 'host': 'posix',
        'productionJarSha256': 'a' * 64, 'sessions': [
            {'label': variant + '-producer', 'status': 'ORACLE_PASSED'} for variant in admission.VARIANTS]}
    evidence = {'status': 'PASS_NAMESPACE_GLOBALS_MEASUREMENT',
        'oracleStatus': 'NAMESPACE_GLOBAL_NATIVE_PASS', 'target': target,
        'jarSha256': 'a' * 64, 'symbols': symbols,
        'harnessSha256': {name: 'b' * 64 for name in admission.SOURCES},
        'nativeSha256': {'consumer': 'c' * 64, 'producer': 'd' * 64},
        'protected': {'jar': 'a' * 64, 'harness': 'b' * 64, 'consumer': 'c' * 64, 'producer': 'd' * 64},
        'artifacts': [{'variant': variant, 'sha256': 'e' * 64,
            'validators': ['readelf', 'llvm', 'strict'],
            'coldQueries': admission.queries(variant, symbols),
            'coldLogSha256': ['f' * 64] * len(admission.queries(variant, symbols))}
            for variant in admission.VARIANTS]}
    for mode in ('compiler', 'selected'):
        evidence[mode] = {'status': 'PASS', 'values': dict(admission.VALUES),
            'addresses': {name: symbols[name] for name in admission.VALUES},
            'return': 140, 'exitCodes': [0], 'shortUnique': 41 if mode == 'selected' else None}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_complete_profiles_and_cohort(self):
        for target in ('x86_64', 'aarch64'):
            admission.cohort([admission.oracle(*fixture(target))], target)
            for cases in ([], [target, target], ['mips32be']):
                with self.subTest(target=target, cases=cases), self.assertRaises(ValueError):
                    admission.cohort(cases, target)
        with self.assertRaises(ValueError):
            admission.cohort(['x86_64'], 'aarch64')

    def test_profile_and_sessions(self):
        for key, value in [('suite', 'other'), ('layer', 'headless'), ('host', 'nt'),
                ('productionJarSha256', '0' * 64), ('sessions', []),
                ('unmeasuredForcedHalts', [{'label': 'normal-producer'}])]:
            self.reject(lambda r, e: r.update({key: value}))
        for index in range(8):
            with self.subTest(index=index):
                self.reject(lambda r, e: r['sessions'].pop(index))
                self.reject(lambda r, e: r['sessions'][index].update(status='RUNNING'))
        self.reject(lambda r, e: r['sessions'].reverse())
        self.reject(lambda r, e: r['sessions'].append(copy.deepcopy(r['sessions'][0])))
        for key, value in [('target', 'mips32be'), ('status', 'PASS'), ('oracleStatus', 'SKIPPED'), ('jarSha256', '')]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_runtime_contract(self):
        for mode in ('compiler', 'selected'):
            for key, value in [('status', 'SKIPPED'), ('values', {}), ('addresses', {}),
                    ('return', 0), ('exitCodes', []), ('exitCodes', [1]), ('exitCodes', [False]), ('shortUnique', 0)]:
                with self.subTest(mode=mode, key=key):
                    self.reject(lambda r, e: e[mode].update({key: value}))
            for name in admission.VALUES:
                self.reject(lambda r, e: e[mode]['values'].update({name: 0}))
                self.reject(lambda r, e: e[mode]['addresses'].update({name: 0}))
        for name in fixture()[1]['symbols']:
            self.reject(lambda r, e: e['symbols'].pop(name))
            self.reject(lambda r, e: e['symbols'].update({name: True}))

    def test_every_collision_and_cold_query(self):
        for index in range(8):
            self.reject(lambda r, e: e['artifacts'].pop(index))
            for key, value in [('variant', 'normal-other'), ('sha256', ''),
                    ('validators', ['llvm']), ('coldQueries', []), ('coldLogSha256', [])]:
                self.reject(lambda r, e: e['artifacts'][index].update({key: value}))
            for query in range(len(fixture()[1]['artifacts'][index]['coldQueries'])):
                self.reject(lambda r, e: e['artifacts'][index]['coldQueries'].pop(query))
                self.reject(lambda r, e: e['artifacts'][index]['coldLogSha256'].__setitem__(query, ''))
        self.reject(lambda r, e: e['artifacts'].reverse())

    def test_protected_sources_and_native_pair(self):
        for key in ('harnessSha256', 'nativeSha256', 'protected'):
            for name in fixture()[1][key]:
                self.reject(lambda r, e: e[key].pop(name))
                self.reject(lambda r, e: e[key].update({name: ''}))
        self.reject(lambda r, e: e['nativeSha256'].update(producer='9' * 64))


if __name__ == '__main__':
    unittest.main()

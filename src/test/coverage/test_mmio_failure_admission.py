import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('mmio_admission', Path(__file__).with_name('mmio-failure-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(target='x86_64'):
    digest = 'a' * 64
    record = {'suite': 'mmio-failure-controls', 'layer': 'headless', 'host': 'posix',
        'productionJarSha256': digest, 'sessions': [{'label': 'failure-controls', 'status': 'ORACLE_PASSED'}]}
    paths = {k: '/case/' + v for k, v in {'input': 'input.elf', 'sidecar': 'firmware.dbg',
        'source': 'firmware.dbg.c', 'profile': 'firmware.dbg.mmio.json'}.items()}
    protected = {p: digest for p in paths.values()}
    protected.update({'/repo/' + n: digest for n in admission.SOURCES})
    protected.update({'/module/' + p: digest for p in ('lib/GhidraDwarfForge.jar',
        'os/linux_x86_64/libdwarf.so.2.3.2', 'os/linux_x86_64/libdwarfp.so.2.3.2')})
    fields = [5, 5, 41, 52, -3, 57997] if target == 'mips32be' else [5, 17, 13, 10, -1, 42405]
    evidence = {'status': 'PASS_MMIO_FAILURE_MEASUREMENT', 'target': target, 'rawFirmware': False,
        'checks': 16, 'protectedBefore': protected, 'protectedAfter': dict(protected),
        'harnessSha256': {n: digest for n in admission.SOURCES},
        'projectBefore': {'Mmio.rep/idata/a.gbf': digest}, 'projectAfter': {'Mmio.rep/idata/a.gbf': digest},
        'artifactPaths': paths, 'strict': {'status': 'PASS', 'uncorroborated_errors': 0},
        'logSha256': digest, 'controls': {'existing.dbg' + s: digest for s in ('', '.c', '.mmio.json')},
        'baseExport': {'status': 'PASS_LAYOUT_AND_SAVED_SETTINGS', 'gaps': [], 'inputPreservation': 'PASS',
            'projectPreservation': 'PASS', 'determinism': 'PASS', 'inputSha256': digest, 'outputsSha256': [digest] * 3,
            'values': {'address': 0x40000000, 'fields': fields, 'raw': 0xa5a5e28d, 'counter': 17,
                'packed': fields[:2], 'widths': [4, 1, 4, 8], 'unionOffsets': [0] * 5,
                'counterOffset': 4, 'flagValues': [1, 8, 128]}}}
    evidence['controls']['formatters.json'] = admission.FORMATTER_CONTROL
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_complete_targets_and_cohort(self):
        for target in ('x86_64', 'mips32le', 'mips32be'):
            self.assertEqual(target, admission.oracle(*fixture(target)))
        admission.cohort(['x86_64'])
        for cases in ([], ['mips32be'], ['x86_64', 'x86_64']):
            with self.assertRaises(ValueError):
                admission.cohort(cases)

    def test_incomplete_sessions(self):
        for key, value in [('suite', 'other'), ('host', 'nt'), ('layer', 'native-java'),
                ('sessions', []), ('productionJarSha256', 'b' * 64), ('unmeasuredForcedHalts', [1])]:
            self.reject(lambda r, e: r.update({key: value}))
        self.reject(lambda r, e: r['sessions'].append(copy.deepcopy(r['sessions'][0])))
        self.reject(lambda r, e: r['sessions'][0].update(status='INCOMPLETE'))
        self.reject(lambda r, e: r['sessions'][0].update(label='import'))
        for key, value in [('checks', 15), ('checks', True), ('rawFirmware', True),
                ('target', 'aarch64'), ('status', 'PASS'), ('logSha256', '')]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_preservation_and_source_identity(self):
        for key in ('protectedBefore', 'protectedAfter', 'harnessSha256', 'projectBefore', 'projectAfter'):
            for name in fixture()[1][key]:
                self.reject(lambda r, e: e[key].pop(name))
                self.reject(lambda r, e: e[key].update({name: 'b' * 64}))
        for key in fixture()[1]['artifactPaths']:
            self.reject(lambda r, e: e['artifactPaths'].pop(key))
            self.reject(lambda r, e: e['artifactPaths'].update({key: '/missing'}))
        self.reject(lambda r, e: e['artifactPaths'].update(source=e['artifactPaths']['sidecar']))

    def test_validator_and_layout_binding(self):
        for key, value in [('status', 'INCOMPLETE'), ('gaps', ['unknown']), ('inputPreservation', 'FAIL'),
                ('projectPreservation', 'FAIL'), ('determinism', 'FAIL'), ('inputSha256', 'b' * 64),
                ('outputsSha256', []), ('values', {})]:
            self.reject(lambda r, e: e['baseExport'].update({key: value}))
        for key in fixture()[1]['baseExport']['values']:
            self.reject(lambda r, e: e['baseExport']['values'].pop(key))
        for key, value in [('status', 'SKIPPED'), ('uncorroborated_errors', 1), ('uncorroborated_errors', False)]:
            self.reject(lambda r, e: e['strict'].update({key: value}))
        for name in fixture()[1]['controls']:
            self.reject(lambda r, e: e['controls'].pop(name))
            self.reject(lambda r, e: e['controls'].update({name: 'b' * 64}))
        self.reject(lambda r, e: e['controls'].update({'partial.dbg': 'a' * 64}))

    def test_numeric_types_are_not_boolean_or_float(self):
        for name, value in fixture()[1]['baseExport']['values'].items():
            for replacement in (True, 1.0):
                if isinstance(value, list):
                    self.reject(lambda r, e: e['baseExport']['values'][name].__setitem__(0, replacement))
                else:
                    self.reject(lambda r, e: e['baseExport']['values'].update({name: replacement}))


if __name__ == '__main__':
    unittest.main()

"""Synthetic receipt controls, never used as production execution evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('recovered-signature-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(kind):
    names = admission.RETURN_NAMES if kind == 'returns' else admission.PARAMETER_NAMES
    functions = [{'name': name, 'signatureSource': 'USER_DEFINED' if name.startswith('curated_') else 'DEFAULT',
        'returnSource': 'USER_DEFINED' if name.startswith('curated_') else 'DEFAULT',
        'formalName': 'undefined', 'customStorage': False, 'varargs': False,
        'listingParameterCount': 1 if name.startswith('curated_') else 0} for name in sorted(names)]
    dies = [{'name': name, 'attributes': ['DW_AT_prototyped'] if name.startswith('curated_') else [],
        'parameters': []} for name in sorted(names)]
    if kind == 'returns':
        for row in functions:
            if row['name'].startswith('recovered_'):
                row['recoveredName'], row['recoveredBytes'] = {
                    'recovered_signed': ('int', 4), 'recovered_unsigned': ('ulong', 8), 'recovered_double': ('double', 8)}[row['name']]
    else:
        for row, die in zip(functions, dies):
            if row['name'].startswith('inferred_'):
                dtype, size = {'inferred_scalar': ('int', 4), 'inferred_pointer': ('int *', 8),
                    'inferred_floating': ('double', 8)}[row['name']]
                row['parameters'] = [{'name': 'param_1', 'type': dtype, 'bytes': size, 'hidden': False, 'thisPointer': False}]
                die['parameters'] = [{'name': 'param_1', 'attributes': ['DW_AT_name', 'DW_AT_type']}]
    protected = {'/repo/' + name: 'b' * 64 for name in admission.sources(kind)}
    protected.update({'/module/lib/GhidraDwarfForge.jar': 'a' * 64, '/case/' + kind + '.input': 'c' * 64})
    project = {admission.PROFILES[kind][1] + '.rep/idata/00/~00000000.db/db.1.gbf': '1' * 64}
    expected = {'recovered_signed': -41, 'recovered_unsigned': 41, 'recovered_double': 1.75} if kind == 'returns' else {
        'inferred_scalar': -41, 'inferred_pointer': 41, 'inferred_floating': 1.75}
    gdb = []
    for variant in ('compiler', 'forge'):
        observed = {name: {'returnedValue': value, 'prototype': 'type = int ()'} for name, value in expected.items()}
        for name, row in observed.items():
            if kind == 'returns':
                row['returnBytes'] = 8 if name == 'recovered_double' or (name == 'recovered_unsigned' and variant == 'forge') else 4
            elif variant == 'forge':
                row['valueStatus'] = 'unavailable'
            else:
                row['argument'] = {'inferred_scalar': -123, 'inferred_pointer': 123, 'inferred_floating': 1.5}[name]
        gdb.append({'variant': variant, 'status': 'PASS', 'functions': observed, 'exitCodes': [0], 'sourceSteps': ['next', 'step']})
    reports = [{'phase': phase, 'counts': {'functionsFailed': 0}, 'artifacts': {'inputSha256': 'c' * 64,
        'outputSha256': 'd' * 64, 'sourceSha256': 'e' * 64}, 'omittedLocations': [{'function': name,
        'variable': 'param_1', 'kind': 'PARAMETER', 'reason': 'UNKNOWN_LIFETIME'} for name in expected]}
        for phase in ('fixed', 'repeat')]
    evidence = {'status': 'PASS_RECOVERED_SIGNATURE_MEASUREMENT', 'kind': kind, 'target': 'x86_64', 'role': 'exec',
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'], 'protectedUnchanged': True,
        'historicalComparisonMeasured': False, 'protectedBefore': protected, 'protectedAfter': copy.deepcopy(protected),
        'harnessSha256': {name: 'b' * 64 for name in admission.sources(kind)},
        'inputSha256': 'c' * 64, 'artifactSha256': ['d' * 64, 'e' * 64], 'modelHashes': ['f' * 64] * 3,
        'projectBefore': project, 'projectAfter': copy.deepcopy(project), 'projectBackupChanges': [],
        'strict': {'status': 'PASS', 'uncorroborated_errors': 0}, 'reports': reports,
        'functions': functions, 'functionDIEs': dies, 'gdb': gdb}
    record = {'suite': 'recovered-' + kind, 'layer': 'headless', 'host': 'posix', 'productionJarSha256': 'a' * 64,
        'sessions': [{'label': label} for label in ('import', 'fixed', 'repeat')]}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit, kinds=('returns', 'parameters')):
        for kind in kinds:
            record, evidence = fixture(kind)
            edit(record, evidence)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                admission.oracle(record, evidence)

    def test_complete_and_missing_cohort(self):
        cases = [admission.oracle(*fixture(kind)) for kind in ('returns', 'parameters')]
        admission.cohort(cases)
        for cases in ([], ['returns'], ['parameters', 'returns', 'returns'], ['returns', 'other']):
            with self.assertRaises(ValueError):
                admission.cohort(cases)

    def test_incomplete_or_wrong_execution(self):
        for key, value in [('suite', 'other'), ('layer', 'windows'), ('host', 'nt'), ('productionJarSha256', 'f' * 64)]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('status', 'PASS'), ('kind', 'other'), ('target', 'aarch64'), ('role', 'pie'),
                ('historicalComparisonMeasured', True), ('protectedUnchanged', False), ('validators', [])]:
            self.reject(lambda r, e: e.update({key: value}))
        self.reject(lambda r, e: r['sessions'].pop())
        self.reject(lambda r, e: r['sessions'].reverse())
        self.reject(lambda r, e: r.update(launcherInvocations=[{}]))

    def test_harness_and_input_preservation(self):
        for kind in ('returns', 'parameters'):
            for source in admission.sources(kind):
                self.reject(lambda r, e: e['harnessSha256'].pop(source), (kind,))
                self.reject(lambda r, e: e['harnessSha256'].update({source: 'f' * 64}), (kind,))
        self.reject(lambda r, e: e['protectedAfter'].update({'/new': 'f' * 64}))
        self.reject(lambda r, e: e.update(inputSha256='f' * 64))

    def test_saved_database_and_model_preservation(self):
        self.reject(lambda r, e: e['projectAfter'].clear())
        self.reject(lambda r, e: e['projectAfter'].update({next(iter(e['projectAfter'])): 'f' * 64}))
        self.reject(lambda r, e: e.update(projectBackupChanges=['concealed']))
        self.reject(lambda r, e: e['modelHashes'].__setitem__(1, 'a' * 64))
        for kind in ('returns', 'parameters'):
            record, evidence = fixture(kind)
            name = admission.PROFILES[kind][1] + '.rep/idata/~journal.bak'
            evidence['projectBefore'][name] = '3' * 64
            evidence['projectBackupChanges'] = [name]
            admission.oracle(record, evidence)

    def test_failed_or_nondeterministic_exports(self):
        self.reject(lambda r, e: e['reports'].reverse())
        self.reject(lambda r, e: e['reports'][0]['counts'].update(functionsFailed=1))
        self.reject(lambda r, e: e['reports'][0]['counts'].update(functionsFailed=False))
        for key in ('inputSha256', 'sourceSha256', 'outputSha256'):
            self.reject(lambda r, e: e['reports'][1]['artifacts'].update({key: 'f' * 64}))
        self.reject(lambda r, e: e['strict'].update(status='SKIPPED'))
        self.reject(lambda r, e: e['strict'].update(uncorroborated_errors=1))
        self.reject(lambda r, e: e['strict'].update(uncorroborated_errors=False))

    def test_curated_precedence_and_inferred_types(self):
        self.reject(lambda r, e: e['functions'].pop())
        self.reject(lambda r, e: e['functionDIEs'].pop())
        self.reject(lambda r, e: next(x for x in e['functionDIEs'] if not x['name'].startswith('curated_'))['attributes'].append('DW_AT_prototyped'))
        self.reject(lambda r, e: next(x for x in e['functionDIEs'] if x['name'].startswith('curated_'))['attributes'].clear())
        self.reject(lambda r, e: next(x for x in e['functions'] if x['name'] == 'recovered_unsigned').update(recoveredBytes=4), ('returns',))
        self.reject(lambda r, e: next(x for x in e['functions'] if x['name'] == 'curated_pointer').update(returnSource='DEFAULT'), ('returns',))
        self.reject(lambda r, e: next(x for x in e['functions'] if x['name'] == 'inferred_scalar').update(customStorage=True), ('parameters',))
        self.reject(lambda r, e: next(x for x in e['functions'] if x['name'] == 'inferred_pointer')['parameters'][0].update(type='void *'), ('parameters',))

    def test_parameter_omissions_and_unknown_lists(self):
        for attribute in ('DW_AT_location', 'DW_AT_const_value', 'DW_AT_artificial'):
            self.reject(lambda r, e: next(x for x in e['functionDIEs'] if x['name'] == 'inferred_scalar')['parameters'][0]['attributes'].append(attribute), ('parameters',))
        self.reject(lambda r, e: next(x for x in e['functionDIEs'] if x['name'] == 'unresolved_pair')['parameters'].append({}), ('parameters',))
        self.reject(lambda r, e: e['reports'][0]['omittedLocations'].clear(), ('parameters',))
        self.reject(lambda r, e: e['reports'][1]['omittedLocations'][0].update(reason='OTHER'), ('parameters',))

    def test_runtime_reference_values_and_stepping(self):
        self.reject(lambda r, e: e['gdb'].reverse())
        self.reject(lambda r, e: e['gdb'].pop())
        for index in (0, 1):
            for key, value in [('status', 'SKIPPED'), ('exitCodes', [1]), ('exitCodes', [False]), ('sourceSteps', [])]:
                self.reject(lambda r, e: e['gdb'][index].update({key: value}))
            self.reject(lambda r, e: next(iter(e['gdb'][index]['functions'].values())).update(returnedValue=0))
        self.reject(lambda r, e: e['gdb'][1]['functions']['recovered_unsigned'].update(returnBytes=4), ('returns',))
        self.reject(lambda r, e: e['gdb'][1]['functions']['inferred_scalar'].update(argument=-123), ('parameters',))
        self.reject(lambda r, e: e['gdb'][0]['functions']['inferred_scalar'].update(argument=0), ('parameters',))


if __name__ == '__main__':
    unittest.main()

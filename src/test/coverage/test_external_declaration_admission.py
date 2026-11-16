"""Metadata rejection controls; these synthetic receipts are not execution evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('external_admission', Path(__file__).with_name('external-declaration-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture():
    def parameter(name, carrier=False):
        return {'name': name, 'returnStorage': carrier, 'artificial': carrier, 'objectPointer': False}

    declarations = [
        {'name': '<EXTERNAL>::imported_adjust', 'parameters': [parameter('value')], 'variadic': False, 'noReturn': False},
        {'name': 'analyst_library::external_aggregate', 'parameters': [parameter('__return_storage_ptr__', True), parameter('seed')],
            'variadic': False, 'noReturn': False},
        {'name': 'analyst_library::never_called', 'parameters': [parameter('cookie')], 'variadic': True, 'noReturn': True},
    ]
    dies = []
    for row in declarations:
        row['signatureSource'] = 'USER_DEFINED'
        attributes = ['DW_AT_name', 'DW_AT_type', 'DW_AT_declaration', 'DW_AT_external', 'DW_AT_prototyped']
        if row['noReturn']:
            attributes.append('DW_AT_noreturn')
        children = [{'tag': 'DW_TAG_variable' if p['returnStorage'] else 'DW_TAG_formal_parameter',
            'name': p['name'], 'artificial': p['artificial'],
            'attributes': ['DW_AT_name', 'DW_AT_type'] + (['DW_AT_artificial'] if p['artificial'] else [])}
            for p in row['parameters']]
        if row['variadic']:
            children.append({'tag': 'DW_TAG_unspecified_parameters', 'name': '', 'artificial': False, 'attributes': []})
        dies.append({'name': row['name'], 'noReturn': row['noReturn'], 'attributes': attributes, 'children': children})
    protected = {'/repo/' + name: {'sha256': 'b' * 64} for name in admission.SOURCES}
    protected.update({'/case/decl.stripped': {'sha256': 'c' * 64}, '/module/lib/GhidraDwarfForge.jar': {'sha256': 'a' * 64}})
    artifacts = {'inputSha256': 'c' * 64, 'outputSha256': 'd' * 64, 'sourceSha256': 'e' * 64}
    project = {'ExternalDeclarations.gpr': '1' * 64,
        'ExternalDeclarations.rep/idata/00/~00000000.db/db.1.gbf': '2' * 64}
    evidence = {'status': 'PASS_EXTERNAL_DECLARATIONS_MEASUREMENT', 'target': 'x86_64', 'role': 'exec',
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'harnessSha256': {name: 'b' * 64 for name in admission.SOURCES}, 'protectedUnchanged': True,
        'protected': protected, 'strict': {'status': 'PASS', 'uncorroborated_errors': 0},
        'modelHashes': ['f' * 64] * 2, 'phaseOutputs': [['d' * 64, 'e' * 64] for _ in range(2)],
        'projectBefore': project, 'projectAfter': copy.deepcopy(project), 'projectMetadataChanges': {},
        'phaseReports': [{'phase': phase, 'functionsFailed': 0, 'artifacts': copy.deepcopy(artifacts)} for phase in ('curate', 'reopen')],
        'compilerPrototype': {'returnBytes': 8, 'argumentBytes': [4], 'signed': True},
        'declarations': declarations, 'declarationDIEs': dies,
        'gdb': [{'status': 'PASS', 'variant': variant, 'observed': 12, 'exitCodes': [0],
            'unlocatedDeclarations': ['imported_adjust'] if variant == 'compiler' else [row['name'] for row in declarations],
            'sourceSteps': ['next', 'step'], 'source': 'source listing', 'prototype': 'type = int (void)'}
            for variant in ('compiler', 'forge')]}
    record = {'suite': 'external-declarations', 'layer': 'headless', 'host': 'posix', 'productionJarSha256': 'a' * 64,
        'sessions': [{'label': label} for label in ('export-curate', 'export-reopen')]}
    return record, evidence


class Admission(unittest.TestCase):
    def test_complete_and_missing_cohort(self):
        case = admission.oracle(*fixture())
        admission.cohort([case])
        for cases in ([], [case, case], [('aarch64', 'exec')], [('x86_64', 'pie')]):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                admission.cohort(cases)

    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_profiles_and_required_sources(self):
        for key, value in [('suite', 'other'), ('layer', 'native-java'), ('host', 'nt')]:
            with self.subTest(key=key):
                self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('target', 'aarch64'), ('role', 'pie'), ('status', 'PASS'), ('protectedUnchanged', False),
                ('validators', ['llvm-dwarfdump'])]:
            with self.subTest(key=key):
                self.reject(lambda r, e: e.update({key: value}))
        for source in admission.SOURCES:
            with self.subTest(source=source):
                self.reject(lambda r, e: e['harnessSha256'].pop(source))
                self.reject(lambda r, e: e['protected'].pop('/repo/' + source))
                self.reject(lambda r, e: e['harnessSha256'].update({source: '1' * 64}))

    def test_missing_reordered_or_unmeasured_sessions(self):
        for sessions in ([], [{'label': 'export-curate'}], [{'label': 'export-reopen'}, {'label': 'export-curate'}],
                [{'label': 'export-curate'}, {'label': 'export-curate'}]):
            self.reject(lambda r, e: r.update(sessions=sessions))
        for key in ('launcherInvocations', 'unmeasuredForcedHalts'):
            self.reject(lambda r, e: r.update({key: [{}]}))

    def test_models_artifacts_and_real_validation(self):
        self.reject(lambda r, e: e.update(modelHashes=['1' * 64, '2' * 64]))
        self.reject(lambda r, e: e['phaseOutputs'][1].__setitem__(0, '1' * 64))
        self.reject(lambda r, e: e['phaseReports'].reverse())
        self.reject(lambda r, e: e['phaseReports'][0].update(functionsFailed=1))
        self.reject(lambda r, e: e['phaseReports'][0].update(functionsFailed=False))
        for key in ('inputSha256', 'outputSha256', 'sourceSha256'):
            self.reject(lambda r, e: e['phaseReports'][0]['artifacts'].update({key: '1' * 64}))
        self.reject(lambda r, e: r.update(productionJarSha256='1' * 64))
        self.reject(lambda r, e: e['strict'].update(status='SKIPPED'))
        self.reject(lambda r, e: e['strict'].update(uncorroborated_errors=1))
        self.reject(lambda r, e: e['strict'].update(uncorroborated_errors=False))
        self.reject(lambda r, e: e['compilerPrototype'].update(returnBytes=4))
        self.reject(lambda r, e: e['compilerPrototype'].update(signed=1))

    def test_only_disclosed_project_bookkeeping_can_change(self):
        record, evidence = fixture()
        name = 'ExternalDeclarations.rep/idata/~index.bak'
        evidence['projectBefore'][name] = '3' * 64
        evidence['projectMetadataChanges'][name] = ['3' * 64, None]
        admission.oracle(record, evidence)
        self.reject(lambda r, e: e['projectAfter'].update({'ExternalDeclarations.gpr': '3' * 64}))
        def concealed(r, e):
            name = 'ExternalDeclarations.rep/idata/00/~00000000.db/db.1.gbf'
            e['projectAfter'][name] = '3' * 64
            e['projectMetadataChanges'][name] = ['2' * 64, '3' * 64]
        self.reject(concealed)
        self.reject(lambda r, e: e['projectMetadataChanges'].update({name: [None, '3' * 64]}))
        self.reject(lambda r, e: e.update(projectBefore={}, projectAfter={}))

    def test_declarations_cannot_gain_runtime_locations(self):
        for attribute in admission.UNLOCATED:
            self.reject(lambda r, e: e['declarationDIEs'][0]['attributes'].append(attribute))
        for attribute in ('DW_AT_location', 'DW_AT_const_value'):
            self.reject(lambda r, e: e['declarationDIEs'][0]['children'][0]['attributes'].append(attribute))
        for field in ('address', 'locals'):
            self.reject(lambda r, e: e['declarations'][0].update({field: 4096}))
        self.reject(lambda r, e: e['declarations'][0].update(signatureSource='ANALYSIS'))
        self.reject(lambda r, e: e['declarationDIEs'].pop())
        self.reject(lambda r, e: e['declarations'].append(copy.deepcopy(e['declarations'][0])))

    def test_variadic_return_and_parameter_inventory(self):
        self.reject(lambda r, e: e['declarationDIEs'][2]['children'].pop())
        self.reject(lambda r, e: e['declarationDIEs'][2].update(noReturn=False))
        self.reject(lambda r, e: e['declarations'][2].update(noReturn=False, variadic=False))
        self.reject(lambda r, e: e['declarations'][0].update(variadic=0))
        self.reject(lambda r, e: e['declarationDIEs'][1]['children'][0].update(tag='DW_TAG_formal_parameter'))
        self.reject(lambda r, e: e['declarations'][1]['parameters'][0].update(returnStorage=False))
        self.reject(lambda r, e: e['declarations'][0]['parameters'][0].update(artificial=0))
        self.reject(lambda r, e: e['declarationDIEs'][1]['children'][0].update(artificial=False))
        self.reject(lambda r, e: e['declarationDIEs'][1]['children'][0]['attributes'].remove('DW_AT_artificial'))

    def test_debugger_reference_runtime_and_source_required(self):
        self.reject(lambda r, e: e['gdb'].pop())
        self.reject(lambda r, e: e['gdb'].reverse())
        for index in (0, 1):
            for field, value in [('status', 'SKIPPED'), ('observed', 13), ('exitCodes', [1]),
                    ('exitCodes', [False]), ('source', ''), ('prototype', ''), ('sourceSteps', []),
                    ('unlocatedDeclarations', [])]:
                with self.subTest(index=index, field=field):
                    self.reject(lambda r, e: e['gdb'][index].update({field: value}))


if __name__ == '__main__':
    unittest.main()

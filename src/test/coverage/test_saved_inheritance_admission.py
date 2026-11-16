"""Synthetic receipt corruption tests; not debugger or coverage evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location('saved_inheritance', Path(__file__).with_name('saved-inheritance-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(role='exec', variant='valid', rebased=False, thunks=True):
    label = 'x86_64-' + role
    record = {'suite': 'saved-inheritance', 'layer': 'headless', 'host': 'posix',
        'sessions': [{'label': label + '-' + phase, 'session': phase} for phase in ('curate', 'reopen')],
        'launcherInvocations': [{'label': label + '-reopen', 'status': 'ORACLE_PASSED', 'sessions': ['reopen']}]}
    compiler = {'status': 'PASS_REFERENCE_OBSERVATION', 'inheritedValues': dict(admission.VALUES),
        'dynamicTypes': dict(zip(admission.VARIABLES, (name + ' *' for name in admission.DYNAMIC))),
        'baseValues': {'single_base->base': 11, 'multiple_right->right': 17, 'diamond_base->root': 19},
        'offsets': {'multipleRight': 16, 'diamondBase': 32, 'diamondRight': 16},
        'queries': {'info vtbl *' + name: {'result': '[0]: function'} for name in admission.VARIABLES}}
    names = {mode: {variable: {'name': ('Recovered_' + name if variant == 'renamed'
        else 'Shared' if variant == 'duplicate' else name), 'size': 16, 'members': ['value']}
        for variable, name in zip(admission.VARIABLES, kinds)}
        for mode, kinds in (('static', admission.STATIC), ('dynamic', admission.DYNAMIC))}
    actual = copy.deepcopy(compiler)
    if variant != 'valid':
        negative = variant in ('missing', 'stale', 'conflict')
        chosen = names['static' if negative else 'dynamic']
        actual = {'status': 'PASS_STATIC_NAME_CONTROL' if negative else 'PASS_RECOVERED_VTABLE_NAMES',
            'dynamicTypes': {key: row['name'] + ' *' for key, row in chosen.items()},
            'layouts': {key: {'size': row['size'], 'members': row['members']} for key, row in chosen.items()}}
    rows = [{'name': name, 'kind': kind, 'adjustment': -16, 'steps': 2, 'return': value}
        for name, kind, value in zip(('recovered_multiple_adjustor', 'recovered_diamond_virtual_adjustor',
            'recovered_diamond_right_adjustor'), ('fixed', 'virtual', 'fixed'), (46, 56, 68))]
    evidence = {'status': 'PASS_SAVED_INHERITANCE_MEASUREMENT', 'target': 'x86_64', 'role': role,
        'variant': variant, 'rebased': rebased, 'adjustmentThunksRequested': thunks,
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'debugger': 'GDB batch: dynamic types, inherited values, vtables and exit 0',
        'harnessSha256': {name: 'a' * 64 for name in admission.SOURCES}, 'protected': {'reference.elf': 'b' * 64},
        'projectBefore': {'Inheritance.rep/idata/file': 'c' * 64},
        'projectAfter': {'Inheritance.rep/idata/file': 'c' * 64},
        'projectMetadataChanges': {}, 'savedProgramUnchanged': True,
        'inputSha256': 'd' * 64, 'inputAfterSha256': 'd' * 64,
        'phaseOutputs': [['e' * 64, 'f' * 64], ['e' * 64, 'f' * 64]],
        'sidecarSha256': 'e' * 64, 'sourceSha256': 'f' * 64,
        'phaseReports': [{'phase': phase, 'status': 'SUCCESS', 'functionsFailed': 0} for phase in ('curate', 'reopen')],
        'configuration': {'counts': {'classes': 11, 'declarations': 1, 'bases': 8, 'virtual_methods': 15, 'vtables': 7},
            'actions': [False, True, False], 'selectionSha256': 'a' * 64, 'recordSnapshotSha256': 'b' * 64},
        'modelCounts': {'classes': 11, 'bases': 8, 'methods': 15}, 'tableCount': 7,
        'observed': actual, 'compilerObservation': compiler, 'expectedNames': names,
        'adjustmentThunks': [{'status': 'PASS_ADJUSTMENT_THUNKS', 'thunks': copy.deepcopy(rows),
            'bias': 0x100000 if role.startswith('pie') else 0,
            'callRestrictions': [] if index == 0 else ['warning: does not follow the target calling convention'] * 3}
            for index in range(2)] if thunks else [],
        'thunkEvidence': {'target': 'x86_64', 'checkpoint': 1000,
            'thunks': [{**row, 'address': 2000 + index * 10, 'size': 8, 'target': 3000 + index * 10}
                for index, row in enumerate(rows)]} if thunks else None}
    return record, evidence


class SavedInheritance(unittest.TestCase):
    def test_complete_cohort(self):
        fixtures = [fixture(role) for role in admission.ROLES]
        fixtures += [fixture(role, rebased=True) for role in ('pie', 'pie-no-rtti')]
        fixtures += [fixture(role, variant, True, False) for role in admission.ROLES for variant in admission.VARIANTS]
        cases = [admission.oracle(*value) for value in fixtures]
        admission.cohort(cases)
        self.assertEqual(len(cases), 34)
        for index in range(len(cases)):
            with self.assertRaises(ValueError):
                admission.cohort(cases[:index] + cases[index + 1:])
        with self.assertRaises(ValueError):
            admission.cohort(cases + cases[:1])

    def test_missing_evidence_and_wrong_profiles(self):
        record, evidence = fixture()
        for key in evidence:
            if key == 'expectedNames':
                continue  # Only needed by name/control variants.
            changed = copy.deepcopy(evidence)
            del changed[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission.oracle(record, changed)
        for key, value in [('host', 'nt'), ('layer', 'native-java'), ('suite', 'inheritance-producer'),
                ('sessions', []), ('sessions', record['sessions'][::-1]), ('launcherInvocations', [])]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission.oracle({**record, key: value}, evidence)
        for key, value in [('rebased', 1), ('adjustmentThunksRequested', 1), ('tableCount', True),
                ('target', 'arm32'), ('role', 'shared'), ('variant', 'unknown'), ('harnessSha256', {})]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission.oracle(record, {**evidence, key: value})

    def test_preservation_sessions_and_configuration(self):
        record, evidence = fixture()
        cases = []
        for key in ('inputAfterSha256', 'sourceSha256', 'sidecarSha256'):
            changed = copy.deepcopy(evidence); changed[key] = '0' * 64; cases.append(changed)
        for key in ('projectBefore', 'projectAfter'):
            changed = copy.deepcopy(evidence); changed[key]['extra'] = '0' * 64; cases.append(changed)
        for field in evidence['configuration']['counts']:
            changed = copy.deepcopy(evidence); changed['configuration']['counts'][field] -= 1; cases.append(changed)
        for actions in ([True, True, False], [False, False, False], [0, 1, 0]):
            changed = copy.deepcopy(evidence); changed['configuration']['actions'] = actions; cases.append(changed)
        changed = copy.deepcopy(evidence); changed['phaseOutputs'][1][0] = '0' * 64; cases.append(changed)
        changed = copy.deepcopy(evidence); changed['phaseReports'][1]['functionsFailed'] = 1; cases.append(changed)
        for changed in cases:
            with self.assertRaises(ValueError):
                admission.oracle(record, changed)
        changed = copy.deepcopy(record); changed['launcherInvocations'][0]['sessions'] = ['curate']
        with self.assertRaises(ValueError):
            admission.oracle(changed, evidence)

    def test_debugger_and_thunk_corruption(self):
        record, evidence = fixture('pie', rebased=True)
        cases = []
        for field in ('dynamicTypes', 'baseValues', 'offsets', 'inheritedValues', 'queries'):
            changed = copy.deepcopy(evidence); changed['observed'][field] = {}; cases.append(changed)
        for index in range(2):
            for key, value in [('return', 0), ('steps', 0), ('adjustment', 0), ('name', 'wrong')]:
                changed = copy.deepcopy(evidence); changed['adjustmentThunks'][index]['thunks'][0][key] = value; cases.append(changed)
            changed = copy.deepcopy(evidence); changed['adjustmentThunks'][index]['bias'] = 0; cases.append(changed)
        changed = copy.deepcopy(evidence); changed['adjustmentThunks'][1]['callRestrictions'] = []; cases.append(changed)
        for changed in cases:
            with self.assertRaises(ValueError):
                admission.oracle(record, changed)

    def test_rejected_name_evidence_cannot_be_promoted(self):
        for variant in admission.VARIANTS:
            record, evidence = fixture(variant=variant, rebased=True, thunks=False)
            admission.oracle(record, evidence)
            for field in ('dynamicTypes', 'layouts'):
                changed = copy.deepcopy(evidence); changed['observed'][field] = {}
                with self.assertRaises(ValueError):
                    admission.oracle(record, changed)
            changed = copy.deepcopy(evidence); changed['expectedNames'] = {}
            with self.assertRaises(ValueError):
                admission.oracle(record, changed)


if __name__ == '__main__':
    unittest.main()

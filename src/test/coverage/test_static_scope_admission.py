#!/usr/bin/env python3
"""Reject incomplete or semantically incorrect static-scope measurement receipts."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('static_admission', Path(__file__).with_name('static-scope-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(suite, layer='headless', role='exec'):
    scopes = ('root', 'outer', 'inner', 'sibling', 'other', 'global')
    objects = {name: 0x2000 + i * 4 for i, name in enumerate(scopes)}
    markers = ('root_live', 'outer_begin', 'inner_begin', 'inner_end', 'outer_end',
        'sibling_begin', 'sibling_end', 'other_live', 'global_live')
    labels = {name: 0x1000 + i * 8 for i, name in enumerate(markers)}
    values = {'root': 11, 'outer': 21, 'inner': 31, 'sibling': 41, 'other': 51, 'global': 101}
    normal = ('root', 'outer', 'inner', 'outer', 'root', 'sibling', 'root', 'other', 'global')

    def observed(mode):
        expected = {
            'stale': ('root', 'outer', 'outer', 'outer', 'root', 'sibling', 'root', 'other', 'global'),
            'conflict': ('root', 'outer', 'outer', 'outer', 'root', 'root', 'root', 'other', 'global'),
            'coalesced': ('root', 'root', 'root', 'root', 'root', 'root', 'root', 'other', 'global'),
            'failed': ('global',) * 7 + ('other', 'global'),
            'memory-stale': ('global',) * 7 + ('other', 'global'),
            'memory-failed': ('global',) * 7 + ('other', 'global'),
            'inferred-stale': normal[:7] + ('global', 'global'),
            'inferred-namespace': normal[:7] + ('global', 'global'),
            'inferred-overlap': normal[:7] + ('global', 'global'),
            'memory-overlay': normal[:7] + ('global', 'global'),
            'memory-mapped': normal[:7] + ('global', 'global'),
        }.get(mode, normal)
        bias = 0 if role == 'exec' else 0x400000
        return [{'marker': marker, 'scope': scope, 'value': values[scope], 'address': objects[scope],
            'runtimePc': labels[marker] + bias, 'bias': bias} for marker, scope in zip(markers, expected)]

    names = ('lexical-statics-export.py', 'lexical-statics-controls.py', 'recovered-statics-export.py',
        'lexical-statics-gdb.py', 'lexical-statics-gdb.sh', 'integration_coverage.py', 'static_coverage.py',
        'check-lexical-statics.py', 'check-dwarfdump.py')
    evidence = {'target': 'x86_64', 'role': role, 'protected': {'original.elf': 'a' * 64},
        'harnessSha256': {'src/test/integration/' + name: 'b' * 64 for name in names},
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'debugger': 'GDB batch: values, types, addresses, lexical lookup, instruction stepping and exit 0',
        'compilerObjects': objects, 'labels': labels, 'compilerObservations': observed('compiler')}
    if suite == 'lexical-statics':
        evidence.update(status='PASS_LEXICAL_STATICS_MEASUREMENT', oracleStatus='LEXICAL_STATICS_PASS',
            javaRuntime=21, controls=True, recovered=True, outputPair=['c' * 64, 'd' * 64], observations=9,
            debuggerObservations={name: observed(name) for name in ('isolated', 'forge')},
            measurement={'directAnalyzerSessions': 3, 'directNativeSessions': 1,
                'measuredNestedSuites': ['lexical-statics-controls', 'recovered-statics-positive', 'recovered-statics-controls']})
        labels = ['isolated-producer'] if layer == 'native-java' else ['import', 'export-first', 'export-repeat']
    else:
        scope = suite == 'lexical-statics-controls'
        controls = scope or suite == 'recovered-statics-controls'
        modes = ['stale', 'conflict', 'coalesced', 'failed'] if scope else (
            ['inferred-stale', 'inferred-namespace', 'inferred-overlap', 'inferred-curated',
                'memory-stale', 'memory-failed', 'memory-overlay', 'memory-mapped']
            if controls else ['inferred', 'memory'])
        evidence.update(status='PASS_STATIC_SCOPE_CONTROLS_MEASUREMENT' if scope else 'PASS_RECOVERED_STATICS_MEASUREMENT',
            oracleStatus='STATIC_SCOPE_CONTROLS_PASS' if scope else (
                'RECOVERED_STATICS_CONTROLS_PASS' if controls else 'RECOVERED_STATICS_POSITIVE_PASS'),
            cancelledExports=int(controls))
        if scope:
            evidence['exports'] = 9
        evidence['controls' if scope else 'cases'] = [{'mode': mode,
            'outputPair' if scope else 'pair': ['c' * 64, 'd' * 64], 'observations': observed(mode)} for mode in modes]
        labels = [mode + ('-export-' if scope else '-') + iteration for mode in modes for iteration in ('first', 'repeat')]
        if controls:
            labels += ['cancel-import', 'cancel-export']
        if scope:
            labels += ['baseline-reopen']
        evidence['measurement'] = {'directAnalyzerSessions': len(labels), 'modes': modes}
    return {'suite': suite, 'layer': layer, 'host': 'posix', 'sessions': [{'label': label} for label in labels]}, evidence


class Admission(unittest.TestCase):
    def profiles(self):
        return [(suite, layer, role) for role in ('exec', 'pie', 'pie-rebased') for suite, layer in (
            ('lexical-statics', 'headless'), ('lexical-statics', 'native-java'),
            ('lexical-statics-controls', 'headless'), ('recovered-statics-positive', 'headless'),
            ('recovered-statics-controls', 'headless'))]

    def test_complete_cohort(self):
        cases = [admission.oracle(*fixture(*profile)) for profile in self.profiles()]
        admission.cohort(cases)
        for i in range(len(cases)):
            with self.subTest(missing=i), self.assertRaises(ValueError):
                admission.cohort(cases[:i] + cases[i + 1:])
        with self.assertRaises(ValueError):
            admission.cohort(cases + cases[:1])
        with self.assertRaises(ValueError):
            admission.cohort(cases[:-1] + cases[:1])
        admission.cohort(cases[:5], roles=('exec',))

    def test_missing_reordered_and_duplicate_sessions(self):
        for profile in self.profiles():
            record, evidence = fixture(*profile)
            for i in range(len(record['sessions'])):
                changed = copy.deepcopy(record)
                changed['sessions'].pop(i)
                with self.subTest(profile=profile, missing=i), self.assertRaises(ValueError):
                    admission.oracle(changed, evidence)
            for rows in (record['sessions'] + record['sessions'][:1], list(reversed(record['sessions']))):
                if rows == record['sessions']:
                    continue
                with self.subTest(profile=profile, rows=rows), self.assertRaises(ValueError):
                    admission.oracle({**record, 'sessions': rows}, evidence)

    def test_debugger_boundaries(self):
        for profile in self.profiles():
            record, evidence = fixture(*profile)
            samples = [evidence['compilerObservations']]
            if profile[0] == 'lexical-statics':
                samples += list(evidence['debuggerObservations'].values())
            else:
                samples += [row['observations'] for row in evidence['controls' if profile[0] == 'lexical-statics-controls' else 'cases']]
            for rows in samples:
                for i, row in enumerate(rows):
                    for key, value in (('scope', 'missing'), ('marker', 'missing'), ('value', -1),
                            ('address', -1), ('runtimePc', -1), ('bias', -1), ('value', True)):
                        old = row[key]
                        row[key] = value
                        with self.subTest(profile=profile, boundary=i, key=key), self.assertRaises(ValueError):
                            admission.oracle(record, evidence)
                        row[key] = old
                last = rows.pop()
                with self.assertRaises(ValueError):
                    admission.oracle(record, evidence)
                rows.append(last)

    def test_common_evidence(self):
        record, evidence = fixture('lexical-statics')
        for key, value in (('target', 'aarch64'), ('role', 'unknown'), ('validators', ['readelf']),
                ('debugger', 'PASS'), ('protected', {}), ('harnessSha256', {}), ('compilerObjects', {}),
                ('labels', {}), ('status', 'PASS'), ('oracleStatus', 'PASS'), ('javaRuntime', 25),
                ('controls', False), ('recovered', False), ('outputPair', ['c' * 64]),
                ('observations', 8), ('debuggerObservations', {}), ('measurement', {})):
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission.oracle(record, {**evidence, key: value})
        for key, value in (('host', 'nt'), ('layer', 'windows'), ('suite', 'wrong')):
            with self.subTest(key=key), self.assertRaises(ValueError):
                admission.oracle({**record, key: value}, evidence)
        for name in evidence['harnessSha256']:
            reduced = dict(evidence['harnessSha256'])
            del reduced[name]
            with self.subTest(source=name), self.assertRaises(ValueError):
                admission.oracle(record, {**evidence, 'harnessSha256': reduced})
        evidence['measurement']['directNativeSessions'] = True
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_controls_cannot_disappear(self):
        for suite in ('lexical-statics-controls', 'recovered-statics-positive', 'recovered-statics-controls'):
            record, evidence = fixture(suite)
            for value in (None, True, 7):
                with self.subTest(suite=suite, value=value), self.assertRaises(ValueError):
                    admission.oracle(record, {**evidence, 'cancelledExports': value})
            rows_key = 'controls' if suite == 'lexical-statics-controls' else 'cases'
            for i in range(len(evidence[rows_key])):
                changed = copy.deepcopy(evidence)
                changed[rows_key].pop(i)
                with self.subTest(suite=suite, mode=i), self.assertRaises(ValueError):
                    admission.oracle(record, changed)
            changed = copy.deepcopy(evidence)
            changed[rows_key][0]['outputPair' if suite == 'lexical-statics-controls' else 'pair'] = []
            with self.assertRaises(ValueError):
                admission.oracle(record, changed)

    def test_unsupported_mapping_cannot_claim_the_original_object(self):
        for mode in ('memory-overlay', 'memory-mapped'):
            record, evidence = fixture('recovered-statics-controls')
            row = next(case for case in evidence['cases'] if case['mode'] == mode)['observations'][7]
            self.assertEqual(row['marker'], 'other_live')
            self.assertEqual(row['scope'], 'global')
            row.update(scope='other', value=51, address=evidence['compilerObjects']['other'])
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                admission.oracle(record, evidence)


if __name__ == '__main__':
    unittest.main()

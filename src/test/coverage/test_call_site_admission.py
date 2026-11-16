"""Synthetic admission controls, not evidence that a debugger or exporter ran."""
import copy
from pathlib import Path
import runpy
import unittest


admission = runpy.run_path(str(Path(__file__).with_name('call-site-admission.py')))
SINKS = (11, 23, 34, 36, 43, 53, 60, 70)
INTERMEDIATE = (('cs_normal',), ('cs_tail_middle', 'cs_tail_first'), (), (),
    ('cs_recursive',) * 4, ('cs_tail_recursive',), (), ('cs_forward',))
ENTRIES = ((11, 10), (23, 21, 20), (None,), (None,), (43, 43, 42, 41, 40), (53, 50), (None,), (70, 70))


def observation(scenario):
    names = ('cs_checkpoint', 'cs_leaf', *INTERMEDIATE[scenario], 'cs_driver', 'main')
    frames = []
    for index, name in enumerate(names):
        tail = 2 <= index < len(names) - 2 and (scenario in (1, 5, 7) or scenario == 4 and index == 2)
        frame = {'name': name, 'tail': tail, 'info': 'tail call frame' if tail else 'normal frame'}
        if 1 <= index < len(names) - 2:
            value = ENTRIES[scenario][index - 1]
            frame['entryValue'] = {'available': value is not None, 'value': value}
            frame['value'] = {'available': False}
        if name in ('cs_recursive', 'cs_tail_recursive'):
            frame['entryDepth'] = {'available': True, 'value': index - 2 if scenario == 4 else 3}
        frames.append(frame)
    return {'status': 'OBSERVED', 'frames': frames, 'sink': SINKS[scenario], 'exitCode': 0}


def fixture(role='exec'):
    record = {'suite': 'call-site-packaged', 'layer': 'headless', 'productionJarSha256': 'a' * 64,
        'sessions': [{'label': label} for label in ('original-headless', 'rebased-headless')]}
    saved = {'program.db': 'b' * 64}
    compiler = {'status': 'PASS_COMPILER_REFERENCE', 'target': 'x86_64', 'role': role,
        'preservedSha256': {'fixture/input': 'c' * 64}, 'runtime': []}
    for mode in ('compiler', 'absent'):
        for scenario in range(8):
            observed = observation(scenario)
            frames = observed['frames']
            if mode == 'absent':
                names = ['cs_checkpoint', 'cs_leaf', *(['cs_normal'] if scenario == 0 else
                    ['cs_recursive'] * 3 if scenario == 4 else []), 'cs_driver', 'main']
                tails, entries = [], []
            else:
                names = [frame['name'] for frame in frames]
                tails = [frame['name'] for frame in frames if frame['tail']]
                entries = [frame['entryValue'] for frame in frames[1:-2]]
                if scenario == 4:
                    entries[0] = {'available': False}
            compiler['runtime'].append({'mode': mode, 'scenario': scenario, 'frames': names, 'tailFrames': tails,
                'entryValues': entries, 'runtimeBias': '0x100000' if role == 'pie' else '0x0',
                'sink': SINKS[scenario], 'exitCode': 0})
    runtime = {'status': 'PASS_RECOVERED_RUNTIME', 'target': 'x86_64', 'role': role, 'failures': [],
        'sessions': [{'variant': view, 'scenario': scenario, 'status': 'PASS', 'observation': observation(scenario)}
            for view in ('original', 'rebased') for scenario in range(8)]}
    export = {'status': 'PASS_PACKAGED_CALL_SITE_EXPORT', 'readOnlyProject': True, 'correctedDriverBody': True,
        'analystNamedThunks': ['cs_indirect', 'cs_forward'], 'inputSha256': 'c' * 64, 'jarSha256': 'a' * 64,
        'scriptSha256': 'd' * 64, 'consumerSha256': 'e' * 64, 'producerSha256': 'f' * 64,
        'sidecarSha256': '1' * 64, 'sourceSha256': '2' * 64, 'rebaseDelta': 0}
    evidence = {'status': 'PASS_PACKAGED_CALL_SITES', 'target': 'x86_64', 'role': role, 'failures': [],
        'probeReport': 'switch-plan', 'measurement': {'directAnalyzerSessions': 2, 'exportsPerSession': 2,
            'prerequisitesMeasured': False}, 'packageSha256': '3' * 64, 'inputSha256': 'c' * 64,
        'savedProgramSha256': saved, 'testedSources': {'fixture.py': '4' * 64},
        'installedInventory': {'lib/GhidraDwarfForge.jar': 'a' * 64, 'ghidra_scripts/GhidraDwarfForge.java': 'd' * 64,
            'os/linux_x86_64/libdwarf.so.2': 'e' * 64, 'os/linux_x86_64/libdwarfp.so.2': 'f' * 64},
        'exports': [export, {**export, 'rebaseDelta': 0x400000}],
        'sessions': [{'view': row['variant'], 'scenario': row['scenario'], 'status': row['status'],
            'observation': copy.deepcopy(row['observation'])} for row in runtime['sessions']],
        'prerequisites': {'compiler': compiler, 'runtime': runtime,
            'structural': {'status': 'PASS_RECOVERED_PLAN_STRUCTURAL', 'target': 'x86_64', 'role': role,
                'inputSha256': 'c' * 64, 'savedProgramSha256': copy.deepcopy(saved)}}}
    return record, evidence


class CallSiteAdmission(unittest.TestCase):
    def test_both_elf_roles_required(self):
        cases = [admission['oracle'](*fixture(role)) for role in ('exec', 'pie')]
        admission['cohort'](cases)
        for missing in ([], cases[:1], cases[1:], ['exec', 'exec'], cases + cases):
            with self.subTest(cases=missing), self.assertRaises(ValueError):
                admission['cohort'](missing)

    def test_missing_or_incorrect_measurement_rejected(self):
        for field, value in [('status', 'PASS'), ('failures', ['bad export']), ('target', 'aarch64'),
                ('role', 'shared'), ('probeReport', 'forge-plan'), ('packageSha256', None),
                ('savedProgramSha256', {}), ('testedSources', {}), ('exports', []), ('installedInventory', {}),
                ('measurement', {'directAnalyzerSessions': 2, 'exportsPerSession': 2, 'prerequisitesMeasured': True})]:
            record, evidence = fixture()
            evidence[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                admission['oracle'](record, evidence)
        for field, value in [('suite', 'other'), ('layer', 'windows'), ('sessions', []),
                ('productionJarSha256', '9' * 64)]:
            record, evidence = fixture()
            record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                admission['oracle'](record, evidence)

    def test_export_provenance_and_rebase_rejected(self):
        for field, value in [('status', 'FAIL'), ('readOnlyProject', False), ('correctedDriverBody', False),
                ('analystNamedThunks', []), ('inputSha256', '9' * 64), ('jarSha256', '9' * 64),
                ('scriptSha256', '9' * 64), ('consumerSha256', '9' * 64), ('producerSha256', '9' * 64),
                ('sidecarSha256', None), ('sourceSha256', None), ('rebaseDelta', 0), ('rebaseDelta', float(0x400000))]:
            record, evidence = fixture()
            evidence['exports'][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                admission['oracle'](record, evidence)

    def test_failed_or_mismatched_prerequisites_rejected(self):
        for name in ('compiler', 'structural', 'runtime'):
            for field, value in [('status', 'FAIL'), ('role', 'pie'), ('target', 'aarch64')]:
                record, evidence = fixture()
                evidence['prerequisites'][name][field] = value
                with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                    admission['oracle'](record, evidence)
        for name, field, value in [('compiler', 'preservedSha256', {'fixture/input': '9' * 64}),
                ('structural', 'inputSha256', '9' * 64), ('structural', 'savedProgramSha256', {}),
                ('runtime', 'failures', ['failed']), ('compiler', 'runtime', [])]:
            record, evidence = fixture()
            evidence['prerequisites'][name][field] = value
            with self.subTest(name=name, field=field), self.assertRaises(ValueError):
                admission['oracle'](record, evidence)

    def test_each_debugger_scenario_required_in_both_exports_and_prerequisite(self):
        for prerequisite in (False, True):
            for index in range(16):
                for duplicate in (False, True):
                    record, evidence = fixture()
                    rows = evidence['prerequisites']['runtime']['sessions'] if prerequisite else evidence['sessions']
                    rows.pop(index)
                    if duplicate:
                        rows.append(copy.deepcopy(rows[0]))
                    with self.subTest(prerequisite=prerequisite, index=index, duplicate=duplicate), self.assertRaises(ValueError):
                        admission['oracle'](record, evidence)

    def test_runtime_values_frames_tails_and_recursive_depth_rejected(self):
        for prerequisite in (False, True):
            for mutation in ('status', 'sink', 'exit', 'frame', 'tail', 'info', 'entry', 'current', 'depth'):
                record, evidence = fixture()
                rows = evidence['prerequisites']['runtime']['sessions'] if prerequisite else evidence['sessions']
                observed = rows[4]['observation']
                if mutation == 'status': observed['status'] = 'FAIL'
                elif mutation == 'sink': observed['sink'] = 0
                elif mutation == 'exit': observed['exitCode'] = 1
                elif mutation == 'frame': observed['frames'][2]['name'] = 'wrong'
                elif mutation == 'tail': observed['frames'][2]['tail'] = False
                elif mutation == 'info': observed['frames'][2]['info'] = 'normal frame'
                elif mutation == 'entry': observed['frames'][1]['entryValue']['value'] = 0
                elif mutation == 'current': observed['frames'][1]['value'] = {'available': True, 'value': 0}
                elif mutation == 'depth': observed['frames'][2]['entryDepth']['value'] = 3
                with self.subTest(prerequisite=prerequisite, mutation=mutation), self.assertRaises(ValueError):
                    admission['oracle'](record, evidence)

    def test_compiler_and_absent_debug_controls_are_independent(self):
        for index in range(16):
            record, evidence = fixture()
            evidence['prerequisites']['compiler']['runtime'].pop(index)
            with self.subTest(index=index), self.assertRaises(ValueError):
                admission['oracle'](record, evidence)
        for index, field, value in [(0, 'frames', []), (1, 'tailFrames', []), (0, 'entryValues', []),
                (0, 'entryValues', [{'available': True, 'value': 0}, {'available': True, 'value': 10}]),
                (0, 'runtimeBias', '0x1'), (0, 'runtimeBias', 'invalid'), (8, 'tailFrames', ['cs_normal']),
                (8, 'sink', 0), (8, 'exitCode', 1)]:
            record, evidence = fixture()
            evidence['prerequisites']['compiler']['runtime'][index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                admission['oracle'](record, evidence)


if __name__ == '__main__':
    unittest.main()

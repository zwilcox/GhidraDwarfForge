"""Synthetic metadata controls, not debugger execution or production coverage."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile


spec = importlib.util.spec_from_file_location('admission', Path(__file__).with_name('stack-transition-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(target='x86_64', role='exec'):
    functions, raw = [], {}
    for shape, count in sorted(admission.SHAPES.items()):
        for width in (4, 8):
            name = 'transfer_' + shape + str(width * 8)
            entry = 100 + len(functions) * 100
            end = entry + 12
            step = 12 // count if shape in ('keep', 'respill') else 1
            locations = [[entry + i * step, entry + (i + 1) * step, 'r' if i % 2 == 0 else 's', 0] for i in range(count)]
            functions.append({'name': name, 'shape': shape, 'width': width, 'entry': entry, 'end': end,
                'return': end - 1, 'instructionPcs': list(range(entry, end)), 'locations': locations})
            raw[name] = [[low, high, '9000' if kind == 'r' else ('920700' if target == 'x86_64' else '921f00')]
                for low, high, kind, _ in locations]
    protected = {'/repo/' + name: 'b' * 64 for name in admission.SOURCES}
    protected.update({'/module/lib/GhidraDwarfForge.jar': 'a' * 64, '/case/local.input': 'c' * 64})
    project = {'Local.rep/idata/00/~00000000.db/db.1.gbf': '1' * 64}
    runs = []
    for variant in ('compiler', 'forge'):
        cases = []
        for f in functions:
            expected = sum(any(low <= pc < high for low, high, _, _ in f['locations']) for pc in f['instructionPcs'])
            for argument in (19, -19, -1985229329 if f['width'] == 4 else -81985529216486895):
                cases.append({'function': f['name'], 'input': argument,
                    'value': argument if f['shape'] in ('keep', 'respill', 'alias') else 0,
                    'points': 12, 'availablePoints': expected, 'unavailablePoints': 12 - expected,
                    'physicalChecks': 3, 'valueChecks': expected if variant == 'forge' else 0,
                    'runtimeBias': 0 if role == 'exec' else 4096, 'firstLinkPc': f['entry'], 'lastLinkPc': f['return']})
        runs.append({'variant': variant, 'status': 'PASS', 'exitCodes': [0], 'rawSha256': '2' * 64,
            'navigation': [{'command': 'next', 'pc': 100}, {'command': 'step', 'pc': 101}], 'cases': cases})
    evidence = {'status': 'PASS_STACK_TRANSITION_MEASUREMENT', 'target': target, 'role': role,
        'historicalComparisonMeasured': False, 'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'protectedUnchanged': True, 'protectedBefore': protected, 'protectedAfter': copy.deepcopy(protected),
        'harnessSha256': {name: 'b' * 64 for name in admission.SOURCES}, 'inputSha256': 'c' * 64,
        'projectBefore': project, 'projectAfter': copy.deepcopy(project), 'projectBackupChanges': [],
        'modelHashes': ['f' * 64] * 3, 'artifactSha256': ['d' * 64, 'e' * 64],
        'rebaseDelta': 0x2100000 if role == 'pie-rebased' else 0,
        'strict': {'status': 'PASS', 'uncorroborated_errors': 0},
        'reports': [{'phase': phase, 'functionsFailed': 0, 'artifacts': {'inputSha256': 'c' * 64,
            'outputSha256': 'd' * 64, 'sourceSha256': 'e' * 64}} for phase in ('fixed', 'repeat')],
        'functions': functions, 'locations': {'stack_value_transitions_locations': 'PASS', 'functions': raw}, 'runtime': runs}
    record = {'suite': 'stack-value-transitions', 'layer': 'headless', 'host': 'posix', 'productionJarSha256': 'a' * 64,
        'sessions': [{'label': label} for label in ('import', 'curate', 'fixed', 'repeat')]}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        for target in ('x86_64', 'aarch64'):
            record, evidence = fixture(target)
            edit(record, evidence)
            with self.subTest(target=target), self.assertRaises(ValueError):
                admission.oracle(record, evidence)

    def test_complete_target_and_six_case_cohorts(self):
        cases = [admission.oracle(*fixture(target, role)) for target in ('x86_64', 'aarch64') for role in admission.ROLES]
        admission.cohort(cases, ['x86_64', 'aarch64'])
        for target in ('x86_64', 'aarch64'):
            selected = [case for case in cases if case['target'] == target]
            admission.cohort(selected, [target])
            for incomplete in (selected[:2], selected + [selected[0]], []):
                with self.assertRaises(ValueError):
                    admission.cohort(incomplete, [target])
        with self.assertRaises(ValueError):
            admission.cohort(cases[:3], ['aarch64'])

    def test_rebased_semantics_must_match(self):
        for key, value in [('input', 'f' * 64), ('delta', 0), ('functions', []), ('locations', {})]:
            cases = [admission.oracle(*fixture('x86_64', role)) for role in admission.ROLES]
            next(row for row in cases if row['role'] == 'pie-rebased')[key] = value
            with self.assertRaises(ValueError):
                admission.cohort(cases, ['x86_64'])

    def test_profiles_and_missing_phases(self):
        for key, value in [('suite', 'other'), ('layer', 'windows'), ('host', 'nt'), ('productionJarSha256', 'f' * 64)]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('target', 'mips'), ('role', 'shared'), ('status', 'PASS'),
                ('historicalComparisonMeasured', True), ('validators', []), ('protectedUnchanged', False)]:
            self.reject(lambda r, e: e.update({key: value}))
        self.reject(lambda r, e: r['sessions'].pop())
        self.reject(lambda r, e: r['sessions'].reverse())
        self.reject(lambda r, e: r.update(launcherInvocations=[{}]))

    def test_protected_harness_inputs_and_database(self):
        for name in admission.SOURCES:
            self.reject(lambda r, e: e['harnessSha256'].pop(name))
            self.reject(lambda r, e: e['harnessSha256'].update({name: 'f' * 64}))
        self.reject(lambda r, e: e['protectedAfter'].clear())
        self.reject(lambda r, e: e.update(inputSha256='f' * 64))
        self.reject(lambda r, e: e['projectAfter'].update({next(iter(e['projectAfter'])): 'f' * 64}))
        self.reject(lambda r, e: e.update(projectBackupChanges=['hidden']))
        self.reject(lambda r, e: e['modelHashes'].__setitem__(0, 'a' * 64))

    def test_export_reports_and_strict_validator(self):
        self.reject(lambda r, e: e['reports'].pop())
        self.reject(lambda r, e: e['reports'][0].update(functionsFailed=1))
        self.reject(lambda r, e: e['reports'][1].update(functionsFailed=False))
        for name in ('inputSha256', 'outputSha256', 'sourceSha256'):
            self.reject(lambda r, e: e['reports'][1]['artifacts'].update({name: 'f' * 64}))
        self.reject(lambda r, e: e['strict'].update(status='SKIPPED'))
        self.reject(lambda r, e: e['strict'].update(uncorroborated_errors=1))

    def test_function_and_transition_inventory(self):
        self.reject(lambda r, e: e['functions'].pop())
        self.reject(lambda r, e: e['functions'][0].update(width=8))
        self.reject(lambda r, e: e['functions'][0]['instructionPcs'].reverse())
        self.reject(lambda r, e: e['functions'][0]['locations'].pop())
        self.reject(lambda r, e: e['functions'][0]['locations'][0].__setitem__(1, 9999))
        self.reject(lambda r, e: e['locations'].update(stack_value_transitions_locations='SKIP'))
        self.reject(lambda r, e: e['locations']['functions']['transfer_alias32'][0].__setitem__(2, '9001'))
        self.reject(lambda r, e: e['locations']['functions']['transfer_alias32'][1].__setitem__(2, '920200'))

    def test_runtime_values_and_physical_checks(self):
        self.reject(lambda r, e: e['runtime'].pop())
        self.reject(lambda r, e: e['runtime'].reverse())
        for index in (0, 1):
            for key, value in [('status', 'SKIP'), ('exitCodes', [1]), ('exitCodes', [False]), ('navigation', [])]:
                self.reject(lambda r, e: e['runtime'][index].update({key: value}))
            self.reject(lambda r, e: e['runtime'][index]['cases'].pop())
            for key, value in [('input', 7), ('value', 0), ('points', 0), ('physicalChecks', 0),
                    ('availablePoints', 0), ('unavailablePoints', 999), ('firstLinkPc', 0), ('lastLinkPc', 0)]:
                self.reject(lambda r, e: e['runtime'][index]['cases'][0].update({key: value}))
        self.reject(lambda r, e: e['runtime'][1]['cases'][0].update(valueChecks=0))

    def test_runtime_bias_and_rebase_required(self):
        for role in ('pie', 'pie-rebased'):
            record, evidence = fixture('aarch64', role)
            evidence['runtime'][1]['cases'][0]['runtimeBias'] = 0
            with self.assertRaises(ValueError):
                admission.oracle(record, evidence)
        record, evidence = fixture('x86_64', 'pie-rebased')
        evidence['rebaseDelta'] = 0
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)


class HostedMatrixAdmission(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('hosted', Path(__file__).with_name('hosted-combined-report.py'))
        self.hosted = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.hosted)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.jar = self.root / 'production.jar'
        with ZipFile(self.jar, 'w') as archive:
            archive.writestr('ghidradwarfforge/Fake.class', b'synthetic metadata test; not valid class bytes')

    def bundle(self, target):
        coverage = self.hosted.combined.integration
        root = self.root / target
        root.mkdir()
        agent = self.root / 'agent.jar'
        agent.write_bytes(b'synthetic agent; never executed')
        records = []
        for role in sorted(admission.ROLES):
            collection = coverage.Collection('stack-value-transitions', self.jar, 'headless', environment={
                'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(root / 'collections'),
                'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent)})
            collection.record['host'] = 'posix'
            for label in ('import', 'curate', 'fixed', 'repeat'):
                with collection.session(['java', 'Fake'], label):
                    (collection.root / collection.record['sessions'][-1]['file']).write_bytes(b'not real JaCoCo probes')
            _, evidence = fixture(target, role)
            for key in ('protectedBefore', 'protectedAfter'):
                evidence[key]['/module/lib/GhidraDwarfForge.jar'] = coverage.digest(self.jar)
            oracle = self.root / (target + '-' + role + '.json')
            coverage.save(oracle, evidence)
            collection.finish(oracle)
            records.append(collection)
        # This lane also requires bitfield evidence. These remain synthetic
        # receipt fixtures, never assertions of actual debugger execution.
        collection = coverage.Collection('bitfield-values', self.jar, 'headless', environment={
            'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(root / 'collections'),
            'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent)})
        for label in ('export', 'repeat'):
            with collection.session(['java', 'Fake'], label):
                (collection.root / collection.record['sessions'][-1]['file']).write_bytes(b'not real JaCoCo probes')
        fields = [{'name': 'a', 'value': 5, 'bits': 3, 'offset': 0},
            {'name': 'b', 'value': 17, 'bits': 5, 'offset': 3}]
        observed = [{'name': name, 'size': size, 'fields': fields}
            for name, size in [('word_value', 4), ('byte_value', 1)]]
        oracle = self.root / (target + '-bitfields.json')
        coverage.save(oracle, {'status': 'PASS_MEASURED_BITFIELDS', 'target': 'aarch64',
            'deterministic': True, 'strictUncorroboratedErrors': 0,
            'inputSha256': 'a' * 64, 'artifactSha256': 'b' * 64, 'sourceSha256': 'c' * 64,
            'protected': {str(i): 'd' * 64 for i in range(6)},
            'gdb': [{'values': ['word={a=5,b=17}', 'byte={a=5,b=17}'],
                'logSha256': 'e' * 64, 'exit': 'normal'} for _ in range(2)],
            'lldb': {'status': 'PASS_LLDB_BITFIELDS', 'target': 'aarch64',
                'cases': [{'mode': mode, 'observations': observed} for mode in ('compiler', 'forge')]}})
        collection.finish(oracle)
        records.append(collection)
        report = root / 'report'
        report.mkdir()
        xml = report / 'headless.xml'
        xml.write_text('<report/>')
        summary = {'schema': 1, 'status': 'PASS', 'commit': 'a' * 40,
            'productionJarSha256': coverage.digest(self.jar),
            'cohort': {'commit': 'a' * 40, 'run': '7', 'job': 'target-preflight'},
            'layers': {'headless': {'xmlSha256': coverage.digest(xml), 'sessions': 14, 'productionClasses': 1,
                'suites': ['bitfield-values', 'stack-value-transitions'], 'unmeasuredForcedHalts': [],
                'receipts': {c.root.name: coverage.digest(c.root / 'receipt.json') for c in records}}}}
        coverage.save(report / 'summary.json', summary)
        return root, records, summary

    def test_aarch64_receipt_layer_and_full_inventory(self):
        root, _, _ = self.bundle('aarch64')
        rows, origin = self.hosted.load_job(root, self.jar, 'linux_aarch64', 'a' * 40, '7')
        self.assertEqual(len(rows), 14)
        self.assertEqual(origin['kind'], 'linux_aarch64')

    def test_x86_receipts_cannot_fill_the_aarch64_matrix_input(self):
        root, _, _ = self.bundle('x86_64')
        with self.assertRaisesRegex(ValueError, 'target profile'):
            self.hosted.load_job(root, self.jar, 'linux_aarch64', 'a' * 40, '7')

    def test_rebound_report_still_cannot_omit_a_profile(self):
        root, records, summary = self.bundle('aarch64')
        removed = records[-2]
        # Retain omitted synthetic data outside the input rather than erasing it.
        removed.root.rename(self.root / 'omitted')
        summary['layers']['headless']['receipts'].pop(removed.root.name)
        summary['layers']['headless']['sessions'] = 10
        self.hosted.files.save(root / 'report/summary.json', summary)
        with self.assertRaisesRegex(ValueError, 'target profile'):
            self.hosted.load_job(root, self.jar, 'linux_aarch64', 'a' * 40, '7')


if __name__ == '__main__':
    unittest.main()

"""Synthetic admission faults only; these tests do not execute MIPS code."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile
from test_location_width_admission import fixture as width_fixture


spec = importlib.util.spec_from_file_location('mips_truncated_admission',
    Path(__file__).with_name('mips-truncated-admission.py'))
admission = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admission)


def fixture(target='mips32be'):
    record = {'suite': 'mips-truncated-space', 'layer': 'headless', 'host': 'posix',
        'productionJarSha256': 'a' * 64, 'sessions': [{'label': label} for label in admission.LABELS]}
    evidence = {'status': 'PASS_MIPS_TRUNCATED_SPACE', 'target': target,
        'productionJarSha256': 'a' * 64, 'harnessSha256': {name: 'b' * 64 for name in admission.SOURCES},
        'protected': {'jar': 'a' * 64, 'script': 'c' * 64, 'consumer': 'd' * 64, 'producer': 'e' * 64},
        'cases': [{'abi': abi, 'deterministic': True, 'inputPreserved': True,
            'validators': ['readelf', 'llvm', 'strict'], 'strictErrors': 0,
            **{key: 'f' * 64 for key in ('resultSha256', 'inputSha256', 'outputSha256', 'sourceSha256')},
            'gdb': [{'variant': variant, 'status': 'PASS', 'exitCodes': [0],
                'globalsAfterReturn': copy.deepcopy(admission.GLOBALS), 'observationsSha256': '1' * 64}
                for variant in ('compiler', 'forge')]} for abi in ('o32', 'n32')]}
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_both_targets_and_exact_cohorts(self):
        for target in ('mips32be', 'mips32le'):
            admission.cohort([admission.oracle(*fixture(target))], target)
            for cases in ([], [target, target], ['arm32']):
                with self.subTest(target=target, cases=cases), self.assertRaises(ValueError):
                    admission.cohort(cases, target)
        with self.assertRaises(ValueError):
            admission.cohort(['mips32le'], 'mips32be')

    def test_profile_and_complete_sessions(self):
        for key, value in [('suite', 'other'), ('layer', 'native-java'), ('host', 'nt'),
                ('productionJarSha256', 'b' * 64), ('unmeasuredForcedHalts', [{}])]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('status', 'PASS'), ('target', 'mips64'), ('productionJarSha256', '')]:
            self.reject(lambda r, e: e.update({key: value}))
        for i in range(4):
            self.reject(lambda r, e: r['sessions'].pop(i))
        self.reject(lambda r, e: r['sessions'].reverse())

    def test_every_abi_validator_and_artifact_required(self):
        for i in range(2):
            self.reject(lambda r, e: e['cases'].pop(i))
            for key, value in [('abi', 'n64'), ('deterministic', False), ('inputPreserved', False),
                    ('validators', ['llvm']), ('strictErrors', 1), ('strictErrors', False),
                    ('resultSha256', ''), ('inputSha256', ''), ('outputSha256', ''), ('sourceSha256', '')]:
                self.reject(lambda r, e: e['cases'][i].update({key: value}))

    def test_debugger_values_and_exit(self):
        for i in range(2):
            for j in range(2):
                self.reject(lambda r, e: e['cases'][i]['gdb'].pop(j))
                for key, value in [('variant', 'other'), ('status', 'FAIL'), ('exitCodes', []),
                        ('observationsSha256', ''), ('globalsAfterReturn', [])]:
                    self.reject(lambda r, e: e['cases'][i]['gdb'][j].update({key: value}))
                self.reject(lambda r, e: e['cases'][i]['gdb'][j]['globalsAfterReturn'][0].update(observed_wide=7))

    def test_source_and_native_provenance(self):
        for name in admission.SOURCES:
            self.reject(lambda r, e: e['harnessSha256'].pop(name))
            self.reject(lambda r, e: e['harnessSha256'].update({name: ''}))
        for name in fixture()[1]['protected']:
            self.reject(lambda r, e: e['protected'].pop(name))
            self.reject(lambda r, e: e['protected'].update({name: ''}))


class HostedAdmission(unittest.TestCase):
    def test_matching_lane_required_even_when_all_hashes_are_rebound(self):
        spec = importlib.util.spec_from_file_location('mips_hosted_report',
            Path(__file__).with_name('hosted-combined-report.py'))
        hosted = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hosted)
        coverage = hosted.combined.integration
        for target in ('mips32be', 'mips32le'):
            with self.subTest(target=target), tempfile.TemporaryDirectory(prefix='forge-mips-receipts-') as temp:
                root = Path(temp)
                jar, agent = root / 'production.jar', root / 'agent.jar'
                with ZipFile(jar, 'w') as archive:
                    archive.writestr('ghidradwarfforge/Fixture.class', b'not production bytecode')
                agent.write_bytes(b'not an agent')
                job = root / 'job'
                collection = coverage.Collection('mips-truncated-space', jar, 'headless', environment={
                    'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(job / 'collections'),
                    'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent)})
                collection.record['host'] = 'posix'
                for label in admission.LABELS:
                    with collection.session(['java', 'Fake'], label):
                        (collection.root / collection.record['sessions'][-1]['file']).write_bytes(b'not real probes')
                _, evidence = fixture(target)
                evidence['productionJarSha256'] = evidence['protected']['jar'] = coverage.digest(jar)
                oracle = root / 'oracle.json'
                coverage.save(oracle, evidence)
                collection.finish(oracle)
                width_records = []
                for mode in hosted.location_width.MODES:
                    width = coverage.Collection('location-width-producer', jar, 'native-java', environment={
                        'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(job / 'collections'),
                        'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent)})
                    width.record['host'] = 'posix'
                    with width.session(['java', 'Fake'], 'producer'):
                        (width.root / width.record['sessions'][-1]['file']).write_bytes(b'not real probes')
                    _, width_evidence = width_fixture(target, mode)
                    width_evidence['productionJarSha256'] = width_evidence['protectedSha256']['jar'] = coverage.digest(jar)
                    width_oracle = root / (mode + '.json')
                    coverage.save(width_oracle, width_evidence)
                    width.finish(width_oracle)
                    width_records.append(width)
                context = coverage.Collection('context-boundaries', jar, 'headless', environment={
                    'FORGE_INTEGRATION_COVERAGE_OUTPUT': str(job / 'collections'),
                    'FORGE_INTEGRATION_COVERAGE_AGENT': str(agent)})
                context.record['host'] = 'posix'
                with context.session(['java', 'Fake'], 'context-boundaries'):
                    (context.root / context.record['sessions'][-1]['file']).write_bytes(b'not real probes')
                context_oracle = root / 'context.json'
                coverage.save(context_oracle, {'status': 'PASS_CONTEXT_BOUNDARIES', 'target': target,
                    'productionJarSha256': coverage.digest(jar)})
                context.finish(context_oracle)
                report = job / 'report'
                report.mkdir()
                xml = report / 'headless.xml'
                xml.write_text('<report/>')
                native_xml = report / 'native-java.xml'
                native_xml.write_text('<report/>')
                summary = {'schema': 1, 'status': 'PASS', 'commit': 'a' * 40,
                    'productionJarSha256': coverage.digest(jar),
                    'cohort': {'commit': 'a' * 40, 'run': '7', 'job': 'target-preflight'},
                    'layers': {'headless': {'xmlSha256': coverage.digest(xml), 'sessions': 5,
                        'productionClasses': 1, 'suites': ['context-boundaries', 'mips-truncated-space'],
                        'unmeasuredForcedHalts': [],
                        'receipts': {collection.root.name: coverage.digest(collection.root / 'receipt.json'),
                            context.root.name: coverage.digest(context.root / 'receipt.json')}},
                        'native-java': {'xmlSha256': coverage.digest(native_xml), 'sessions': 4,
                            'productionClasses': 1, 'suites': ['location-width-producer'], 'unmeasuredForcedHalts': [],
                            'receipts': {r.root.name: coverage.digest(r.root / 'receipt.json') for r in width_records}}}}
                coverage.save(report / 'summary.json', summary)
                rows, origin = hosted.load_job(job, jar, 'linux_' + target, 'a' * 40, '7')
                self.assertEqual(len(rows), 9)
                self.assertEqual(origin['kind'], 'linux_' + target)
                other = 'mips32le' if target == 'mips32be' else 'mips32be'
                with self.assertRaisesRegex(ValueError, 'target cohort'):
                    hosted.load_job(job, jar, 'linux_' + other, 'a' * 40, '7')
                # A lane cannot omit the newly required context suite, even when
                # every remaining receipt and report hash is rebound consistently.
                summary['layers']['headless']['suites'] = ['mips-truncated-space']
                summary['layers']['headless']['sessions'] = 4
                summary['layers']['headless']['receipts'].pop(context.root.name)
                coverage.save(report / 'summary.json', summary)
                with self.assertRaisesRegex(ValueError, 'missing or unexpected collection files'):
                    hosted.load_job(job, jar, 'linux_' + target, 'a' * 40, '7')
                summary['layers']['headless']['suites'] = ['context-boundaries', 'mips-truncated-space']
                summary['layers']['headless']['sessions'] = 5
                summary['layers']['headless']['receipts'][context.root.name] = coverage.digest(context.root / 'receipt.json')
                coverage.save(report / 'summary.json', summary)
                # A producer cannot omit an ABI even by recomputing receipt/report hashes.
                evidence['cases'].pop()
                coverage.save(collection.root / 'oracle.json', evidence)
                collection.record['evidenceSha256'] = coverage.digest(collection.root / 'oracle.json')
                collection._save()
                summary['layers']['headless']['receipts'][collection.root.name] = coverage.digest(
                    collection.root / 'receipt.json')
                coverage.save(report / 'summary.json', summary)
                with self.assertRaisesRegex(ValueError, 'ABI cases missing'):
                    hosted.load_job(job, jar, 'linux_' + target, 'a' * 40, '7')


if __name__ == '__main__':
    unittest.main()

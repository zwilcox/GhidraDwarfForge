"""Synthetic receipt controls, not evidence of native installation or GDB execution."""
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location('bundle_admission', Path(__file__).with_name('build-id-source-bundle-admission.py'))
admission = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admission)


def fixture():
    dependencies = ['forge-src-' + 'a' * 64 + '.json',
        *['forge-src-' + f'{index:06d}-' + 'b' * 64 + '.c' for index in (1, 2)]]
    record = {'suite': 'build-id-source-bundle', 'layer': 'native-java', 'host': 'posix',
        'productionJarSha256': 'c' * 64, 'sessions': [{'label': label} for label in
            ['install-multi', 'idempotent-multi', 'changed-dependency-0', 'changed-dependency-1',
                'changed-dependency-2', 'update-single', 'update-multi', 'remove']]}
    evidence = {'status': 'PASS_BUILD_ID_SOURCE_BUNDLE', 'target': 'x86_64', 'host': admission.HOST,
        'productionJarSha256': 'c' * 64, 'dependencies': dependencies, 'refusedDependencies': list(dependencies),
        'inputsUnchanged': True, 'retainedGenerationsUnchanged': True, 'registrationRemoved': True,
        'checks': [{'label': label, 'outcome': outcome} for label, outcome in admission.CHECKS],
        'protected': {str(n): 'd' * 64 for n in range(20)}, 'generations': [], 'consumers': []}
    for index, layout in enumerate(('multi', 'single', 'multi')):
        root = Path('/generation/' + str(index))
        source = root / 'source/forge.dbg.c'
        files = {str(p): 'e' * 64 for p in [source, root / 'installed.debug', root / 'validation.json']}
        if layout == 'multi':
            files.update({str(folder / name): 'e' * 64 for folder in (root, source.parent) for name in dependencies})
        evidence['generations'].append({'layout': layout, 'source': str(source), 'files': files})
        stops = [{'function': function, 'file': str(source.parent / dependencies[at + 1]) if layout == 'multi'
            else str(source), 'line': 3} for at, function in enumerate(('recovered_first', 'recovered_second'))]
        evidence['consumers'].append({'label': admission.CONSUMERS[index][0], 'layout': layout,
            'inputsHidden': True, 'stdoutSha256': 'f' * 64,
            'observation': {'status': 'PASS', 'observed': 10, 'exitCodes': [0], 'stops': stops}})
    evidence['consumers'].append({'label': 'gdb-removed', 'layout': 'multi', 'inputsHidden': True,
        'stdoutSha256': 'f' * 64, 'observation': {'status': 'PASS_NO_REGISTRATION'}})
    return record, evidence


class Admission(unittest.TestCase):
    def reject(self, edit):
        record, evidence = fixture()
        edit(record, evidence)
        with self.assertRaises(ValueError):
            admission.oracle(record, evidence)

    def test_complete_receipt(self):
        admission.oracle(*fixture())

    def test_host_measurement_and_lifecycle_required(self):
        for key, value in [('suite', 'other'), ('layer', 'headless'), ('host', 'nt'),
                ('productionJarSha256', '0' * 64), ('sessions', [])]:
            self.reject(lambda r, e: r.update({key: value}))
        for key, value in [('host', 'test-host'), ('target', 'aarch64'), ('status', 'PASS'),
                ('checks', []), ('protected', {}), ('inputsUnchanged', False),
                ('registrationRemoved', False), ('retainedGenerationsUnchanged', False)]:
            self.reject(lambda r, e: e.update({key: value}))

    def test_dependencies_cannot_be_missing_or_unchecked(self):
        for key, value in [('dependencies', []), ('dependencies', [None] * 3), ('refusedDependencies', [])]:
            self.reject(lambda r, e: e.update({key: value}))
        self.reject(lambda r, e: e['dependencies'].append(e['dependencies'][1]))
        for generation in (0, 2):
            for folder in ('', 'source/'):
                self.reject(lambda r, e: e['generations'][generation]['files'].pop(
                    '/generation/' + str(generation) + '/' + folder + e['dependencies'][1]))
            self.reject(lambda r, e: e['generations'][generation]['files'].update({
                '/generation/' + str(generation) + '/source/' + e['dependencies'][1]: '0' * 64}))

    def test_retained_generations_and_validation_required(self):
        self.reject(lambda r, e: e.update(generations=[]))
        for index in range(3):
            self.reject(lambda r, e: e['generations'][index]['files'].pop('/generation/' + str(index) + '/validation.json'))
            self.reject(lambda r, e: e['generations'][index].update(source='/outside/index.c'))
        self.reject(lambda r, e: e['generations'].__setitem__(2, e['generations'][0]))

    def test_actual_gdb_values_paths_and_removal_required(self):
        self.reject(lambda r, e: e.update(consumers=[]))
        for index in range(4):
            self.reject(lambda r, e: e['consumers'][index].update(inputsHidden=False))
            self.reject(lambda r, e: e['consumers'][index].update(stdoutSha256='bad'))
        for index in range(3):
            for key, value in [('status', 'FAILED'), ('observed', 9), ('exitCodes', [1]), ('exitCodes', [False]), ('stops', [])]:
                self.reject(lambda r, e: e['consumers'][index]['observation'].update({key: value}))
            self.reject(lambda r, e: e['consumers'][index]['observation']['stops'][0].update(file='/outside/part.c'))
            self.reject(lambda r, e: e['consumers'][index]['observation']['stops'][0].update(line=0))
            self.reject(lambda r, e: e['consumers'][index]['observation']['stops'][0].update(function='other'))
        self.reject(lambda r, e: e['consumers'][0]['observation']['stops'][1].update(
            file=e['consumers'][0]['observation']['stops'][0]['file']))
        self.reject(lambda r, e: e['consumers'][3].update(observation={'status': 'PASS'}))


if __name__ == '__main__':
    unittest.main()

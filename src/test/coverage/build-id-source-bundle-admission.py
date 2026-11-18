"""Require split-source installation, independent consumers and dependency refusals."""
from pathlib import PurePosixPath
import re


HOST = 'linux-x64-ext4-build-id-visible-metadata-v1'
CHECKS = [('install-multi', 'INSTALLED'), ('idempotent-multi', 'ALREADY_INSTALLED'),
    ('update-single', 'UPDATED'), ('update-multi', 'UPDATED'), ('remove', 'REMOVED')]
CONSUMERS = [('gdb-installed-multi', 'multi'), ('gdb-updated-single', 'single'),
    ('gdb-updated-multi', 'multi'), ('gdb-removed', 'multi')]


def sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def oracle(record, evidence):
    dependencies = evidence.get('dependencies')
    if (record.get('suite') != 'build-id-source-bundle' or record.get('layer') != 'native-java'
            or record.get('host') != 'posix' or evidence.get('status') != 'PASS_BUILD_ID_SOURCE_BUNDLE'
            or evidence.get('target') != 'x86_64' or evidence.get('host') != HOST
            or not sha(evidence.get('productionJarSha256'))
            or record.get('productionJarSha256') != evidence['productionJarSha256']
            or not isinstance(dependencies, list) or not 3 <= len(dependencies) <= 64
            or not all(isinstance(name, str) for name in dependencies)
            or len(set(dependencies)) != len(dependencies)
            or not re.fullmatch(r'forge-src-[0-9a-f]{64}\.json', dependencies[0])
            or any(not re.fullmatch(r'forge-src-[0-9]{6}-[0-9a-f]{64}\.c', name) for name in dependencies[1:])
            or evidence.get('refusedDependencies') != dependencies
            or any(evidence.get(key) is not True for key in
                ('inputsUnchanged', 'retainedGenerationsUnchanged', 'registrationRemoved'))):
        raise ValueError('source bundle installation requires real Linux host and every preserved/refused dependency')
    labels = ['install-multi', 'idempotent-multi',
        *['changed-dependency-' + str(index) for index in range(len(dependencies))],
        'update-single', 'update-multi', 'remove']
    if ([row.get('label') for row in record.get('sessions', [])] != labels
            or evidence.get('checks') != [{'label': label, 'outcome': outcome} for label, outcome in CHECKS]):
        raise ValueError('incomplete measured installation lifecycle')
    protected = evidence.get('protected')
    if not isinstance(protected, dict) or len(protected) < 20 or not all(sha(value) for value in protected.values()):
        raise ValueError('missing protected input, tool or harness hashes')
    consumers, generations = evidence.get('consumers'), evidence.get('generations')
    if (not isinstance(consumers, list) or len(consumers) != 4
            or not isinstance(generations, list) or len(generations) != 3):
        raise ValueError('missing installed-source consumer or retained generation')
    for item, layout in zip(generations, ('multi', 'single', 'multi')):
        if not isinstance(item, dict) or item.get('layout') != layout or not isinstance(item.get('source'), str):
            raise ValueError('invalid retained generation')
        source = PurePosixPath(item['source'])
        files = item.get('files')
        expected = {str(source), str(source.parent.parent / 'validation.json'),
            str(source.parent.parent / 'installed.debug')}
        if layout == 'multi':
            expected.update(str(folder / name) for folder in (source.parent, source.parent.parent) for name in dependencies)
        if (not source.is_absolute() or source.name != 'forge.dbg.c' or source.parent.name != 'source'
                or not isinstance(files, dict) or not expected <= files.keys()
                or not all(sha(value) for value in files.values())):
            raise ValueError('retained generation lacks validator or complete source dependencies')
        if layout == 'multi' and any(files[str(source.parent / name)] != files[str(source.parent.parent / name)]
                for name in dependencies):
            raise ValueError('retained and exported dependency bytes differ')
    if generations[0]['source'] == generations[2]['source']:
        raise ValueError('update reused the old source generation')
    for index, (item, (label, layout)) in enumerate(zip(consumers, CONSUMERS)):
        if (not isinstance(item, dict) or item.get('label') != label or item.get('layout') != layout
                or item.get('inputsHidden') is not True or not sha(item.get('stdoutSha256'))):
            raise ValueError('consumer did not use unavailable export inputs')
        observed = item.get('observation')
        if not isinstance(observed, dict):
            raise ValueError('missing GDB observations')
        if index == 3:
            if observed != {'status': 'PASS_NO_REGISTRATION'}:
                raise ValueError('GDB still found removed registration')
            continue
        stops = observed.get('stops')
        if (observed.get('status') != 'PASS' or type(observed.get('observed')) is not int
                or observed['observed'] != 10 or observed.get('exitCodes') != [0]
                or type(observed['exitCodes'][0]) is not int
                or not isinstance(stops, list) or len(stops) != 2
                or any(not isinstance(stop, dict) for stop in stops)
                or [stop.get('function') for stop in stops] != ['recovered_first', 'recovered_second']):
            raise ValueError('missing GDB stepping, value or normal exit')
        parent = PurePosixPath(generations[index]['source']).parent
        for stop in stops:
            if (not isinstance(stop.get('file'), str) or PurePosixPath(stop['file']).parent != parent
                    or stop['file'] not in generations[index]['files']
                    or (layout == 'single' and stop['file'] != generations[index]['source'])
                    or type(stop.get('line')) is not int or stop['line'] <= 0):
                raise ValueError('GDB used a source outside retained generation')
        if layout == 'multi' and stops[0]['file'] == stops[1]['file']:
            raise ValueError('split-source GDB did not traverse distinct parts')

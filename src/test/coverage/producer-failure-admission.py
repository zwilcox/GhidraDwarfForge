"""Require real retry/validator evidence for the isolated producer fault suite."""
import re


MODES = ('init-error', 'init-null', 'string-error', 'string-no-entry', 'die-null',
    'transform-error', 'buffer-count-zero', 'buffer-count-large', 'section-error',
    'section-unknown', 'section-negative-length', 'section-large-length', 'section-null',
    'missing-strings', 'duplicate-section', 'relocation-version', 'relocation-no-groups',
    'relocation-section', 'relocation-target', 'relocation-empty', 'relocation-null',
    'relocation-offset-negative', 'relocation-offset-outside', 'relocation-zero-width',
    'relocation-unknown-symbol', 'relocation-address-width', 'relocation-missing-address', 'finish-error')
SOURCES = {'src/test/integration/producer-failures.py', 'src/test/native/producer-fault-shim.c',
    'src/test/java/ghidradwarfforge/nativeapi/ProducerFailureProbe.java',
    'src/test/integration/check-dwarfdump.py', 'src/test/integration/integration_coverage.py'}
HEADERS = {
    'src/lib/libdwarf/libdwarf.h': 'e96d60afd9b99ef9202d3b56e4510685e658c2f4945c7603afe2481d789f861f',
    'src/lib/libdwarf/dwarf.h': 'e722bfad6165dc107224204c4664db49d2e15893b851aa8517e1f0ae40048479',
    'src/lib/libdwarfp/libdwarfp.h': '3fd4cc23c0f9363d1b8875f45c06363d196413475d75fd28e3be915a40d7f7ae',
}
ARCHIVE_SHA256 = '7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def oracle(record, evidence):
    require(record.get('suite') == 'producer-failures' and record.get('layer') == 'native-java'
        and record.get('host') == 'posix' and evidence.get('host') == 'linux'
        and evidence.get('target') == 'x86_64' and evidence.get('status') == 'PASS_ISOLATED_PRODUCER_FAILURES',
        'producer failure coverage requires its isolated Linux/x86-64 profile')
    require(evidence.get('sourceCommit') == 'af7b278c6aa2ae9daad94fb7f8bffdc0e9980993'
        and evidence.get('sourceArchiveSha256') == ARCHIVE_SHA256 and evidence.get('headersSha256') == HEADERS,
        'producer failure coverage requires the audited pinned headers')
    require(hash_value(evidence.get('productionJarSha256'))
        and evidence['productionJarSha256'] == record.get('productionJarSha256')
        and hash_value(evidence.get('shimSha256')), 'producer failure build identity differs')
    harnesses = evidence.get('harnessSha256')
    require(isinstance(harnesses, dict) and set(harnesses) == SOURCES
        and all(hash_value(value) for value in harnesses.values()), 'producer failure harness inventory is incomplete')
    native, protected = evidence.get('nativeSha256'), evidence.get('protected')
    require(isinstance(native, dict) and set(native) == {'consumer', 'producer'}
        and all(hash_value(value) for value in native.values()), 'producer native pair is not identified')
    require(isinstance(protected, dict) and len(protected) == 5
        and all(isinstance(path, str) and path and hash_value(value) for path, value in protected.items())
        and {ARCHIVE_SHA256, evidence['productionJarSha256'], *native.values()}.issubset(protected.values()),
        'producer failure coverage lacks protected input/native identities')
    require([row.get('label') for row in record.get('sessions', [])] == list(MODES)
        and not record.get('unmeasuredForcedHalts'), 'producer failure coverage lacks its complete measured session sequence')
    controls = evidence.get('controls')
    require(isinstance(controls, list) and all(isinstance(row, dict) for row in controls)
        and [row.get('mode') for row in controls] == list(MODES), 'producer failure controls are missing or reordered')
    for mode, row in zip(MODES, controls, strict=True):
        starts = 2 if mode.startswith('init-') else 4
        require(type(row.get('faults')) is int and row['faults'] == 2
            and type(row.get('starts')) is int and row['starts'] == starts
            and type(row.get('finishes')) is int and row['finishes'] == starts,
            'producer failure did not prove both faults and complete native lifecycles')
        require(all(row.get(key) is True for key in ('existingPreserved', 'absentPreserved', 'retryIdentical'))
            and row.get('validators') == ['readelf', 'llvm', 'strict'] and row.get('gdb') == 'PASS'
            and hash_value(row.get('sidecarSha256')) and hash_value(row.get('sourceSha256')),
            'producer failure lacks preservation or independently validated retry')
    return 'linux', 'x86_64'


def cohort(cases):
    require(cases == [('linux', 'x86_64')], 'producer failure coverage requires one complete isolated suite')

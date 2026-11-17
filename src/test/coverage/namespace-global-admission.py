"""Bind namespace coverage to every collision, validator and debugger check."""
import re


VARIANTS = ('normal', 'type-short', 'enum-short', 'function-short',
    'type-full', 'enum-full', 'function-full', 'global-full')
VALUES = {'left::item': 17, 'right::item': 29, 'left::unique_value': 41, 'item': 53}
SOURCES = {'src/test/integration/namespace-globals-native.py',
    'src/test/java/ghidradwarfforge/nativeapi/NamespaceGlobalLookupSmoke.java',
    'src/test/scenarios/namespace-globals/fixture.cpp',
    'src/test/scenarios/namespace-globals/runtime.py',
    'src/test/scenarios/namespace-globals/runtime.sh',
    'src/test/integration/qemu-socket.sh', 'src/test/integration/alias_relationships.py',
    'src/test/integration/check-dwarfdump.py', 'src/test/integration/integration_coverage.py'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hash_value(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def queries(variant, symbols):
    expected = [["print /x &'right::item'", hex(symbols['right::item'])],
        ["print /x &'left::unique_value'", hex(symbols['left::unique_value'])]]
    full = variant.endswith('full')
    if not full:
        expected.append(["print /x &'left::item'", hex(symbols['left::item'])])
    collision = 'left::item' if full else 'unique_value'
    if variant.startswith('type-'):
        expected.append(["ptype '" + collision + "'", 'type = int'])
    elif variant.startswith('enum-'):
        expected.append(["print (int)'" + collision + "'", '= 73'])
    elif variant.startswith('function-'):
        expected.append(["print /x &'" + collision + "'", hex(symbols['marker'])])
    elif variant == 'global-full':
        expected.append(["print /x &'left::item'", hex(symbols['left::unique_value'])])
    return expected


def oracle(record, evidence):
    require(record.get('suite') == 'namespace-globals' and record.get('layer') == 'native-java'
        and record.get('host') == 'posix' and evidence.get('target') in ('x86_64', 'aarch64')
        and evidence.get('status') == 'PASS_NAMESPACE_GLOBALS_MEASUREMENT'
        and evidence.get('oracleStatus') == 'NAMESPACE_GLOBAL_NATIVE_PASS', 'namespace profile differs')
    require(hash_value(evidence.get('jarSha256'))
        and evidence['jarSha256'] == record.get('productionJarSha256'), 'namespace JAR differs')
    sessions = record.get('sessions', [])
    require(isinstance(sessions, list) and all(isinstance(row, dict) for row in sessions)
        and [row.get('label') for row in sessions] == [name + '-producer' for name in VARIANTS]
        and all(row.get('status') == 'ORACLE_PASSED' for row in sessions)
        and not record.get('unmeasuredForcedHalts'), 'namespace producer sessions are incomplete')
    symbols = evidence.get('symbols')
    require(isinstance(symbols, dict) and set(symbols) == set(VALUES) | {'marker', 'marker.size'}
        and all(type(value) is int and value > 0 for value in symbols.values())
        and len({symbols[name] for name in VALUES}) == len(VALUES), 'namespace compiler symbols differ')
    for mode in ('compiler', 'selected'):
        result = evidence.get(mode)
        require(isinstance(result, dict) and result.get('status') == 'PASS'
            and result.get('values') == VALUES
            and result.get('addresses') == {name: symbols[name] for name in VALUES}
            and type(result.get('return')) is int and result['return'] == 140
            and result.get('exitCodes') == [0] and type(result['exitCodes'][0]) is int
            and 'shortUnique' in result
            and result.get('shortUnique') == (41 if mode == 'selected' else None),
            'namespace debugger behavior is incomplete')
    artifacts = evidence.get('artifacts')
    require(isinstance(artifacts, list) and len(artifacts) == len(VARIANTS), 'namespace artifact inventory differs')
    for artifact, variant in zip(artifacts, VARIANTS):
        require(isinstance(artifact, dict) and artifact.get('variant') == variant
            and hash_value(artifact.get('sha256'))
            and artifact.get('validators') == ['readelf', 'llvm', 'strict']
            and artifact.get('coldQueries') == queries(variant, symbols), 'namespace collision checks differ')
        logs = artifact.get('coldLogSha256')
        require(isinstance(logs, list) and len(logs) == len(artifact['coldQueries'])
            and all(hash_value(value) for value in logs), 'namespace cold debugger logs are incomplete')
    harnesses, native, protected = (evidence.get(name) for name in ('harnessSha256', 'nativeSha256', 'protected'))
    require(isinstance(harnesses, dict) and set(harnesses) == SOURCES
        and all(hash_value(value) for value in harnesses.values()), 'namespace source inventory differs')
    require(isinstance(native, dict) and set(native) == {'consumer', 'producer'}
        and all(hash_value(value) for value in native.values()), 'namespace native inventory differs')
    require(isinstance(protected, dict) and protected
        and all(isinstance(name, str) and name and hash_value(value) for name, value in protected.items())
        and {evidence['jarSha256'], *native.values(), *harnesses.values()} <= set(protected.values()),
        'namespace protected inputs differ')
    return evidence['target']


def cohort(cases, target):
    require(cases == [target] and target in ('x86_64', 'aarch64'),
        'namespace coverage requires exactly one complete target fixture')

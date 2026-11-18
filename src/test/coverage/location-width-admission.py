"""Admission for real native location exports, width refusals and debugger values."""
import re


TARGETS = ('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le')
MODES = ('listed', 'stable', 'listed-indirect', 'stable-indirect')
SOURCES = {'src/test/integration/location-width-producer.py',
    'src/test/java/ghidradwarfforge/nativeapi/LocationWidthProducerProbe.java',
    'src/test/integration/qemu-socket.sh', 'src/test/integration/check-dwarfdump.py',
    'src/test/integration/integration_coverage.py'}


def require(value, message):
    if not value:
        raise ValueError(message)


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def oracle(record, evidence):
    target, mode = evidence.get('target'), evidence.get('mode')
    role = evidence.get('role')
    require(record.get('suite') == 'location-width-producer' and record.get('layer') == 'native-java'
        and record.get('host') == 'posix' and evidence.get('status') == 'PASS_LOCATION_WIDTH_PRODUCER'
        and target in TARGETS and mode in MODES, 'location-width profile differs')
    require(role in ('exec', 'pie') and (role == 'exec' or target == 'x86_64')
        and type(evidence.get('elfType')) is int and evidence['elfType'] == (3 if role == 'pie' else 2)
        and type(evidence.get('runtimeAddressChecksPerDebugger')) is int
        and evidence['runtimeAddressChecksPerDebugger'] == 2, 'location-width runtime addresses missing')
    require(hash_value(evidence.get('productionJarSha256'))
        and record.get('productionJarSha256') == evidence['productionJarSha256'], 'location-width JAR differs')
    require([row.get('label') for row in record.get('sessions', [])] == ['producer']
        and not record.get('unmeasuredForcedHalts'), 'location-width producer session incomplete')
    require(type(evidence.get('rejectedOverflowExports')) is int
        and evidence['rejectedOverflowExports'] == (0 if target in ('x86_64', 'aarch64') else 4),
        'location-width overflow refusals missing')
    require(evidence.get('validators') == ['readelf', 'llvm', 'strict']
        and evidence.get('compilerGdb') == evidence.get('exportedGdb') == 'PASS'
        and evidence.get('deterministic') is True and evidence.get('inputPreserved') is True
        and hash_value(evidence.get('sidecarSha256')), 'location-width behavior incomplete')
    sources, native, protected = (evidence.get(key) for key in ('harnessSha256', 'nativeSha256', 'protectedSha256'))
    require(isinstance(sources, dict) and set(sources) == SOURCES
        and all(hash_value(value) for value in sources.values()), 'location-width source hashes missing')
    require(isinstance(native, dict) and set(native) == {'consumer', 'producer'}
        and all(hash_value(value) for value in native.values()), 'location-width native hashes missing')
    require(isinstance(protected, dict) and len(protected) == 10
        and all(isinstance(key, str) and key and hash_value(value) for key, value in protected.items())
        and {evidence['productionJarSha256'], *sources.values(), *native.values()}.issubset(protected.values()),
        'location-width protected inputs missing')
    return target, role, mode


def cohort(cases, target):
    roles = ('exec', 'pie') if target == 'x86_64' else ('exec',)
    require(target in TARGETS
        and sorted(cases) == sorted((target, role, mode) for role in roles for mode in MODES),
        'location-width cohort needs all four location forms and required ELF roles on the matching target')

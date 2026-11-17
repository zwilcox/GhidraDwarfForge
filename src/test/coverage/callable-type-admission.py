"""Require native callable DIE controls and real debugger/validator evidence."""
import re


CONTROLS = ['ellipsis', 'unnamed', 'location', 'declaration-address', 'noreturn', 'convention', 'void-return']
SOURCES = {'src/test/integration/callable-type-producer.py',
    'src/test/java/ghidradwarfforge/nativeapi/CallableTypeProducerProbe.java',
    'src/test/integration/check-object-parameters.py', 'src/test/integration/check-dwarfdump.py',
    'src/test/integration/integration_coverage.py'}


def require(value, message):
    if not value:
        raise ValueError(message)


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def oracle(record, evidence):
    require(record.get('suite') == 'callable-type-producer' and record.get('layer') == 'native-java'
        and record.get('host') == 'posix' and evidence.get('host') == 'linux'
        and evidence.get('target') == 'x86_64' and evidence.get('role') == 'exec'
        and evidence.get('status') == 'PASS_CALLABLE_TYPE_PRODUCER', 'callable type profile differs')
    require(hash_value(evidence.get('productionJarSha256'))
        and evidence['productionJarSha256'] == record.get('productionJarSha256'), 'callable type JAR differs')
    require([row.get('label') for row in record.get('sessions', [])] == ['producer']
        and not record.get('unmeasuredForcedHalts'), 'callable producer session is incomplete')
    require(evidence.get('deterministic') is True and evidence.get('inputPreserved') is True,
        'callable preservation evidence missing')
    variants = evidence.get('variants')
    require(isinstance(variants, list) and len(variants) == 4, 'callable variants missing')
    for variant, mode in zip(variants, ('compiler', 'normal', 'unknown', 'blocked')):
        require(isinstance(variant, dict) and variant.get('mode') == mode
            and variant.get('negativeControls') == ([] if mode == 'compiler' else CONTROLS)
            and variant.get('gdb') == 'PASS' and variant.get('validators') == ['readelf', 'llvm', 'strict']
            and hash_value(variant.get('sidecarSha256')), 'callable behavioral evidence missing')
    harnesses = evidence.get('harnessSha256', {})
    require(isinstance(harnesses, dict) and set(harnesses) == SOURCES
        and all(hash_value(value) for value in harnesses.values()), 'callable harness provenance missing')
    native, protected = evidence.get('nativeSha256'), evidence.get('protected')
    require(isinstance(native, dict) and set(native) == {'consumer', 'producer'}
        and all(hash_value(value) for value in native.values()), 'callable native pair missing')
    require(isinstance(protected, dict) and len(protected) == 10
        and all(isinstance(path, str) and path and hash_value(value) for path, value in protected.items())
        and {evidence['productionJarSha256'], *native.values(), *harnesses.values()}.issubset(protected.values()),
        'callable protected inputs missing')
    return 'linux', 'x86_64'


def cohort(cases):
    require(cases == [('linux', 'x86_64')], 'callable types require one complete Linux x86-64 fixture')

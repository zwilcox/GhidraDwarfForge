"""Require compiler, debugger and DIE evidence before admitting qualifier coverage."""
import re


GLOBALS = ('forge_base', 'forge_atomic', 'forge_cv', 'forge_restrict', 'forge_void',
    'forge_schar', 'forge_uchar', 'forge_bool', 'forge_utf16', 'forge_utf32',
    'forge_float', 'forge_double', 'forge_u64')
SOURCES = {'src/test/integration/qualified-type-producer.py',
    'src/test/java/ghidradwarfforge/nativeapi/QualifiedTypeProducerProbe.java',
    'src/test/integration/check-object-parameters.py', 'src/test/integration/check-dwarfdump.py',
    'src/test/integration/integration_coverage.py'}
UNTYPED_CONTROLS = ['name', 'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_type',
    'DW_AT_prototyped', 'DW_AT_calling_convention', 'DW_AT_noreturn', 'DW_AT_location',
    'extra-variable', 'source-presence']


def expected_controls():
    controls = []
    for name in GLOBALS:
        controls.append(name + ':address')
        depth = {'forge_atomic': 2, 'forge_cv': 3, 'forge_restrict': 3, 'forge_void': 2}.get(name, 1)
        for index in range(depth):
            controls.append(name + ':tag:' + str(index))
            if (name, index) in (('forge_restrict', 1), ('forge_void', 0)):
                controls.append(name + ':pointer-width')
        controls.extend([name + ':void-target'] if name == 'forge_void'
            else [name + ':encoding', name + ':width'])
    return controls


def require(value, message):
    if not value:
        raise ValueError(message)


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def oracle(record, evidence):
    require(record.get('suite') == 'qualified-type-producer' and record.get('layer') == 'native-java'
        and record.get('host') == 'posix' and evidence.get('host') == 'linux'
        and evidence.get('target') == 'x86_64' and evidence.get('role') == 'exec'
        and evidence.get('status') == 'PASS_QUALIFIED_TYPE_PRODUCER', 'qualified type profile differs')
    require(hash_value(evidence.get('productionJarSha256'))
        and evidence['productionJarSha256'] == record.get('productionJarSha256'), 'qualified type JAR differs')
    require([row.get('label') for row in record.get('sessions', [])] == ['producer']
        and not record.get('unmeasuredForcedHalts'), 'qualified type producer session is incomplete')
    require(evidence.get('globals') == list(GLOBALS)
        and evidence.get('compilerGdb') == 'PASS' and evidence.get('exportedGdb') == 'PASS'
        and evidence.get('validators') == ['readelf', 'llvm', 'strict']
        and evidence.get('deterministic') is True and evidence.get('inputPreserved') is True
        and hash_value(evidence.get('sidecarSha256')) and hash_value(evidence.get('sourceSha256')),
        'qualified type behavior is incomplete')
    checks = evidence.get('typeOracle', {})
    require(checks.get('globals') == list(GLOBALS) and checks.get('negativeControls') == expected_controls()
        and checks.get('constVoidChain') == ['DW_TAG_pointer_type', 'DW_TAG_const_type']
        and checks.get('constVoidHasNoTarget') is True, 'qualified type DIE oracle is incomplete')
    variants = evidence.get('untypedExports')
    require(isinstance(variants, list) and len(variants) == 2, 'optional model export inventory differs')
    for variant, mode in zip(variants, ('symbols', 'source-only')):
        require(isinstance(variant, dict) and variant.get('mode') == mode
            and variant.get('gdb') == 'PASS' and variant.get('validators') == ['readelf', 'llvm', 'strict']
            and variant.get('negativeControls') == UNTYPED_CONTROLS
            and variant.get('deterministic') is True and variant.get('noInventedTypesOrLocations') is True
            and hash_value(variant.get('sidecarSha256'))
            and (variant.get('sourceSha256') is None if mode == 'symbols' else hash_value(variant.get('sourceSha256'))),
            'optional model export behavior is incomplete')
    require(evidence.get('invalidSourceNames') == [None, '', ' ', 'nested/file.c', 'nested\\file.c']
        and evidence.get('typedRetryAfterUntypedAndFailures') is True, 'source admission and typed retry are incomplete')
    harnesses, native, protected = [evidence.get(key) for key in ('harnessSha256', 'nativeSha256', 'protected')]
    require(isinstance(harnesses, dict) and set(harnesses) == SOURCES
        and all(hash_value(value) for value in harnesses.values()), 'qualified type harness inventory differs')
    require(isinstance(native, dict) and set(native) == {'consumer', 'producer'}
        and all(hash_value(value) for value in native.values()), 'qualified type native pair differs')
    require(isinstance(protected, dict) and len(protected) == 10
        and all(isinstance(path, str) and path and hash_value(value) for path, value in protected.items())
        and {evidence['productionJarSha256'], *native.values(), *harnesses.values()}.issubset(protected.values()),
        'qualified type protected input inventory differs')
    return 'linux', 'x86_64'


def cohort(cases):
    require(cases == [('linux', 'x86_64')], 'qualified types require exactly one complete Linux x86-64 fixture')

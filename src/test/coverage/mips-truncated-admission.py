"""Require both freestanding MIPS ABIs and compiler/Forge runtime evidence."""
import re


SOURCES = {
    'src/test/integration/mips-truncated-space.py',
    'src/test/integration/mips-truncated-space-export.sh',
    'src/test/integration/mips-truncated-space-check.py',
    'src/test/integration/mips-truncated-space-gdb.py',
    'src/test/integration/dynamic-parameter-storage-check.py',
    'src/test/integration/ghidra_scripts/PrepareMipsTruncatedSpace.java',
    'src/test/integration/qemu-socket.sh',
    'src/test/integration/check-dwarfdump.py',
    'src/test/integration/integration_coverage.py',
    'src/test/coverage/launcher-headless.py',
    'src/test/fixtures/mips-truncated-space.c',
    'src/test/fixtures/mips-truncated-space-start.S',
}
GLOBALS = [{'observed_wide': 0x1122334455667788},
    {'observed_first': -19, 'observed_fifth': -37, 'observed_sixth': 41, 'observed_sum': 16}]
LABELS = [abi + '-' + phase for abi in ('o32', 'n32') for phase in ('curate', 'inspect')]


def require(value, message):
    if not value:
        raise ValueError(message)


def hash_value(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def oracle(record, evidence):
    require(record.get('suite') == 'mips-truncated-space' and record.get('layer') == 'headless'
        and record.get('host') == 'posix' and evidence.get('status') == 'PASS_MIPS_TRUNCATED_SPACE'
        and evidence.get('target') in ('mips32be', 'mips32le'), 'MIPS STORE profile differs')
    require(hash_value(evidence.get('productionJarSha256'))
        and record.get('productionJarSha256') == evidence['productionJarSha256'], 'MIPS STORE JAR differs')
    require([row.get('label') for row in record.get('sessions', [])] == LABELS
        and not record.get('unmeasuredForcedHalts'), 'MIPS STORE exports incomplete')
    sources, protected = evidence.get('harnessSha256'), evidence.get('protected')
    require(isinstance(sources, dict) and set(sources) == SOURCES
        and all(hash_value(value) for value in sources.values()), 'MIPS STORE harness provenance missing')
    require(isinstance(protected, dict) and len(protected) == 4
        and all(isinstance(key, str) and key and hash_value(value) for key, value in protected.items())
        and evidence['productionJarSha256'] in protected.values(), 'MIPS STORE protected inputs missing')
    cases = evidence.get('cases')
    require(isinstance(cases, list) and len(cases) == 2, 'MIPS STORE ABI cases missing')
    for abi, case in zip(('o32', 'n32'), cases):
        require(isinstance(case, dict) and case.get('abi') == abi
            and case.get('deterministic') is True and case.get('inputPreserved') is True
            and case.get('validators') == ['readelf', 'llvm', 'strict']
            and type(case.get('strictErrors')) is int and case['strictErrors'] == 0,
            'MIPS STORE validators or preservation missing')
        require(all(hash_value(case.get(key)) for key in
            ('resultSha256', 'inputSha256', 'outputSha256', 'sourceSha256')), 'MIPS STORE artifact hashes missing')
        observations = case.get('gdb')
        require(isinstance(observations, list) and len(observations) == 2, 'MIPS STORE debugger pair missing')
        for variant, observation in zip(('compiler', 'forge'), observations):
            require(isinstance(observation, dict) and observation.get('variant') == variant
                and observation.get('status') == 'PASS' and observation.get('exitCodes') == [0]
                and observation.get('globalsAfterReturn') == GLOBALS
                and hash_value(observation.get('observationsSha256')), 'MIPS STORE debugger behavior differs')
    return evidence['target']


def cohort(cases, target):
    require(target in ('mips32be', 'mips32le') and cases == [target],
        'MIPS STORE requires one complete target cohort')

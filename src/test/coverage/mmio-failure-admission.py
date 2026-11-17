"""Admit ELF MMIO controls only with the preserved validated generation."""
import re

SOURCES = {'src/test/scenarios/mmio-access/' + name for name in ('failures.py', 'forge.py', 'layout.py')}
SOURCES |= {'src/test/integration/integration_coverage.py', 'ghidra_scripts/GhidraDwarfForge.java',
    'src/test/integration/ghidra_scripts/RunMmioControls.java',
    'src/test/integration/ghidra_scripts/CheckMmioFailures.java'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def hashes(value):
    return isinstance(value, dict) and bool(value) and all(isinstance(k, str) and sha(v) for k, v in value.items())


def oracle(record, evidence):
    require(isinstance(record, dict) and isinstance(evidence, dict), 'invalid MMIO receipt')
    require(record.get('suite') == 'mmio-failure-controls' and record.get('layer') == 'headless'
        and record.get('host') == 'posix', 'unsupported MMIO measurement host/layer')
    sessions = record.get('sessions')
    require(isinstance(sessions, list) and len(sessions) == 1 and isinstance(sessions[0], dict)
        and sessions[0].get('label') == 'failure-controls' and sessions[0].get('status') == 'ORACLE_PASSED'
        and not record.get('launcherInvocations') and not record.get('unmeasuredForcedHalts'),
        'MMIO requires its complete direct analyzer session')
    target = evidence.get('target')
    require(evidence.get('status') == 'PASS_MMIO_FAILURE_MEASUREMENT'
        and target in ('x86_64', 'mips32be', 'mips32le') and evidence.get('rawFirmware') is False
        and type(evidence.get('checks')) is int and evidence['checks'] == 16,
        'missing complete ELF MMIO controls')
    before, after = evidence.get('protectedBefore'), evidence.get('protectedAfter')
    require(hashes(before) and before == after, 'MMIO protected files changed')
    harness = evidence.get('harnessSha256')
    require(hashes(harness) and SOURCES <= harness.keys(), 'missing MMIO source provenance')
    for name in SOURCES:
        require({v for k, v in before.items() if k.endswith('/' + name)} == {harness[name]},
            'MMIO harness provenance differs')
    require([v for k, v in before.items() if k.endswith('/lib/GhidraDwarfForge.jar')]
        == [record.get('productionJarSha256')], 'MMIO measured JAR differs')
    for library in ('libdwarf.so.2.3.2', 'libdwarfp.so.2.3.2'):
        require(len([v for k, v in before.items() if k.endswith('/os/linux_x86_64/' + library)]) == 1,
            'missing MMIO native provenance')
    project = evidence.get('projectBefore')
    require(hashes(project) and project == evidence.get('projectAfter')
        and any(name.startswith('Mmio.rep/idata/') and name.endswith('.gbf') for name in project),
        'MMIO saved program changed or is missing')
    paths = evidence.get('artifactPaths')
    require(isinstance(paths, dict) and paths.keys() == {'input', 'sidecar', 'source', 'profile'}
        and all(isinstance(p, str) and p in before for p in paths.values())
        and len(set(paths.values())) == 4, 'missing distinct MMIO artifact bindings')
    base = evidence.get('baseExport')
    require(isinstance(base, dict) and base.get('status') == 'PASS_LAYOUT_AND_SAVED_SETTINGS'
        and base.get('gaps') == [] and base.get('inputPreservation') == base.get('projectPreservation') == base.get('determinism') == 'PASS'
        and base.get('inputSha256') == before[paths['input']]
        and base.get('outputsSha256') == [before[paths[k]] for k in ('sidecar', 'source', 'profile')],
        'MMIO controls detached from validated deterministic generation')
    fields = [5, 5, 41, 52, -3, 57997] if target == 'mips32be' else [5, 17, 13, 10, -1, 42405]
    require(base.get('values') == {'address': 0x40000000, 'fields': fields, 'raw': 0xa5a5e28d,
        'counter': 17, 'packed': fields[:2], 'widths': [4, 1, 4, 8], 'unionOffsets': [0] * 5,
        'counterOffset': 4, 'flagValues': [1, 8, 128]}, 'MMIO debugger value/layout oracle differs')
    strict = evidence.get('strict')
    require(isinstance(strict, dict) and strict.get('status') == 'PASS'
        and type(strict.get('uncorroborated_errors')) is int and strict['uncorroborated_errors'] == 0,
        'MMIO strict validation incomplete')
    require(sha(evidence.get('logSha256')), 'MMIO control log is unbound')
    controls = evidence.get('controls')
    require(isinstance(controls, dict) and controls == {
        'existing.dbg' + suffix: before[paths[role]]
        for suffix, role in (('', 'sidecar'), ('.c', 'source'), ('.mmio.json', 'profile'))},
        'MMIO failed publication left unexpected files or changed prior output')
    return target


def cohort(cases):
    require(cases == ['x86_64'], 'hosted MMIO cohort is missing, duplicated or from another lane')

"""Require complete static-scope debugger and session evidence before probe admission."""
import re


ROLES = ('exec', 'pie', 'pie-rebased')
SCOPES = ('root', 'outer', 'inner', 'sibling', 'other', 'global')
SEQUENCE = (('root_live', 'root'), ('outer_begin', 'outer'), ('inner_begin', 'inner'),
    ('inner_end', 'outer'), ('outer_end', 'root'), ('sibling_begin', 'sibling'),
    ('sibling_end', 'root'), ('other_live', 'other'), ('global_live', 'global'))
VALUES = dict(zip(SCOPES, (11, 21, 31, 41, 51, 101)))
CONTROL_MODES = ('stale', 'conflict', 'coalesced', 'failed')
RECOVERED_MODES = ('inferred', 'memory')
RECOVERED_CONTROLS = ('inferred-stale', 'inferred-namespace', 'inferred-overlap',
    'inferred-curated', 'memory-stale', 'memory-failed', 'memory-overlay', 'memory-mapped')
SUITES = {'lexical-statics', 'lexical-statics-controls',
    'recovered-statics-positive', 'recovered-statics-controls'}
DEBUGGER = 'GDB batch: values, types, addresses, lexical lookup, instruction stepping and exit 0'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def hashes(value):
    return isinstance(value, dict) and bool(value) and all(
        isinstance(name, str) and isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest)
        for name, digest in value.items())


def pair(value):
    return isinstance(value, list) and len(value) == 2 and all(
        isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) for digest in value)


def observations(rows, mode, objects, labels, role):
    require(isinstance(rows, list) and len(rows) == len(SEQUENCE), 'static debugger requires all nine boundaries')
    biases = set()
    for row, (marker, original_scope) in zip(rows, SEQUENCE):
        scope = original_scope
        if mode == 'stale' and scope == 'inner':
            scope = 'outer'
        if mode == 'conflict' and scope in ('inner', 'sibling'):
            scope = 'outer' if scope == 'inner' else 'root'
        if mode == 'coalesced' and scope in ('outer', 'inner', 'sibling'):
            scope = 'root'
        if mode in ('failed', 'memory-stale', 'memory-failed') and scope in ('root', 'outer', 'inner', 'sibling'):
            scope = 'global'
        if mode in ('inferred-stale', 'inferred-namespace', 'inferred-overlap', 'memory-overlay', 'memory-mapped') and scope == 'other':
            scope = 'global'
        require(isinstance(row, dict) and row.get('marker') == marker and row.get('scope') == scope,
            'static debugger lost lexical identity or boundary ordering')
        require(all(type(row.get(key)) is int for key in ('value', 'address', 'runtimePc', 'bias')),
            'static debugger lacks numeric value/address evidence')
        require(row['value'] == VALUES[scope] and row['address'] == objects[scope]
            and row['runtimePc'] == labels[marker] + row['bias'], 'static debugger value, object or runtime address differs')
        require(row['bias'] == 0 if role == 'exec' else row['bias'] > 0, 'static debugger load bias disagrees with ELF role')
        biases.add(row['bias'])
    require(len(biases) == 1, 'static debugger load bias changed within one process')


def oracle(record, evidence):
    require(isinstance(record, dict) and isinstance(evidence, dict), 'invalid static measurement objects')
    suite, layer, role = record.get('suite'), record.get('layer'), evidence.get('role')
    require(suite in SUITES and role in ROLES and evidence.get('target') == 'x86_64', 'unsupported static measurement profile')
    require(record.get('host') == 'posix', 'static measurement requires the actual Linux harness host')
    require(layer in ('headless', 'native-java') and (layer == 'headless' or suite == 'lexical-statics'),
        'static measurement uses wrong JVM layer')
    require(evidence.get('validators') == ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer']
        and evidence.get('debugger') == DEBUGGER and hashes(evidence.get('protected'))
        and hashes(evidence.get('harnessSha256')), 'static measurement lacks validators, source or preservation evidence')
    required_sources = {'src/test/integration/' + name for name in (
        'lexical-statics-export.py', 'lexical-statics-controls.py', 'recovered-statics-export.py',
        'lexical-statics-gdb.py', 'lexical-statics-gdb.sh', 'integration_coverage.py', 'static_coverage.py',
        'check-lexical-statics.py', 'check-dwarfdump.py')}
    require(required_sources <= evidence['harnessSha256'].keys(), 'static measurement source inventory is incomplete')
    objects, labels = evidence.get('compilerObjects'), evidence.get('labels')
    require(isinstance(objects, dict) and set(objects) == set(SCOPES)
        and all(type(x) is int and x >= 0 for x in objects.values()) and len(set(objects.values())) == 6,
        'static compiler objects are missing or aliased')
    require(isinstance(labels, dict) and all(marker in labels and type(labels[marker]) is int
        and labels[marker] >= 0 for marker, _ in SEQUENCE), 'static compiler boundaries are incomplete')
    observations(evidence.get('compilerObservations'), 'compiler', objects, labels, role)
    measurement = evidence.get('measurement')
    require(isinstance(measurement, dict) and type(measurement.get('directAnalyzerSessions')) is int,
        'static measurement session counts must be integers')
    if suite == 'lexical-statics':
        require(evidence.get('status') == 'PASS_LEXICAL_STATICS_MEASUREMENT'
            and evidence.get('oracleStatus') == 'LEXICAL_STATICS_PASS' and evidence.get('javaRuntime') == 21
            and evidence.get('controls') is True and evidence.get('recovered') is True
            and pair(evidence.get('outputPair')) and evidence.get('observations') == 9,
            'static baseline lacks the complete existing controls or repeatable output')
        require(measurement == {'directAnalyzerSessions': 3, 'directNativeSessions': 1,
            'measuredNestedSuites': ['lexical-statics-controls', 'recovered-statics-positive', 'recovered-statics-controls']},
            'static baseline loses nested measurement obligations')
        require(type(measurement.get('directNativeSessions')) is int, 'native session count must be an integer')
        rows = evidence.get('debuggerObservations')
        require(isinstance(rows, dict) and set(rows) == {'isolated', 'forge'}, 'static baseline loses a debugger consumer')
        for mode, result in rows.items():
            observations(result, mode, objects, labels, role)
        expected_labels = ['isolated-producer'] if layer == 'native-java' else ['import', 'export-first', 'export-repeat']
    else:
        scope_controls = suite == 'lexical-statics-controls'
        recovered_controls = suite == 'recovered-statics-controls'
        modes = CONTROL_MODES if scope_controls else RECOVERED_CONTROLS if recovered_controls else RECOVERED_MODES
        expected_status = 'PASS_STATIC_SCOPE_CONTROLS_MEASUREMENT' if scope_controls else 'PASS_RECOVERED_STATICS_MEASUREMENT'
        expected_oracle = 'STATIC_SCOPE_CONTROLS_PASS' if scope_controls else (
            'RECOVERED_STATICS_CONTROLS_PASS' if recovered_controls else 'RECOVERED_STATICS_POSITIVE_PASS')
        require(evidence.get('status') == expected_status and evidence.get('oracleStatus') == expected_oracle
            and type(evidence.get('cancelledExports')) is int
            and evidence['cancelledExports'] == int(scope_controls or recovered_controls), 'static control completion/cancellation differs')
        if scope_controls:
            require(evidence.get('exports') == 9, 'static control reopen is missing')
        rows = evidence.get('controls' if scope_controls else 'cases')
        require(isinstance(rows, list) and all(isinstance(row, dict) for row in rows)
            and [row.get('mode') for row in rows] == list(modes), 'static control modes are incomplete or duplicated')
        for row in rows:
            require(pair(row.get('outputPair' if scope_controls else 'pair')), 'static control loses repeatable artifact hashes')
            observations(row.get('observations'), row['mode'], objects, labels, role)
        expected_labels = [mode + ('-export-' if scope_controls else '-') + iteration
            for mode in modes for iteration in ('first', 'repeat')]
        if scope_controls or recovered_controls:
            expected_labels += ['cancel-import', 'cancel-export']
        if scope_controls:
            expected_labels += ['baseline-reopen']
        require(measurement == {'directAnalyzerSessions': len(expected_labels), 'modes': list(modes)},
            'static control session declaration differs')
    sessions = record.get('sessions')
    require(isinstance(sessions, list) and all(isinstance(row, dict) for row in sessions)
        and [row.get('label') for row in sessions] == expected_labels, 'missing, duplicate or reordered static JVM sessions')
    return suite, layer, role


def cohort(cases, roles=ROLES):
    expected = {(suite, layer, role) for role in roles for suite, layer in (
        ('lexical-statics', 'headless'), ('lexical-statics', 'native-java'),
        ('lexical-statics-controls', 'headless'), ('recovered-statics-positive', 'headless'),
        ('recovered-statics-controls', 'headless'))}
    require(len(cases) == len(expected) and set(cases) == expected, 'static coverage needs every JVM layer, role and control suite')

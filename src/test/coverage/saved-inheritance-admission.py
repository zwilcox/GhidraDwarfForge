"""Require the existing saved C++ configuration and debugger oracle before admission."""
import re


ROLES = ('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti')
VARIANTS = ('missing', 'stale', 'conflict', 'renamed', 'qualified', 'duplicate', 'retained')
VARIABLES = ('single_base', 'multiple_right', 'diamond_base', 'diamond_right', 'abstract_base')
DYNAMIC = ('Single', 'Multiple', 'Diamond', 'Diamond', 'Concrete')
STATIC = ('Base', 'Right', 'VirtualBase', 'VirtualRight', 'Abstract')
VALUES = {'abstract_base->abstract_value': 41, 'concrete_object->extra': 43,
    'single_object->base': 11, 'single_object->single': 47, 'multiple_object->left': 13,
    'multiple_object->right': 17, 'multiple_object->multiple': 29, 'diamond_object->left': 23,
    'diamond_object->right': 31, 'diamond_object->leaf': 37, 'diamond_object->root': 19,
    'diamond_right->root': 19, 'virtual_left_object->root': 19, 'virtual_right_object->root': 19}
SOURCES = {'src/test/scenarios/inheritance/' + name for name in (
    'extract.py', 'headless_measurement.py', 'measurement.py', 'fixture.cpp',
    'produce.py', 'reference.py', 'gdb.py', 'gdb.sh', 'name-gdb.py', 'thunks-gdb.py',
    'PrepareInheritanceFixture.java', 'ProbeVtableBindings.java', 'RoundTripCxxProfile.java',
    'PrepareAdjustmentThunks.java', 'MutateVtableFixture.java', 'RebaseInheritanceFixture.java')}
SOURCES |= {'ghidra_scripts/GhidraDwarfForge.java', 'ghidra_scripts/GhidraDwarfForgeCxxProfile.java',
    'support/ghidra-dwarf-forge-headless', 'src/test/integration/integration_coverage.py',
    'src/test/coverage/launcher-headless.py', 'src/test/integration/check-object-parameters.py',
    'src/test/integration/qemu-socket.sh'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def hashes(value):
    return isinstance(value, dict) and bool(value) and all(
        isinstance(name, str) and sha(digest) for name, digest in value.items())


def oracle(record, evidence):
    require(isinstance(record, dict) and isinstance(evidence, dict), 'invalid saved inheritance receipt')
    role, variant, target = (evidence.get(key) for key in ('role', 'variant', 'target'))
    rebased, thunks = (evidence.get(key) for key in ('rebased', 'adjustmentThunksRequested'))
    require(record.get('suite') == 'saved-inheritance' and record.get('layer') == 'headless'
        and record.get('host') == 'posix' and target in ('x86_64', 'aarch64')
        and role in ROLES and variant in ('valid', *VARIANTS)
        and type(rebased) is bool and type(thunks) is bool,
        'unsupported saved inheritance host, layer or profile')
    require(evidence.get('status') == 'PASS_SAVED_INHERITANCE_MEASUREMENT'
        and evidence.get('validators') == ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer']
        and evidence.get('debugger') == 'GDB batch: dynamic types, inherited values, vtables and exit 0'
        and hashes(evidence.get('harnessSha256')) and SOURCES <= evidence['harnessSha256'].keys()
        and hashes(evidence.get('protected')), 'saved inheritance lacks complete source/validator evidence')
    label = target + '-' + role
    sessions = record.get('sessions')
    require(isinstance(sessions, list) and len(sessions) == 2
        and all(isinstance(row, dict) for row in sessions)
        and [row.get('label') for row in sessions] == [label + '-curate', label + '-reopen'],
        'saved inheritance requires curation and production-wrapper reopen sessions')
    invocations = record.get('launcherInvocations')
    require(isinstance(invocations, list) and len(invocations) == 1 and isinstance(invocations[0], dict)
        and invocations[0].get('label') == label + '-reopen'
        and invocations[0].get('status') == 'ORACLE_PASSED'
        and invocations[0].get('sessions') == [sessions[1].get('session')]
        and not record.get('unmeasuredForcedHalts'), 'saved inheritance lost its measured wrapper invocation')
    before, after = evidence.get('projectBefore'), evidence.get('projectAfter')
    require(hashes(before) and before == after and any(name.startswith('Inheritance.rep/idata/') for name in before)
        and evidence.get('projectMetadataChanges') == {} and evidence.get('savedProgramUnchanged') is True,
        'saved inheritance must preserve the reopened project')
    require(sha(evidence.get('inputSha256')) and evidence['inputSha256'] == evidence.get('inputAfterSha256'),
        'saved inheritance changed the original executable')
    outputs = evidence.get('phaseOutputs')
    require(isinstance(outputs, list) and len(outputs) == 2
        and all(isinstance(pair, list) and len(pair) == 2 and all(sha(x) for x in pair) for pair in outputs)
        and outputs[0] == outputs[1] == [evidence.get('sidecarSha256'), evidence.get('sourceSha256')],
        'saved inheritance requires identical sidecar and source after reopen')
    reports = evidence.get('phaseReports')
    require(isinstance(reports, list) and len(reports) == 2 and all(isinstance(row, dict) for row in reports)
        and [row.get('phase') for row in reports] == ['curate', 'reopen']
        and all(row.get('status') in ('SUCCESS', 'PARTIAL') and type(row.get('functionsFailed')) is int
            and row['functionsFailed'] == 0 for row in reports), 'saved inheritance export failed or lost a phase')
    configuration = evidence.get('configuration')
    require(isinstance(configuration, dict)
        and configuration.get('counts') == {'classes': 11, 'declarations': 1, 'bases': 8, 'virtual_methods': 15, 'vtables': 7}
        and all(type(value) is int for value in configuration['counts'].values())
        and configuration.get('actions') == [False, True, False]
        and all(type(value) is bool for value in configuration['actions'])
        and sha(configuration.get('selectionSha256')) and sha(configuration.get('recordSnapshotSha256')),
        'saved C++ selection must survive preview, apply and second preview')
    require(evidence.get('modelCounts') == {'classes': 11, 'bases': 8, 'methods': 15}
        and all(type(value) is int for value in evidence['modelCounts'].values())
        and type(evidence.get('tableCount')) is int and evidence['tableCount'] == 7,
        'compiler inheritance inventory is incomplete')
    actual, compiler = evidence.get('observed'), evidence.get('compilerObservation')
    require(isinstance(actual, dict) and isinstance(compiler, dict)
        and compiler.get('status') == 'PASS_REFERENCE_OBSERVATION'
        and compiler.get('inheritedValues') == VALUES, 'missing independent compiler/debugger observation')
    if variant == 'valid':
        require(actual.get('status') == 'PASS_REFERENCE_OBSERVATION'
            and all(actual.get(key) == compiler.get(key) and isinstance(actual.get(key), dict)
                and bool(actual[key]) for key in ('dynamicTypes', 'baseValues', 'offsets', 'inheritedValues')),
            'saved inheritance debugger differs from compiler reference')
        require({key: value.removeprefix('struct ') for key, value in actual['dynamicTypes'].items()
            if isinstance(value, str)} == dict(zip(VARIABLES, (name + ' *' for name in DYNAMIC)))
            and actual['baseValues'] == {'single_base->base': 11, 'multiple_right->right': 17, 'diamond_base->root': 19}
            and set(actual['offsets']) == {'multipleRight', 'diamondBase', 'diamondRight'}
            and all(type(value) is int and value > 0 for value in actual['offsets'].values()),
            'saved inheritance loses dynamic type, member value or physical base offset')
        queries = actual.get('queries')
        require(isinstance(queries, dict) and all(isinstance(queries.get('info vtbl *' + name), dict)
            and isinstance(queries['info vtbl *' + name].get('result'), str)
            and '[0]:' in queries['info vtbl *' + name].get('result', '')
            and 'error' not in queries['info vtbl *' + name] for name in
            ('single_base', 'multiple_right', 'diamond_base', 'abstract_base')), 'missing runtime vtable lookup')
    else:
        negative = variant in ('missing', 'stale', 'conflict')
        expected_status = 'PASS_STATIC_NAME_CONTROL' if negative else 'PASS_RECOVERED_VTABLE_NAMES'
        names = evidence.get('expectedNames')
        require(isinstance(names, dict) and isinstance(names.get('static' if negative else 'dynamic'), dict),
            'missing recovered-name expectations')
        names = names['static' if negative else 'dynamic']
        expected = STATIC if negative else DYNAMIC
        spellings = [('Recovered_' + name if variant == 'renamed' else 'Shared' if variant == 'duplicate' else name)
            for name in expected]
        require(set(names) == set(VARIABLES) and all(isinstance(row, dict) for row in names.values())
            and [names[key].get('name') for key in VARIABLES] == spellings
            and actual.get('status') == expected_status
            and actual.get('dynamicTypes') == dict(zip(VARIABLES, (name + ' *' for name in spellings))),
            'saved name control promoted rejected evidence or lost recovered identity')
        layouts = actual.get('layouts')
        require(isinstance(layouts, dict) and set(layouts) == set(VARIABLES)
            and all(type(names[key].get('size')) is int and names[key]['size'] > 0
                and isinstance(names[key].get('members'), list) and bool(names[key]['members'])
                and layouts[key] == {'size': names[key]['size'], 'members': names[key]['members']} for key in VARIABLES),
            'recovered-name control lost physical type layout')
    observations = evidence.get('adjustmentThunks')
    if not thunks:
        require(observations == [] and evidence.get('thunkEvidence') is None,
            'unrequested adjustment evidence is ambiguous')
    else:
        require(variant == 'valid' and isinstance(observations, list) and len(observations) == 2
            and all(isinstance(row, dict) and row.get('status') == 'PASS_ADJUSTMENT_THUNKS' for row in observations),
            'missing compiler or Forge adjustment-thunk observation')
        expected_names = ['recovered_multiple_adjustor', 'recovered_diamond_virtual_adjustor', 'recovered_diamond_right_adjustor']
        compiler_thunks = evidence.get('thunkEvidence')
        require(isinstance(compiler_thunks, dict) and compiler_thunks.get('target') == target
            and type(compiler_thunks.get('checkpoint')) is int and compiler_thunks['checkpoint'] > 0
            and isinstance(compiler_thunks.get('thunks'), list) and len(compiler_thunks['thunks']) == 3
            and all(isinstance(row, dict) for row in compiler_thunks['thunks'])
            and [row.get('name') for row in compiler_thunks['thunks']] == expected_names
            and [row.get('return') for row in compiler_thunks['thunks']] == [46, 56, 68]
            and all(type(row.get(key)) is int and row[key] > 0 for row in compiler_thunks['thunks']
                for key in ('address', 'size', 'target')), 'missing compiler adjustment-thunk identity')
        for observation in observations:
            rows = observation.get('thunks')
            require(isinstance(rows, list) and len(rows) == 3 and all(isinstance(row, dict) for row in rows)
                and [row.get('name') for row in rows] == expected_names
                and [row.get('return') for row in rows] == [46, 56, 68]
                and [row.get('kind') for row in rows] == ['fixed', 'virtual', 'fixed']
                and all(type(row.get('adjustment')) is int and row['adjustment'] < 0
                    and type(row.get('steps')) is int and 1 <= row['steps'] <= 6 for row in rows),
                'adjustment thunk lost physical this adjustment, stepping or return value')
            bias = observation.get('bias')
            require(type(bias) is int and (bias > 0 if role.startswith('pie') else bias == 0),
                'adjustment thunk lost runtime load bias')
        require(observations[0]['thunks'] == observations[1]['thunks']
            and observations[0].get('callRestrictions') == []
            and isinstance(observations[1].get('callRestrictions'), list)
            and len(observations[1]['callRestrictions']) == 3
            and all(isinstance(x, str) and 'does not follow the target calling convention' in x
                for x in observations[1]['callRestrictions']), 'adjustment behavior or debugger-call restrictions changed')
    return target, role, variant, rebased, thunks


def cohort(cases, target='x86_64'):
    expected = {(target, role, 'valid', False, True) for role in ROLES}
    expected |= {(target, role, 'valid', True, True) for role in ('pie', 'pie-no-rtti')}
    expected |= {(target, role, variant, True, False) for role in ROLES for variant in VARIANTS}
    require(len(cases) == len(expected) and set(cases) == expected,
        'saved inheritance requires all 34 existing role, rebase, RTTI and name/control cases')

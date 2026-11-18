"""Require complete stack-transition debugger and byte-oracle evidence."""
import re


SHAPES = {'keep': 4, 'respill': 6, 'loss': 3, 'badload': 2, 'alias': 2, 'chainloss': 5}
ROLES = {'exec', 'pie', 'pie-rebased'}
SOURCES = {'src/test/integration/' + name for name in ('stack-value-transitions-export.py',
    'stack-value-transitions-gdb.py', 'stack-value-transitions-gdb.sh', 'check-stack-value-transitions-locations.py',
    'ghidra_scripts/PrepareStackValueTransitions.java', 'ghidra_scripts/RebaseFixtureProgram.java',
    'integration_coverage.py', 'stack_transition_evidence.py', 'qemu-socket.sh', 'elf-layout-gdb-oracle.sh', 'check-dwarfdump.py')}
SOURCES |= {'src/test/fixtures/stack-value-transitions.c', 'src/test/performance/export-benchmark.py',
    'ghidra_scripts/GhidraDwarfForge.java'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def hashes(value):
    return isinstance(value, dict) and bool(value) and all(isinstance(k, str) and sha(v) for k, v in value.items())


def oracle(record, evidence):
    require(isinstance(record, dict) and isinstance(evidence, dict), 'invalid stack-transition receipt')
    target, role = evidence.get('target'), evidence.get('role')
    require(target in ('x86_64', 'aarch64') and isinstance(role, str) and role in ROLES
        and record.get('suite') == 'stack-value-transitions' and record.get('layer') == 'headless'
        and record.get('host') == 'posix', 'unsupported stack-transition profile')
    sessions = record.get('sessions')
    require(isinstance(sessions, list) and len(sessions) == 4 and all(isinstance(row, dict) for row in sessions)
        and [row.get('label') for row in sessions] == ['import', 'curate', 'fixed', 'repeat']
        and not record.get('launcherInvocations') and not record.get('unmeasuredForcedHalts')
        and evidence.get('historicalComparisonMeasured') is False, 'missing or mixed stack-transition sessions')
    require(evidence.get('status') == 'PASS_STACK_TRANSITION_MEASUREMENT'
        and evidence.get('validators') == ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer']
        and evidence.get('protectedUnchanged') is True, 'missing complete stack-transition oracle')
    before, after, harness = evidence.get('protectedBefore'), evidence.get('protectedAfter'), evidence.get('harnessSha256')
    require(hashes(before) and before == after and hashes(harness) and SOURCES <= harness.keys(), 'missing preserved inputs/harnesses')
    for name in SOURCES:
        require({value for path, value in before.items() if path.endswith('/' + name)} == {harness[name]}, 'changed harness hash')
    require([value for path, value in before.items() if path.endswith('/lib/GhidraDwarfForge.jar')]
        == [record.get('productionJarSha256')], 'protected JAR differs from measured JAR')
    require([value for path, value in before.items() if path.endswith('/local.input')]
        == [evidence.get('inputSha256')], 'protected input differs')
    pb, pa = evidence.get('projectBefore'), evidence.get('projectAfter')
    require(hashes(pb) and hashes(pa) and any(name.startswith('Local.rep/idata/') and name.endswith('.gbf') for name in pb),
        'missing saved program inventory')
    changes = sorted(name for name in pb.keys() | pa.keys() if pb.get(name) != pa.get(name))
    require(set(changes) <= {'Local.rep/idata/~index.bak', 'Local.rep/idata/~journal.bak'}
        and evidence.get('projectBackupChanges') == changes, 'saved program changed or changes concealed')
    models, pair = evidence.get('modelHashes'), evidence.get('artifactSha256')
    require(isinstance(models, list) and len(models) == 3 and all(sha(x) for x in models) and len(set(models)) == 1
        and isinstance(pair, list) and len(pair) == 2 and all(sha(x) for x in pair), 'nondeterministic model or missing output')
    delta = evidence.get('rebaseDelta')
    require(type(delta) is int and delta >= 0 and (role != 'pie-rebased' or delta >= 0x2000000), 'missing explicit rebase')
    strict = evidence.get('strict')
    require(isinstance(strict, dict) and strict.get('status') == 'PASS'
        and type(strict.get('uncorroborated_errors')) is int and strict['uncorroborated_errors'] == 0, 'validator did not pass')
    reports = evidence.get('reports')
    require(isinstance(reports, list) and len(reports) == 2 and all(isinstance(row, dict) for row in reports)
        and [row.get('phase') for row in reports] == ['fixed', 'repeat'], 'missing both export reports')
    for row in reports:
        artifacts = row.get('artifacts')
        require(type(row.get('functionsFailed')) is int and row['functionsFailed'] == 0 and isinstance(artifacts, dict)
            and artifacts.get('inputSha256') == evidence['inputSha256']
            and [artifacts.get('outputSha256'), artifacts.get('sourceSha256')] == pair, 'failed or mismatched export')
    names = {'transfer_' + shape + str(width) for shape in SHAPES for width in (32, 64)}
    functions = evidence.get('functions')
    require(isinstance(functions, list) and len(functions) == 12 and all(isinstance(row, dict)
        and isinstance(row.get('name'), str) for row in functions) and {row['name'] for row in functions} == names,
        'missing function shapes or widths')
    by_name = {row['name']: row for row in functions}
    locations = evidence.get('locations')
    require(isinstance(locations, dict) and locations.get('stack_value_transitions_locations') == 'PASS'
        and isinstance(locations.get('functions'), dict) and locations['functions'].keys() == names, 'missing raw location oracle')
    for name, row in by_name.items():
        width, shape = (4 if name.endswith('32') else 8), name.removeprefix('transfer_')[:-2]
        require(type(row.get('width')) is int and row['width'] == width and row.get('shape') == shape, 'wrong value width/shape')
        pcs, ranges = row.get('instructionPcs'), row.get('locations')
        require(isinstance(pcs, list) and len(pcs) >= 3 and all(type(pc) is int for pc in pcs) and pcs == sorted(set(pcs))
            and row.get('entry') == pcs[0] and row.get('return') == pcs[-1]
            and type(row.get('end')) is int and row['end'] > pcs[-1], 'incomplete instruction boundary inventory')
        require(isinstance(ranges, list) and len(ranges) == SHAPES[shape], 'missing value transitions')
        end = row['entry']
        for item in ranges:
            require(isinstance(item, list) and len(item) == 4 and all(type(v) is int for v in (item[0], item[1], item[3]))
                and end <= item[0] < item[1] <= row['end'] and item[0] in pcs
                and item[1] in pcs + [row['end']] and item[2] in ('r', 's') and 0 <= item[3] <= 31,
                'invalid transition boundary or carrier')
            end = item[1]
        raw = locations['functions'][name]
        require(isinstance(raw, list) and len(raw) == len(ranges), 'incomplete serialized locations')
        for item, expected in zip(raw, ranges):
            require(isinstance(item, list) and len(item) == 3 and item[:2] == expected[:2]
                and isinstance(item[2], str) and re.fullmatch('[0-9a-f]+', item[2]) is not None, 'serialized interval differs')
            if expected[2] == 'r':
                require(item[2] == '90' + format(expected[3], '02x'), 'wrong serialized register')
            else:
                require(len(item[2]) == 6 and item[2].startswith('9207' if target == 'x86_64' else '921f')
                    and int(item[2][-2:], 16) < 128, 'wrong stack pointer expression')
    runs = evidence.get('runtime')
    require(isinstance(runs, list) and len(runs) == 2 and all(isinstance(row, dict) for row in runs)
        and [row.get('variant') for row in runs] == ['compiler', 'forge'], 'missing compiler/Forge runtime pair')
    for run in runs:
        navigation = run.get('navigation')
        require(run.get('status') == 'PASS' and run.get('exitCodes') == [0] and type(run['exitCodes'][0]) is int
            and sha(run.get('rawSha256')) and isinstance(navigation, list) and len(navigation) == 2
            and all(isinstance(row, dict) and type(row.get('pc')) is int for row in navigation)
            and [row.get('command') for row in navigation] == ['next', 'step'], 'runtime/source stepping incomplete')
        cases = run.get('cases')
        require(isinstance(cases, list) and len(cases) == 36 and all(isinstance(row, dict) for row in cases), 'missing signed input cases')
        seen = set()
        for case in cases:
            name, argument = case.get('function'), case.get('input')
            require(isinstance(name, str) and name in names and type(argument) is int, 'invalid runtime input')
            function = by_name[name]
            require(argument in (19, -19, -1985229329 if function['width'] == 4 else -81985529216486895)
                and (name, argument) not in seen, 'duplicated or unexpected runtime case')
            seen.add((name, argument))
            expected = sum(any(low <= pc < high for low, high, _, _ in function['locations']) for pc in function['instructionPcs'])
            count = len(function['instructionPcs'])
            values = {'points': count, 'availablePoints': expected, 'unavailablePoints': count - expected,
                'valueChecks': expected if run['variant'] == 'forge' else 0,
                'firstLinkPc': function['entry'], 'lastLinkPc': function['return'],
                'value': argument if function['shape'] in ('keep', 'respill', 'alias') else 0}
            require(all(type(case.get(key)) is int and case[key] == value for key, value in values.items())
                and type(case.get('physicalChecks')) is int and 0 < case['physicalChecks'] <= count
                and type(case.get('runtimeBias')) is int and (role == 'exec' or case['runtimeBias'] != 0),
                'missing instruction/value/physical-state checks or runtime relocation')
    return {'target': target, 'role': role, 'input': evidence['inputSha256'], 'delta': delta,
        'functions': functions, 'locations': locations}


def cohort(cases, targets):
    require(set(targets) <= {'x86_64', 'aarch64'} and bool(targets), 'unknown stack-transition cohort target')
    expected = {(target, role) for target in targets for role in ROLES}
    require(len(cases) == len(expected) and {(row['target'], row['role']) for row in cases} == expected,
        'missing or duplicated stack-transition address/target profile')
    for target in targets:
        pie, rebased = (next(row for row in cases if row['target'] == target and row['role'] == role)
            for role in ('pie', 'pie-rebased'))
        require(pie['input'] == rebased['input'] and pie['functions'] == rebased['functions']
            and pie['locations'] == rebased['locations'] and pie['delta'] != rebased['delta'],
            'rebased PIE changed link-time semantics or did not rebase')

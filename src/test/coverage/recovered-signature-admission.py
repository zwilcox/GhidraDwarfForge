"""Admit recovered-signature sessions only with their full behavioral evidence."""
import re


PROFILES = {
    'returns': ('recovered-default-returns', 'Returns', 'ObserveRecoveredReturns', 'CheckRecoveredReturnPass'),
    'parameters': ('recovered-parameter-types', 'Parameters', 'ObserveRecoveredParameters', 'CheckRecoveredParameterPass'),
}
COMMON = {'src/test/integration/' + name for name in ('integration_coverage.py', 'recovered_signature_coverage.py',
    'check-dwarfdump.py', 'dynamic-composite-storage-check.py', 'dynamic-parameter-storage-check.py')}
COMMON |= {'src/test/performance/export-benchmark.py', 'ghidra_scripts/GhidraDwarfForge.java'}
RETURN_NAMES = {'recovered_signed', 'recovered_unsigned', 'recovered_double', 'curated_pointer', 'curated_void'}
PARAMETER_NAMES = {'inferred_scalar', 'inferred_pointer', 'inferred_floating', 'unresolved_pair', 'curated_scalar'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def hashes(value):
    return isinstance(value, dict) and bool(value) and all(isinstance(k, str) and sha(v) for k, v in value.items())


def inventory(rows, names):
    require(isinstance(rows, list) and len(rows) == len(names) and all(isinstance(row, dict)
        and isinstance(row.get('name'), str) for row in rows), 'incomplete recovered-signature inventory')
    require({row['name'] for row in rows} == names, 'wrong recovered-signature names')
    return {row['name']: row for row in rows}


def sources(kind):
    stem, _, observe, check = PROFILES[kind]
    return COMMON | {'src/test/fixtures/' + stem + '.c', 'src/test/integration/' + stem + '-export.py',
        'src/test/integration/' + stem + '-gdb.py', 'src/test/integration/ghidra_scripts/' + observe + '.java',
        'src/test/integration/ghidra_scripts/' + check + '.java'}


def oracle(record, evidence):
    require(isinstance(record, dict) and isinstance(evidence, dict), 'invalid recovered-signature receipt')
    kind = evidence.get('kind')
    require(isinstance(kind, str) and kind in PROFILES, 'unknown recovered-signature profile')
    stem, project, _, _ = PROFILES[kind]
    require(record.get('suite') == 'recovered-' + kind and record.get('layer') == 'headless'
        and record.get('host') == 'posix' and evidence.get('target') == 'x86_64' and evidence.get('role') == 'exec',
        'unsupported recovered-signature execution')
    sessions = record.get('sessions')
    require(isinstance(sessions, list) and len(sessions) == 3 and all(isinstance(row, dict) for row in sessions)
        and [row.get('label') for row in sessions] == ['import', 'fixed', 'repeat']
        and not record.get('launcherInvocations') and not record.get('unmeasuredForcedHalts')
        and evidence.get('historicalComparisonMeasured') is False, 'missing or mixed-version analyzer sessions')
    require(evidence.get('status') == 'PASS_RECOVERED_SIGNATURE_MEASUREMENT'
        and evidence.get('validators') == ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer']
        and evidence.get('protectedUnchanged') is True, 'incomplete recovered-signature oracle')
    before, after = evidence.get('protectedBefore'), evidence.get('protectedAfter')
    harness = evidence.get('harnessSha256')
    require(hashes(before) and before == after and hashes(harness) and sources(kind) <= harness.keys(),
        'missing protected inputs or harness sources')
    for name in sources(kind):
        require({value for path, value in before.items() if path.endswith('/' + name)} == {harness[name]},
            'recovered-signature harness hash mismatch')
    require([value for path, value in before.items() if path.endswith('/lib/GhidraDwarfForge.jar')]
        == [record.get('productionJarSha256')], 'protected measured production JAR differs')
    require([value for path, value in before.items() if path.endswith('/' + kind + '.input')]
        == [evidence.get('inputSha256')], 'protected target differs')
    pb, pa = evidence.get('projectBefore'), evidence.get('projectAfter')
    require(hashes(pb) and hashes(pa) and any(name.startswith(project + '.rep/idata/') and name.endswith('.gbf')
        for name in pb), 'missing saved-program bytes')
    changes = sorted(name for name in pb.keys() | pa.keys() if pb.get(name) != pa.get(name))
    require(set(changes) <= {project + '.rep/idata/~index.bak', project + '.rep/idata/~journal.bak'}
        and evidence.get('projectBackupChanges') == changes, 'saved program was changed or changes concealed')
    models = evidence.get('modelHashes')
    pair = evidence.get('artifactSha256')
    require(isinstance(models, list) and len(models) == 3 and all(sha(x) for x in models) and len(set(models)) == 1
        and isinstance(pair, list) and len(pair) == 2 and all(sha(x) for x in pair), 'missing deterministic model/artifacts')
    strict = evidence.get('strict')
    require(isinstance(strict, dict) and strict.get('status') == 'PASS'
        and type(strict.get('uncorroborated_errors')) is int and strict['uncorroborated_errors'] == 0,
        'recovered-signature validator did not pass')
    reports = evidence.get('reports')
    require(isinstance(reports, list) and len(reports) == 2 and all(isinstance(row, dict) for row in reports)
        and [row.get('phase') for row in reports] == ['fixed', 'repeat'], 'missing both export reports')
    for report in reports:
        counts, artifacts = report.get('counts'), report.get('artifacts')
        require(isinstance(counts, dict) and type(counts.get('functionsFailed')) is int and counts['functionsFailed'] == 0
            and isinstance(artifacts, dict) and artifacts.get('inputSha256') == evidence['inputSha256']
            and [artifacts.get('outputSha256'), artifacts.get('sourceSha256')] == pair, 'failed export or detached output')
    names = RETURN_NAMES if kind == 'returns' else PARAMETER_NAMES
    functions = inventory(evidence.get('functions'), names)
    dies = inventory(evidence.get('functionDIEs'), names)
    for name, die in dies.items():
        attributes = die.get('attributes')
        require(isinstance(attributes, list) and all(isinstance(x, str) for x in attributes)
            and ('DW_AT_prototyped' in attributes) == name.startswith('curated_'),
            'inference asserted a complete prototype or curated signature lost')
    if kind == 'returns':
        for name, dtype, size in [('recovered_signed', 'int', 4), ('recovered_unsigned', 'ulong', 8), ('recovered_double', 'double', 8)]:
            row = functions[name]
            require(row.get('signatureSource') == row.get('returnSource') == 'DEFAULT' and row.get('formalName') == 'undefined'
                and row.get('recoveredName') == dtype and type(row.get('recoveredBytes')) is int and row['recoveredBytes'] == size,
                'lost default-signature return inference')
        require(all(functions[name].get('returnSource') == 'USER_DEFINED' for name in ('curated_pointer', 'curated_void')),
            'curated returns lost precedence')
    else:
        require(functions['curated_scalar'].get('signatureSource') == 'USER_DEFINED'
            and functions['curated_scalar'].get('listingParameterCount') == 1, 'curated parameter lost precedence')
        for name, dtype, size in [('inferred_scalar', 'int', 4), ('inferred_pointer', 'int *', 8), ('inferred_floating', 'double', 8)]:
            row = functions[name]
            parameters = row.get('parameters')
            require(row.get('signatureSource') == 'DEFAULT' and type(row.get('listingParameterCount')) is int
                and row['listingParameterCount'] == 0 and row.get('customStorage') is False and row.get('varargs') is False
                and isinstance(parameters, list) and len(parameters) == 1 and isinstance(parameters[0], dict),
                'inferred parameter gained saved formal storage')
            p = parameters[0]
            require((p.get('name'), p.get('type'), p.get('bytes')) == ('param_1', dtype, size)
                and p.get('hidden') is False and p.get('thisPointer') is False, 'lost inferred parameter type')
            children = dies[name].get('parameters')
            require(isinstance(children, list) and len(children) == 1 and isinstance(children[0], dict)
                and children[0].get('name') == 'param_1' and isinstance(children[0].get('attributes'), list)
                and all(isinstance(x, str) for x in children[0]['attributes'])
                and not {'DW_AT_location', 'DW_AT_const_value', 'DW_AT_artificial'} & set(children[0]['attributes']),
                'inferred parameter gained invented location')
            for report in reports:
                omitted = report.get('omittedLocations')
                require(isinstance(omitted, list) and all(isinstance(x, dict) for x in omitted), 'missing omission diagnostics')
                found = [x for x in omitted if x.get('function') == name]
                require(len(found) == 1 and found[0].get('variable') == 'param_1' and found[0].get('kind') == 'PARAMETER'
                    and found[0].get('reason') == 'UNKNOWN_LIFETIME', 'uncertain location omission was lost')
        unresolved = functions['unresolved_pair']
        require(unresolved.get('signatureSource') == 'DEFAULT' and unresolved.get('listingParameterCount') == 0
            and dies['unresolved_pair'].get('parameters') == [], 'unsupported parameter list was partially emitted')
    runs = evidence.get('gdb')
    require(isinstance(runs, list) and len(runs) == 2 and all(isinstance(row, dict) for row in runs)
        and [row.get('variant') for row in runs] == ['compiler', 'forge'], 'missing compiler/Forge debugger evidence')
    expected = {'recovered_signed': -41, 'recovered_unsigned': 41, 'recovered_double': 1.75} if kind == 'returns' else {
        'inferred_scalar': -41, 'inferred_pointer': 41, 'inferred_floating': 1.75}
    for run in runs:
        require(run.get('status') == 'PASS' and run.get('exitCodes') == [0] and type(run['exitCodes'][0]) is int
            and run.get('sourceSteps') in (['next'], ['next', 'step']), 'missing normal exit or source stepping')
        observed = run.get('functions')
        require(isinstance(observed, dict) and observed.keys() == expected.keys(), 'missing runtime observations')
        for name, value in expected.items():
            row = observed[name]
            require(isinstance(row, dict) and type(row.get('returnedValue')) in (int, float) and row['returnedValue'] == value
                and isinstance(row.get('prototype'), str) and bool(row['prototype']), 'wrong function return or prototype')
            if kind == 'parameters':
                if run['variant'] == 'forge':
                    require(row.get('valueStatus') == 'unavailable' and 'argument' not in row, 'invented inferred argument value')
                else:
                    require(row.get('argument') == {'inferred_scalar': -123, 'inferred_pointer': 123, 'inferred_floating': 1.5}[name],
                        'compiler argument reference differs')
            else:
                size = 8 if name == 'recovered_double' or (name == 'recovered_unsigned' and run['variant'] == 'forge') else 4
                require(row.get('returnBytes') == size, 'inferred/compiler return widths were conflated')
    return kind


def cohort(cases):
    require(sorted(cases) == ['parameters', 'returns'], 'missing or duplicated recovered-signature profile')

"""Require the complete compiler, declaration-DIE and debugger oracle before admission."""
import re


SOURCES = {'src/test/integration/' + name for name in (
    'external-function-declarations-export.sh', 'external-function-declarations-export.py',
    'external-function-declarations-check.py', 'external-function-declarations-gdb.py',
    'ghidra_scripts/PrepareExternalDeclarations.java', 'integration_coverage.py',
    'dynamic-composite-storage-check.py', 'dynamic-parameter-storage-check.py',
    'retained-function-aliases-export.py', 'check-dwarfdump.py')}
SOURCES |= {'src/test/fixtures/external-function-declarations.c', 'ghidra_scripts/GhidraDwarfForge.java'}
METADATA = {'ExternalDeclarations.rep/idata/~index.bak', 'ExternalDeclarations.rep/idata/~journal.bak'}
UNLOCATED = {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges', 'DW_AT_entry_pc',
    'DW_AT_location', 'DW_AT_frame_base', 'DW_AT_decl_file', 'DW_AT_decl_line', 'DW_AT_linkage_name'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def hashes(value):
    return isinstance(value, dict) and bool(value) and all(isinstance(k, str) and sha(v) for k, v in value.items())


def strings(value):
    return isinstance(value, list) and all(isinstance(v, str) for v in value) and len(value) == len(set(value))


def oracle(record, evidence):
    require(isinstance(record, dict) and isinstance(evidence, dict), 'invalid external-declaration receipt')
    require(record.get('suite') == 'external-declarations' and record.get('layer') == 'headless'
        and record.get('host') == 'posix' and evidence.get('target') == 'x86_64'
        and evidence.get('role') == 'exec', 'unsupported external-declaration profile')
    sessions = record.get('sessions')
    require(isinstance(sessions, list) and len(sessions) == 2 and all(isinstance(row, dict) for row in sessions)
        and [row.get('label') for row in sessions] == ['export-curate', 'export-reopen']
        and not record.get('launcherInvocations') and not record.get('unmeasuredForcedHalts'),
        'external declarations require both direct analyzer sessions')
    require(evidence.get('status') == 'PASS_EXTERNAL_DECLARATIONS_MEASUREMENT'
        and evidence.get('validators') == ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer']
        and hashes(evidence.get('harnessSha256')) and SOURCES <= evidence['harnessSha256'].keys()
        and evidence.get('protectedUnchanged') is True, 'missing full external-declaration oracle')
    strict = evidence.get('strict')
    require(isinstance(strict, dict) and strict.get('status') == 'PASS'
        and type(strict.get('uncorroborated_errors')) is int and strict['uncorroborated_errors'] == 0,
        'external-declaration validation was incomplete')
    models = evidence.get('modelHashes')
    require(isinstance(models, list) and len(models) == 2 and all(sha(x) for x in models)
        and models[0] == models[1], 'saved external-declaration model changed')
    pairs = evidence.get('phaseOutputs')
    require(isinstance(pairs, list) and len(pairs) == 2 and all(isinstance(pair, list) and len(pair) == 2
        and all(sha(x) for x in pair) for pair in pairs) and pairs[0] == pairs[1], 'nondeterministic external-declaration outputs')
    before, after = evidence.get('projectBefore'), evidence.get('projectAfter')
    require(hashes(before) and hashes(after) and any(name.startswith('ExternalDeclarations.rep/idata/')
        and name.endswith('.gbf') for name in before),
        'missing saved program inventory')
    changes = {name: [before.get(name), after.get(name)] for name in before.keys() | after.keys()
        if before.get(name) != after.get(name)}
    require(changes.keys() <= METADATA and evidence.get('projectMetadataChanges') == changes,
        'reopen changed saved program data or concealed project changes')
    protected = evidence.get('protected')
    require(isinstance(protected, dict) and bool(protected) and all(isinstance(name, str) and
        isinstance(value, dict) and sha(value.get('sha256')) for name, value in protected.items()),
        'missing protected inputs and harnesses')
    inputs = [value['sha256'] for name, value in protected.items() if name.endswith('/decl.stripped')]
    jars = [value['sha256'] for name, value in protected.items() if name.endswith('/lib/GhidraDwarfForge.jar')]
    require(len(inputs) == 1 and len(jars) == 1 and jars[0] == record.get('productionJarSha256'),
        'protected input or measured production JAR is ambiguous')
    for source in SOURCES:
        observed = {value['sha256'] for name, value in protected.items() if name.endswith('/' + source)}
        require(observed == {evidence['harnessSha256'][source]}, 'protected harness differs from measured sources')
    reports = evidence.get('phaseReports')
    require(isinstance(reports, list) and len(reports) == 2 and all(isinstance(row, dict) for row in reports)
        and [row.get('phase') for row in reports] == ['curate', 'reopen'], 'missing export reports')
    for row, pair in zip(reports, pairs):
        artifacts = row.get('artifacts')
        require(type(row.get('functionsFailed')) is int and row['functionsFailed'] == 0
            and isinstance(artifacts, dict) and artifacts.get('inputSha256') == inputs[0]
            and [artifacts.get('outputSha256'), artifacts.get('sourceSha256')] == pair,
            'failed export or detached artifact hashes')
    prototype = evidence.get('compilerPrototype')
    require(prototype == {'returnBytes': 8, 'argumentBytes': [4], 'signed': True}
        and type(prototype['returnBytes']) is int and type(prototype['argumentBytes'][0]) is int
        and prototype['signed'] is True,
        'missing independent compiler prototype')
    declarations, dies = evidence.get('declarations'), evidence.get('declarationDIEs')
    require(isinstance(declarations, list) and len(declarations) == 3 and all(isinstance(row, dict) for row in declarations)
        and isinstance(dies, list) and all(isinstance(row, dict) for row in dies), 'missing declaration inventory')
    names, die_names = [row.get('name') for row in declarations], [row.get('name') for row in dies]
    require(strings(names) and all(name.strip() for name in names) and strings(die_names) and set(names) == set(die_names)
        and sum(name.endswith('::imported_adjust') for name in names) == 1
        and {'analyst_library::never_called', 'analyst_library::external_aggregate'} <= set(names)
        and not any(name.endswith('::unknown_signature') for name in names), 'wrong external-declaration names')
    by_name = {row['name']: row for row in declarations}
    for die in dies:
        declaration = by_name[die['name']]
        require(not {'address', 'locals'} & declaration.keys() and declaration.get('signatureSource') == 'USER_DEFINED',
            'external declaration gained a location or lost curated provenance')
        require(type(declaration.get('noReturn')) is bool and type(declaration.get('variadic')) is bool,
            'invalid declaration flags')
        attributes, children = die.get('attributes'), die.get('children')
        require(strings(attributes) and {'DW_AT_declaration', 'DW_AT_external', 'DW_AT_prototyped', 'DW_AT_type'} <= set(attributes)
            and not UNLOCATED & set(attributes) and isinstance(children, list)
            and all(isinstance(child, dict) for child in children), 'external declaration gained executable metadata')
        require(type(die.get('noReturn')) is bool and die['noReturn'] == declaration.get('noReturn')
            and die['noReturn'] == ('DW_AT_noreturn' in attributes), 'no-return declaration flag disagrees')
        parameters = declaration.get('parameters')
        require(isinstance(parameters, list) and all(isinstance(p, dict) for p in parameters), 'missing formal parameters')
        require(all(all(type(p.get(flag)) is bool for flag in ('artificial', 'returnStorage', 'objectPointer'))
            for p in parameters), 'invalid formal parameter flags')
        expected = [('DW_TAG_variable' if p.get('returnStorage') else 'DW_TAG_formal_parameter', p.get('name'), p.get('artificial'))
            for p in parameters]
        if declaration.get('variadic'):
            expected.append(('DW_TAG_unspecified_parameters', '', False))
        require([(c.get('tag'), c.get('name'), c.get('artificial')) for c in children] == expected,
            'parameter, artificial carrier or variadic DIE inventory disagrees')
        for child in children:
            attributes = child.get('attributes')
            require(strings(attributes) and not {'DW_AT_location', 'DW_AT_const_value'} & set(attributes)
                and type(child.get('artificial')) is bool
                and child['artificial'] == ('DW_AT_artificial' in attributes), 'invented parameter location or carrier flag')
    unused = by_name['analyst_library::never_called']
    imported = next(row for name, row in by_name.items() if name.endswith('::imported_adjust'))
    require([p.get('name') for p in imported['parameters']] == ['value'] and
        [p.get('name') for p in unused['parameters']] == ['cookie']
        and all(p['returnStorage'] is False and p['artificial'] is False and p['objectPointer'] is False
            for row in (unused, imported) for p in row['parameters']), 'independent scalar declaration prototype changed')
    require(unused.get('noReturn') is True and unused.get('variadic') is True, 'lost variadic/no-return control')
    aggregate = by_name['analyst_library::external_aggregate']['parameters']
    require(len(aggregate) == 2 and aggregate[0].get('returnStorage') is True and aggregate[0].get('artificial') is True
        and aggregate[1].get('name') == 'seed' and aggregate[1].get('returnStorage') is False,
        'aggregate return carrier was turned into an explicit argument')
    runs = evidence.get('gdb')
    require(isinstance(runs, list) and len(runs) == 2 and all(isinstance(row, dict) for row in runs)
        and [row.get('variant') for row in runs] == ['compiler', 'forge'], 'missing independent debugger run')
    for row in runs:
        expected_names = ['imported_adjust'] if row['variant'] == 'compiler' else names
        require(row.get('status') == 'PASS' and type(row.get('observed')) is int and row['observed'] == 12
            and row.get('exitCodes') == [0] and type(row['exitCodes'][0]) is int
            and strings(row.get('unlocatedDeclarations')) and set(row['unlocatedDeclarations']) == set(expected_names)
            and row.get('sourceSteps') in (['next'], ['next', 'step'])
            and isinstance(row.get('source'), str) and bool(row['source'])
            and isinstance(row.get('prototype'), str) and bool(row['prototype']), 'incomplete runtime/source/declaration debugger oracle')
    return ('x86_64', 'exec')


def cohort(cases):
    require(cases == [('x86_64', 'exec')], 'external-declaration cohort is missing or duplicated')

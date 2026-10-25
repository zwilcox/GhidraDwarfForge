#!/usr/bin/env python3
"""Actual inferred parameter types, honest location omissions and compiler/GDB oracles."""
import argparse
import importlib.util
import json
from pathlib import Path
import os
import shutil
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('benchmark_support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--previous-ghidra', type=Path)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/recovered-parameter-types'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='x86_64.', dir=root))
    print(case, flush=True)
    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')
    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result
    fixture = repository / 'src/test/fixtures/recovered-parameter-types.c'
    protected = [fixture, Path(__file__).resolve(), source / 'recovered-parameter-types-gdb.py',
        source / 'ghidra_scripts/ObserveRecoveredParameters.java',
        source / 'ghidra_scripts/CheckRecoveredParameterPass.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    reference, binary = case / 'parameters.reference', case / 'parameters.input'
    run('compile', ['gcc', '-O1', '-g3', '-gdwarf-5', '-fno-inline', '-fno-ipa-sra',
        '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-Wl,--build-id=none', fixture, '-o', reference])
    run('strip', ['objcopy', '--strip-debug', reference, binary])
    original = support.digest(binary)
    run('plain', [binary])
    project = case / 'project'
    project.mkdir()
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Parameters', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'ObserveRecoveredParameters.java', 'curate', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    artifact_hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'parameters.dbg')
        pass_check = [] if variant == 'previous' else ['-postScript', 'CheckRecoveredParameterPass.java']
        run(variant, [installation / 'support/analyzeHeadless', project, 'Parameters', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'ObserveRecoveredParameters.java', 'observe', case / (variant + '.json'),
            *pass_check, '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        assert 'GhidraDwarfForge symbol export PASS' in (case / (variant + '.log')).read_text()
        if variant == 'previous':
            continue
        assert 'recovered-parameter-pass=PASS' in (case / (variant + '.log')).read_text()
        hashes = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        if artifact_hashes is not None:
            assert artifact_hashes == hashes
        artifact_hashes = hashes
        if variant == 'fixed':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
    metadata = json.loads((case / 'fixed.json').read_text())
    assert metadata == json.loads((case / 'repeat.json').read_text())
    assert metadata['functions'] == json.loads((case / 'import.json').read_text())['functions']
    assert Path(unquote(urlsplit(metadata['exporterOrigin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in (case / 'fixed.log').read_text().splitlines() if 'GhidraDwarfForge report: {' in line]
    report, = reports
    assert report['status'] == 'PARTIAL' and not report['failedFunctions']
    write('report.json', report)
    by_name = {row['name']: row for row in metadata['functions']}
    for name, dtype, size in [('inferred_scalar', 'int', 4), ('inferred_pointer', 'int *', 8), ('inferred_floating', 'double', 8)]:
        row = by_name[name]
        assert row['signatureSource'] == 'DEFAULT' and row['listingParameterCount'] == 0 and not row['customStorage'], row
        parameter, = row['parameters']
        assert (parameter['name'], parameter['type'], parameter['bytes']) == ('param_1', dtype, size), row
        assert not parameter['hidden'] and not parameter['thisPointer'] and not row['varargs']
        omitted, = [item for item in report['omittedLocations'] if item['function'] == name]
        assert omitted['variable'] == 'param_1' and omitted['kind'] == 'PARAMETER'
        assert omitted['reason'] == 'UNKNOWN_LIFETIME' and 'decompiler name/type evidence' in omitted['diagnostic']
        assert int(omitted['startAddress'], 16) == row['address']
        assert 'Using decompiler-recovered parameter names/types for ' + name + ';' in (case / 'fixed.log').read_text()
    assert by_name['curated_scalar']['signatureSource'] == 'USER_DEFINED'
    assert by_name['curated_scalar']['listingParameterCount'] == 1
    assert 'Using decompiler-recovered parameter names/types for curated_scalar;' not in (case / 'fixed.log').read_text()
    unsupported = by_name['unresolved_pair']
    assert unsupported['signatureSource'] == 'DEFAULT' and unsupported['listingParameterCount'] == 0
    assert [p['type'] for p in unsupported['parameters']] == ['undefined8', 'undefined8 *']
    assert 'Omitted decompiler parameter recovery for unresolved_pair:' in (case / 'fixed.log').read_text()
    for variant, artifact in [('compiler', reference), ('forge', case / 'parameters.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
    records_spec = importlib.util.spec_from_file_location('records', source / 'dynamic-composite-storage-check.py')
    records = importlib.util.module_from_spec(records_spec)
    records_spec.loader.exec_module(records)
    dies = records.die_records((case / 'forge-info.log').read_text())
    by_offset = {row['offset']: row for row in dies}
    import re
    def dtype(die):
        return by_offset[int(re.fullmatch(r'<0x([0-9a-f]+)>', die['attrs']['DW_AT_type'])[1], 16)]
    for name in by_name:
        die, = [row for row in dies if row['tag'] == 'DW_TAG_subprogram' and records.facts.die_name(row) == name]
        children = [row for row in records.children(dies, dies.index(die)) if row['tag'] == 'DW_TAG_formal_parameter']
        if name != 'curated_scalar':
            assert 'DW_AT_prototyped' not in die['attrs'], 'inference asserted as a complete prototype'
        else:
            assert die['attrs']['DW_AT_prototyped'] == '1', 'curated prototype was lost'
        if name == 'unresolved_pair':
            assert not children, 'unsupported list partially emitted'
            continue
        child, = children
        assert records.facts.die_name(child) == ('analyst_seed' if name == 'curated_scalar' else 'param_1')
        typed = dtype(child)
        if name.startswith('inferred_'):
            assert not set(child['attrs']) & {'DW_AT_location', 'DW_AT_const_value', 'DW_AT_artificial'}
        if name == 'inferred_pointer':
            assert typed['tag'] == 'DW_TAG_pointer_type' and typed['attrs']['DW_AT_byte_size'] == '8'
            typed = dtype(typed)
        assert typed['tag'] == 'DW_TAG_base_type'
        assert typed['attrs']['DW_AT_byte_size'] == ('8' if name == 'inferred_floating' else '4')
        assert ('float' if name == 'inferred_floating' else 'signed') in typed['attrs']['DW_AT_encoding']
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'parameters.dbg', case / 'strict-checks.log', '--original', binary])
    for variant in ['compiler', 'forge'] + (['previous'] if args.previous_ghidra else []):
        artifact = reference if variant == 'compiler' else case / ('previous.dbg' if variant == 'previous' else 'parameters.dbg')
        os.environ['PARAMETER_CASE'], os.environ['PARAMETER_VARIANT'] = str(case), variant
        run(variant + '-gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set pagination off',
            '-ex', 'set confirm off', '-ex', 'set python print-stack full', '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
            '-ex', 'set disable-randomization off', '-ex', 'file ' + str(reference if variant == 'compiler' else binary),
            '-ex', 'symbol-file ' + str(artifact), '-x', source / 'recovered-parameter-types-gdb.py'])
        assert 'recovered-parameter-gdb=' + variant + ' PASS' in (case / (variant + '-gdb.log')).read_text()
    after = {str(p): support.digest(p) for p in protected}
    write('protected-after.json', after)
    assert before == after and original == support.digest(binary)
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Parameters.rep/idata/~index.bak', 'Parameters.rep/idata/~journal.bak'}, changes
    write('result.json', {'status': 'PASS', 'inputSha256': original, 'artifactSha256': artifact_hashes,
        'javaVersion': metadata['javaVersion'], 'projectBackupChanges': changes, 'protectedUnchanged': True,
        'previousPackageCompared': bool(args.previous_ghidra)})
    print('recovered-parameter-types=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

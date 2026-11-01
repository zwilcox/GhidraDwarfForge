#!/usr/bin/env python3
"""Validate curated thunk symbols without borrowing destination source."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('support', source.parent / 'performance/export-benchmark.py')
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--previous-ghidra', type=Path)
    parser.add_argument('--target', choices=('x86_64', 'aarch64'), required=True)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/curated-thunk'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless' and name != 'gdb-driver':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/curated-thunk.c'
    protected = [fixture, Path(__file__).resolve(), source / 'curated-thunk-gdb.py',
        source / 'ghidra_scripts/PrepareCuratedThunk.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    reference, binary = case / 'control.reference', case / 'control.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    compiler = 'gcc' if args.target == 'x86_64' else 'aarch64-linux-gnu-gcc'
    objcopy = 'objcopy' if args.target == 'x86_64' else 'aarch64-linux-gnu-objcopy'
    run('compile', [compiler, '-O2', '-g3', '-gdwarf-5', '-gno-variable-location-views', *flags, fixture, '-o', reference])
    run('strip', [objcopy, '--strip-debug', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('gateway', 'implementation'):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
    assert len(symbols) == 2
    write('symbols.json', symbols)
    assert int.from_bytes(reference.read_bytes()[16:18], 'little') == (2 if args.role == 'exec' else 3)
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    project = case / 'project'
    project.mkdir()
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Thunks', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareCuratedThunk.java', 'curate', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'fixed.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'Thunks', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareCuratedThunk.java', 'observe', case / (variant + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        log = (case / (variant + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        observed = json.loads((case / (variant + '.json')).read_text())
        assert observed['entry'] - observed['rebaseDelta'] == symbols['gateway']
        assert observed['target'] - observed['rebaseDelta'] == symbols['implementation']
        assert observed['name'] == 'analyst_gateway' and observed['signature'] == 'int analyst_gateway(int value)'
        assert observed['source'] == observed['signatureSource'] == 'USER_DEFINED'
        assert observed['selected'] == (variant != 'previous')
        if variant == 'previous':
            continue
        assert Path(unquote(urlsplit(observed['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
        assert observed == json.loads((case / 'import.json').read_text())
        if args.role == 'pie-rebased':
            assert observed['rebaseDelta'] >= 0x2000000
        current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
        if hashes is not None:
            assert hashes == current
        hashes = current
        if variant == 'fixed':
            shutil.copyfile(output, case / 'first.dbg')
            shutil.copyfile(Path(str(output) + '.c'), case / 'first.dbg.c')
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert not report['failedFunctions'] and report['failure'] is None
        omissions = [row for row in report['unsupportedConstructs'] if row['kind'] == 'OMITTED_SOURCE']
        assert any(row['name'] == 'analyst_gateway' for row in omissions)
        assert not any(row['name'] == 'analyst_gateway' for row in report['skippedFunctions'])
        source_text = Path(str(output) + '.c').read_text()
        assert 'Synthetic source intentionally omitted for analyst_gateway' in source_text
        assert 'int analyst_gateway(' not in source_text
        write(variant + '-report.json', report)
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Thunks.rep/idata/~index.bak', 'Thunks.rep/idata/~journal.bak'}, changes
    for variant, artifact in [('compiler', reference), ('fixed', case / 'fixed.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log'), '--original', binary])
    records = []
    for line in (case / 'fixed-info.log').read_text().splitlines():
        header = re.match(r'^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?', line)
        if header:
            records.append({'depth': int(header[1]), 'offset': int(header[2], 16), 'tag': header[3], 'attrs': {}})
        elif records:
            attr = re.match(r'^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)', line)
            if attr:
                records[-1]['attrs'][attr[1]] = attr[2]
    index, = [i for i, row in enumerate(records) if row['tag'] == 'DW_TAG_subprogram' and
        row['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == 'analyst_gateway']
    row = records[index]
    assert int(row['attrs']['DW_AT_low_pc'], 16) == symbols['gateway']
    assert int(row['attrs']['DW_AT_high_pc'], 0) == observed['ranges'][0][1] - observed['ranges'][0][0]
    assert observed['ranges'] == [[symbols['gateway'], symbols['gateway'] + int(row['attrs']['DW_AT_high_pc'], 0)]]
    assert 'DW_AT_type' in row['attrs']
    target_row, = [item for item in records if item['tag'] == 'DW_TAG_subprogram' and
        item['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == 'implementation']
    relation = re.match(r'<0x([0-9a-f]+)>', row['attrs'].get('DW_AT_trampoline', ''))
    assert relation and int(relation[1], 16) == target_row['offset'], 'direct saved target reference missing'
    assert 'DW_AT_abstract_origin' not in row['attrs'] and 'DW_AT_specification' not in row['attrs']
    assert not any(key in row['attrs'] for key in ('DW_AT_decl_file', 'DW_AT_decl_line'))
    parameters = []
    for child in records[index + 1:]:
        if child['depth'] <= row['depth']:
            break
        if child['tag'] == 'DW_TAG_formal_parameter':
            parameters.append(child)
    parameter, = parameters
    assert parameter['attrs']['DW_AT_name'].rsplit(': ', 1)[-1] == 'value'
    assert 'DW_AT_type' in parameter['attrs'] and 'DW_AT_location' not in parameter['attrs']
    by_offset = {record['offset']: record for record in records}
    for definition in (row, parameter):
        type_offset = int(re.fullmatch(r'<0x([0-9a-f]+)>', definition['attrs']['DW_AT_type'])[1], 16)
        dtype = by_offset[type_offset]
        assert dtype['tag'] == 'DW_TAG_base_type'
        assert int(dtype['attrs']['DW_AT_byte_size']) == 4
        assert dtype['attrs']['DW_AT_encoding'].split()[0] == '5'
    write('raw-dies.json', records)
    write('model.json', {'target': args.target, 'role': args.role, 'hashes': hashes, 'projectBackupChanges': changes})
    run('gdb-driver', ['env', 'THUNK_TARGET=' + args.target,
        'bash', source / 'curated-thunk-gdb.sh', repository, case], timeout=180)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role, 'inputSha256': before[str(binary)],
        'hashes': hashes, 'protectedUnchanged': True, 'previousPackageCompared': bool(args.previous_ghidra)})
    print('curated-thunk-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

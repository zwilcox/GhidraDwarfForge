#!/usr/bin/env python3
"""Validate explicit alternate conventions without inventing debugger ABI mappings."""
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
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/calling-convention'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.role + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless' and name != 'gdb-driver':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/calling-convention.c'
    protected = [fixture, Path(__file__).resolve(), source / 'calling-convention-gdb.py',
        source / 'ghidra_scripts/PrepareCallingConvention.java', source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    reference, binary = case / 'control.reference', case / 'control.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', ['gcc', '-O1', '-g3', '-gdwarf-5', '-gno-variable-location-views', *flags, fixture, '-o', reference])
    run('strip', ['objcopy', '--strip-debug', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('sysv_function', 'microsoft_function'):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
    assert len(symbols) == 2
    write('symbols.json', symbols)
    assert int.from_bytes(reference.read_bytes()[16:18], 'little') == (2 if args.role == 'exec' else 3)
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    project = case / 'project'
    project.mkdir()
    run('import', [ghidra / 'support/analyzeHeadless', project, 'Conventions', '-import', binary,
        '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
        '-postScript', 'PrepareCallingConvention.java', 'curate', case / 'import.json'], timeout=240)
    assert 'REPORT: Analysis succeeded' in (case / 'import.log').read_text()
    project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-before.json', project_before)
    variants = [('fixed', ghidra), ('repeat', ghidra)]
    if args.previous_ghidra:
        variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
    hashes = None
    for variant, installation in variants:
        output = case / ('previous.dbg' if variant == 'previous' else 'fixed.dbg')
        run(variant, [installation / 'support/analyzeHeadless', project, 'Conventions', '-process', binary.name,
            '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'PrepareCallingConvention.java', 'observe', case / (variant + '.json'),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)], timeout=240)
        log = (case / (variant + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        observed = json.loads((case / (variant + '.json')).read_text())
        for function in observed['functions']:
            assert function['entry'] - observed['rebaseDelta'] == symbols[function['name']]
            assert function['compilerSpec'] == 'gcc'
            assert function['storage'] == (['ECX:4', 'EDX:4', 'R8D:4', 'R9D:4'] if
                function['name'] == 'microsoft_function' else ['EDI:4', 'ESI:4', 'EDX:4', 'ECX:4'])
        if variant == 'previous':
            continue
        assert Path(unquote(urlsplit(observed['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
        assert observed == json.loads((case / 'import.json').read_text())
        if args.role == 'pie-rebased':
            assert observed['rebaseDelta'] >= 0x2000000
        assert 'Debugger-injected calls disabled for microsoft_function:' in log
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
        write(variant + '-report.json', report)
    project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
    write('project-after.json', project_after)
    changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
    assert set(changes) <= {'Conventions.rep/idata/~index.bak', 'Conventions.rep/idata/~journal.bak'}, changes
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
        header = re.match(r'^\s*<(\d+)><[0-9a-f]+>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?', line)
        if header:
            records.append({'depth': int(header[1]), 'tag': header[2], 'attrs': {}})
        elif records:
            attr = re.match(r'^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)', line)
            if attr:
                records[-1]['attrs'][attr[1]] = attr[2]
    for name, expected in [('sysv_function', 1), ('microsoft_function', 3)]:
        row, = [r for r in records if r['tag'] == 'DW_TAG_subprogram' and
            r['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == name]
        assert int(row['attrs']['DW_AT_calling_convention'].split()[0]) == expected
        assert int(row['attrs']['DW_AT_low_pc'], 16) == symbols[name]
    write('raw-dies.json', records)
    write('model.json', {'role': args.role, 'hashes': hashes, 'projectBackupChanges': changes})
    run('gdb-driver', ['env', 'CONVENTION_CASE=' + str(case),
        'CONVENTION_PREVIOUS=' + ('previous' if args.previous_ghidra else ''),
        'bash', source / 'calling-convention-gdb.sh', repository, case], timeout=180)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    write('result.json', {'status': 'PASS', 'role': args.role, 'inputSha256': before[str(binary)],
        'hashes': hashes, 'protectedUnchanged': True, 'previousPackageCompared': bool(args.previous_ghidra)})
    print('calling-convention-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

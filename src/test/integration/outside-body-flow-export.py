#!/usr/bin/env python3
"""Preserve unavailable locations when execution leaves a curated function body."""
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
    parser.add_argument('target', choices=('x86_64', 'aarch64'))
    parser.add_argument('--previous-ghidra', type=Path)
    parser.add_argument('--role', choices=('exec', 'pie', 'pie-rebased'), default='exec')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    root = repository / 'build/test-results/outside-body-flow'
    root.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '.' + args.role + '.', dir=root))
    print(case, flush=True)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, **kwargs):
        result = support.run(command, case / (name + '.log'), **kwargs)
        if Path(command[0]).name != 'analyzeHeadless':
            support.require_clean(case / (name + '.log'))
        return result

    fixture = source.parent / 'fixtures/outside-body-flow.c'
    protected = [fixture, Path(__file__).resolve(), source / 'outside-body-flow-gdb.py',
        source / 'outside-body-flow-gdb.sh', source / 'ghidra_scripts/PrepareOutsideBodyFlow.java',
        source / 'ghidra_scripts/RebaseFixtureProgram.java']
    protected += [p for p in module.rglob('*') if p.is_file()]
    before = {str(p): support.digest(p) for p in protected}
    write('protected-before.json', before)
    cc, objcopy = ('gcc', 'objcopy') if args.target == 'x86_64' else (
        'aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy')
    reference, binary = case / 'control.reference', case / 'control.input'
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run('compile', [cc, '-O1', '-g3', '-gdwarf-5', *flags, fixture, '-o', reference])
    run('strip', [objcopy, '--strip-all', reference, binary])
    before.update({str(binary): support.digest(binary), str(reference): support.digest(reference)})
    write('protected-before.json', before)
    run('symbols', ['readelf', '-sW', reference])
    symbols = {}
    for line in (case / 'symbols.log').read_text().splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('boundary', 'probe_copy_done', 'probe_hidden', 'probe_resume', 'probe_after'):
            assert fields[7] not in symbols
            symbols[fields[7]] = int(fields[1], 16)
            if fields[7] == 'boundary':
                symbols['end'] = int(fields[1], 16) + int(fields[2])
    assert len(symbols) == 6
    write('symbols.json', symbols)
    assert int.from_bytes(reference.read_bytes()[16:18], 'little') == (2 if args.role == 'exec' else 3)
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'pie-rebased' else []
    evidence = {}
    for mode in ('complete', 'excluded'):
        project = case / mode
        project.mkdir()
        run(mode + '-import', [ghidra / 'support/analyzeHeadless', project, 'Flow', '-import', binary,
            '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts', *rebase,
            '-postScript', 'PrepareOutsideBodyFlow.java', 'curate', case / 'symbols.json', mode,
            args.target, case / (mode + '-import.json')], timeout=240)
        assert 'REPORT: Analysis succeeded' in (case / (mode + '-import.log')).read_text()
        project_before = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
        write(mode + '-project-before.json', project_before)
        variants = [('fixed', ghidra), ('repeat', ghidra)]
        if args.previous_ghidra and mode == 'excluded':
            variants.insert(0, ('previous', args.previous_ghidra.resolve(strict=True)))
        hashes = None
        for variant, installation in variants:
            output = case / ('previous.dbg' if variant == 'previous' else mode + '.dbg')
            name = mode + '-' + variant
            run(name, [installation / 'support/analyzeHeadless', project, 'Flow', '-process', binary.name,
                '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
                '-postScript', 'PrepareOutsideBodyFlow.java', 'observe', case / 'symbols.json', mode,
                args.target, case / (name + '.json'), '-postScript', 'GhidraDwarfForge.java',
                '--packaged-natives', '--output=' + str(output)], timeout=240)
            log = (case / (name + '.log')).read_text()
            assert 'GhidraDwarfForge symbol export PASS' in log
            model = json.loads((case / (name + '.json')).read_text())
            assert model['entry'] - model['rebaseDelta'] == symbols['boundary']
            assert model['available'] == (variant == 'previous'), model
            if variant == 'previous':
                continue
            assert Path(unquote(urlsplit(model['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
            assert model == json.loads((case / (mode + '-import.json')).read_text())
            if args.role == 'pie-rebased':
                assert model['rebaseDelta'] >= 0x2000000
            assert ('control flow' if mode == 'excluded' else 'REGISTER_MODIFIED') in model['storage']
            current = [support.digest(output), support.digest(Path(str(output) + '.c'))]
            if hashes is not None:
                assert hashes == current
            hashes = current
            if variant == 'fixed':
                shutil.copyfile(output, case / (mode + '-first.dbg'))
                shutil.copyfile(Path(str(output) + '.c'), case / (mode + '-first.dbg.c'))
            report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
            assert not report['failedFunctions'] and report['failure'] is None
            omitted = [r for r in report['omittedLocations'] if r['function'] == 'boundary' and r['variable'] == 'value']
            assert omitted and all(r['reason'] == 'UNKNOWN_LIFETIME' for r in omitted)
            if mode == 'complete':
                arithmetic, = [row for row in model['instructions'] if row['address'] == symbols['probe_after']]
                assert arithmetic['bytes'] == ('83c007' if args.target == 'x86_64' else '001c0011')
                assert len(omitted) == 1
                assert (int(omitted[0]['startAddress'], 0), int(omitted[0]['endAddress'], 0)) == (arithmetic['next'], symbols['end'])
            else:
                intervals = [(int(r['startAddress'], 0), int(r['endAddress'], 0)) for r in omitted]
                assert intervals == [(symbols['boundary'], symbols['probe_hidden']), (symbols['probe_after'], symbols['end'])]
            write(name + '-report.json', report)
        project_after = {str(p.relative_to(project)): support.digest(p) for p in project.rglob('*') if p.is_file()}
        write(mode + '-project-after.json', project_after)
        changes = [name for name in sorted(project_before.keys() | project_after.keys()) if project_before.get(name) != project_after.get(name)]
        assert set(changes) <= {'Flow.rep/idata/~index.bak', 'Flow.rep/idata/~journal.bak'}, changes
        evidence[mode] = {'hashes': hashes, 'projectBackupChanges': changes, 'model': model}
    for variant, artifact in [('compiler', reference), ('complete', case / 'complete.dbg'), ('excluded', case / 'excluded.dbg')]:
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'loc', 'Ranges'):
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        for name, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n')]:
            run(variant + '-' + name, ['readelf', option, artifact])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact], timeout=60)
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict-checks.log'), '--original', binary])
        if variant != 'compiler':
            # Keep excluded-flow name/type only; the complete CFG now proves a backup.
            records = []
            for line in (case / (variant + '-info.log')).read_text().splitlines():
                header = re.match(r'^\s*<(\d+)><[0-9a-f]+>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?', line)
                if header:
                    records.append({'depth': int(header[1]), 'tag': header[2], 'attrs': {}})
                elif records:
                    attr = re.match(r'^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s+:\s*(.*)', line)
                    if attr:
                        records[-1]['attrs'][attr[1]] = attr[2]
            names = lambda r: r['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1]
            index, = [i for i, r in enumerate(records) if r['tag'] == 'DW_TAG_subprogram' and names(r) == 'boundary']
            children = []
            for record in records[index + 1:]:
                if record['depth'] <= records[index]['depth']:
                    break
                if names(record) == 'value':
                    children.append(record)
            parameter, = children
            assert parameter['tag'] == 'DW_TAG_formal_parameter'
            assert 'DW_AT_type' in parameter['attrs']
            if variant == 'excluded':
                assert 'DW_AT_location' not in parameter['attrs']
            else:
                location = parameter['attrs']['DW_AT_location']
                match = re.fullmatch(r'(0x[0-9a-f]+) \(location list\)', location)
                assert match, location
                # Independently read the exact fixed-form DWARF 5 loclist bytes.
                section, = re.findall(r'^\s*\[\s*\d+\]\s+\.debug_loclists\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b', (case / 'complete-sections.log').read_text(), re.M)
                offset, size = [int(v, 16) for v in section]
                import struct
                data = artifact.read_bytes()[offset:offset + size]
                assert struct.unpack_from('<IHBBI', data) == (size - 4, 5, 8, 0, 0)
                cursor = int(match[1], 16)
                intervals = []
                while data[cursor] != 0:
                    assert data[cursor] == 7  # DW_LLE_start_end
                    start, end = struct.unpack_from('<QQ', data, cursor + 1)
                    assert data[cursor + 17:cursor + 19] == bytes([2, 0x90])  # DW_OP_regx
                    intervals.append([start, end, data[cursor + 19]])
                    cursor += 20
                arithmetic, = [row for row in evidence['complete']['model']['instructions'] if row['address'] == symbols['probe_after']]
                assert intervals == [[symbols['boundary'], symbols['probe_copy_done'], 4 if args.target == 'x86_64' else 1],
                    [symbols['probe_copy_done'], arithmetic['next'], 0]], intervals
                write('complete-raw-intervals.json', intervals)
            write(variant + '-raw-location.json', parameter)
    os.environ['FLOW_PREVIOUS'] = 'previous' if args.previous_ghidra else ''
    write('model.json', {'role': args.role, 'target': args.target, 'cases': evidence})
    run('gdb-driver', ['bash', source / 'outside-body-flow-gdb.sh', repository, case, args.target], timeout=240)
    after = {name: support.digest(Path(name)) for name in before}
    write('protected-after.json', after)
    assert before == after
    write('result.json', {'status': 'PASS', 'target': args.target, 'role': args.role,
        'inputSha256': before[str(binary)], 'cases': evidence, 'protectedUnchanged': True,
        'previousPackageCompared': bool(args.previous_ghidra)})
    print('outside-body-flow-export=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

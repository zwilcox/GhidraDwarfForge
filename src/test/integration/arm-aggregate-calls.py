#!/usr/bin/env python3
"""Real packaged ARM aggregate call classification, independent of location gaps."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
repository = source.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--order', choices=('little', 'big'), required=True)
    parser.add_argument('--pcs', choices=('softfp', 'hard'), required=True)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    args.gdb = args.gdb.resolve(strict=True)
    args.gdb_data = args.gdb_data.resolve(strict=True)
    args.qemu = args.qemu.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    output = repository / 'build/test-results/arm-aggregate-calls'
    output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.order + '.' + args.pcs + '.', dir=output))
    print(case, flush=True)
    facts = load('aggregate_elf', source / 'arm-thumb-mode-check.py')
    dies = load('aggregate_dies', source / 'arm-dynamic-pcs-check.py')
    reference = load('aggregate_reference', source / 'arm-pcs-call-reference.py')
    protected = [Path(__file__), source / 'arm-aggregate-calls-gdb.py',
        source / 'arm-aggregate-pcs-gdb.py', source / 'arm_aggregate_pcs_oracle.py',
        source / 'arm-aggregate-pcs-reference.py', source / 'arm-pcs-profile-runtime.sh',
        source / 'qemu-socket.sh', source / 'arm-thumb-mode-check.py',
        source / 'arm-dynamic-pcs-check.py', source / 'arm-pcs-call-reference.py',
        source / 'check-dwarfdump.py', source / 'ghidra_scripts/PrepareArmAggregatePcs.java',
        repository / 'src/test/fixtures/arm-aggregate-pcs.c',
        repository / 'src/test/fixtures/arm-pcs-start.S', args.gdb, args.qemu]
    protected += [p for base in (module, args.gdb_data) for p in base.rglob('*') if p.is_file()]
    before = {str(p): digest(p) for p in protected}
    commands = []
    java = subprocess.run([str(Path(os.environ['JAVA_HOME']) / 'bin/java'), '-Xshare:off', '-version'],
        capture_output=True, check=True)
    assert not java.stdout
    (case / 'java-version.stderr').write_bytes(java.stderr)

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'command': command})
        write('commands.json', commands)
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.err')).open('wb') as err:
            result = subprocess.run(command, stdout=log, stderr=err, timeout=180)
        assert result.returncode == 0, (case, label, result.returncode)
        stderr = (case / (label + '.err')).read_bytes()
        if Path(command[0]).name == 'analyzeHeadless':
            assert stderr == java.stderr, (case, label, 'unexpected headless stderr')
            assert not re.search(r'(?m)^ERROR (?!GhidraDwarfForge.java> GhidraDwarfForge: )',
                (case / (label + '.log')).read_text()), label
        else:
            assert not stderr, (case, label, 'unexpected stderr')

    run('reference', ['python3', source / 'arm-aggregate-pcs-reference.py', '--order', args.order,
        '--pcs', args.pcs, '--gdb', args.gdb, '--gdb-data', args.gdb_data, '--qemu', args.qemu])
    compiler_case = Path((case / 'reference.log').read_text().splitlines()[0])
    compiler_result = json.loads((compiler_case / 'result.json').read_text())
    assert compiler_result['status'] == 'PASS_COMPILER_REFERENCE'
    write('compiler-reference.json', {'case': str(compiler_case), 'result': compiler_result})
    for leaf in ('calls.input', 'calls.reference', 'profile.json'):
        shutil.copy2(compiler_case / leaf, case / leaf)
        before[str(compiler_case / leaf)] = digest(compiler_case / leaf)
        before[str(case / leaf)] = digest(case / leaf)
    write('protected-before.json', before)
    compiler_elf = facts.elf(case / 'calls.reference', allow_big_endian=True)
    original = facts.elf(case / 'calls.input', allow_big_endian=True)
    names = [pcs + '_' + kind for pcs in ('base', 'vfp') for kind in
        ('pair', 'float3', 'double2', 'mixed', 'split', 'exhaust')]
    labels = names + [name + suffix for suffix in ('_pointer', '_observe') for name in names]
    labels += [prefix + kind for prefix in ('input_', 'seen_') for kind in ('pair', 'float3', 'double2', 'mixed')]
    labels += ['seen_ints', 'seen_doubles', 'calls', 'marker']
    entries = {}
    for name in labels:
        symbol, = [row for row in compiler_elf['symbols'] if row['name'] == name]
        entries[name] = symbol['raw']
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n' for name, address in entries.items()))
    write('labels.json', entries)
    (case / 'project').mkdir()
    run('import', [ghidra / 'support/analyzeHeadless', case / 'project', 'Aggregate', '-import', case / 'calls.input',
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120'])
    assert 'REPORT: Import succeeded' in (case / 'import.log').read_text()
    for phase in ('curate', 'inspect'):
        run(phase, [ghidra / 'support/analyzeHeadless', case / 'project', 'Aggregate', '-process', 'calls.input',
            '-noanalysis', *(['-readOnly'] if phase == 'inspect' else []),
            '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareArmAggregatePcs.java', phase,
            case / 'labels.txt', case / (phase + '.json'), '-postScript', 'GhidraDwarfForge.java',
            '--packaged-natives', '--output=' + str(case / 'calls.dbg')])
        log = (case / (phase + '.log')).read_text()
        assert 'arm-aggregate-pcs-preparation=PASS' in log and 'GhidraDwarfForge symbol export PASS' in log
        if phase == 'curate':
            for leaf in ('calls.dbg', 'calls.dbg.c'):
                shutil.copy2(case / leaf, case / ('first-' + leaf))
            program_before = {str(p.relative_to(case / 'project')): digest(p)
                for p in (case / 'project').rglob('*') if p.is_file()}
            write('program-before.json', program_before)
    observed = json.loads((case / 'inspect.json').read_text())
    assert observed == json.loads((case / 'curate.json').read_text())
    origin = urlsplit(observed['origin'])
    assert origin.scheme == 'file' and not origin.netloc and not origin.query and not origin.fragment
    assert Path(unquote(origin.path)) == module / 'lib/GhidraDwarfForge.jar'
    program_after = {str(p.relative_to(case / 'project')): digest(p)
        for p in (case / 'project').rglob('*') if p.is_file()}
    changed = {p for p in program_before.keys() | program_after.keys() if program_before.get(p) != program_after.get(p)}
    assert changed <= {'Aggregate.rep/idata/~index.bak', 'Aggregate.rep/idata/~journal.bak'}, changed
    write('program-after.json', program_after)
    for leaf in ('calls.dbg', 'calls.dbg.c'):
        assert (case / leaf).read_bytes() == (case / ('first-' + leaf)).read_bytes()
    reports = [facts.transcript(case / (phase + '.log'), 'GhidraDwarfForge report: ') for phase in ('curate', 'inspect')]
    assert reports[0] == reports[1] and reports[0]['failure'] is None
    write('report.json', reports[0])
    for view, option in [('header', '-h'), ('sections', '-SW'), ('attributes', '-A'), ('notes', '-n'),
            ('info', '--debug-dump=info'), ('abbrev', '--debug-dump=abbrev'), ('aranges', '--debug-dump=aranges'),
            ('line', '--debug-dump=decodedline'), ('locations', '--debug-dump=loc')]:
        run('forge-' + view, ['readelf', option, case / 'calls.dbg'])
    run('llvm', ['llvm-dwarfdump', '--verify', case / 'calls.dbg'])
    assert 'No errors.' in (case / 'llvm.log').read_text()
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'calls.dbg', case / 'strict-report.log',
        '--original', case / 'calls.input'])
    exported = facts.elf(case / 'calls.dbg', allow_big_endian=True)
    assert exported['data'][:16] == original['data'][:16]
    assert exported['header'][:4] == original['header'][:4] and exported['header'][6] == original['header'][6]
    assert exported['header'][4] == exported['header'][9] == 0
    for section in ('.text', '.ARM.attributes'):
        assert facts.section(exported, section)['data'] == facts.section(original, section)['data']
    records = dies.records((case / 'forge-info.log').read_text())
    attributes = []
    for name in names:
        allowed = name.split('_')[1] in ('pair', 'mixed', 'split') or name.startswith(
            'vfp_' if args.pcs == 'hard' else 'base_')
        for tag, spelling in [('DW_TAG_subprogram', name), ('DW_TAG_subroutine_type', name + '_type')]:
            record, = [r for r in records if r.get('tag') == tag and
                r['attrs'].get('DW_AT_name', '').endswith(': ' + spelling)]
            assert record['attrs']['DW_AT_calling_convention'] == ('1\t(normal)' if allowed else '3\t(nocall)'), record
            attributes.append({'name': spelling, 'tag': tag, 'offset': record['offset'], 'allowed': allowed})
    write('call-attributes.json', attributes)
    run('runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'forge', args.qemu,
        args.gdb, args.gdb_data, source / 'arm-aggregate-calls-gdb.py'])
    runtime = json.loads((case / 'forge-gdb.json').read_text())
    assert runtime['status'] == 'PASS_AGGREGATE_CALLS' and runtime['exitCode'] == 0
    assert len(runtime['natural']) == 12 and sum('return' in row for row in runtime['natural']) == 9
    assert all('entryParameter' in row for row in runtime['natural'])
    prefixes = [row['hfaPrefix'] for row in runtime['natural'] if 'hfaPrefix' in row]
    assert len(prefixes) == 2 and all(len(rows) > 2 for rows in prefixes)

    assert len(runtime['injected']) == 24 and sum('rejected' in row for row in runtime['injected']) == 6
    warnings = (case / 'forge.stderr').read_text().splitlines()
    for warning in warnings:
        assert warning == 'Failed to read a valid object file image from memory.' or re.fullmatch(
            r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning), warnings
        reference.corroborate_unmapped_vdso_sections(runtime)
    assert len(warnings) <= 1
    assert (case / 'forge.qemu.status').read_text() == 'exit=0\n'
    assert not (case / 'forge.qemu.stderr').read_bytes()
    assert before == {path: digest(Path(path)) for path in before}
    write('result.json', {'status': 'PASS_AGGREGATE_CALLS', 'order': args.order, 'pcs': args.pcs,
        'rawEntryTransfers': 12, 'typedEntryParameters': 12, 'hfaInstructionObservations': sum(map(len, prefixes)),
        'capturedArguments': 12, 'typedReturns': 9, 'injectedCalls': 18,
        'unchangedStateRejections': 6, 'deterministic': True, 'protectedFilesUnchanged': True,
        'scope': 'Aggregate call classification; parameter location lifetimes and broader layouts remain separate'})
    print('PASS_AGGREGATE_CALLS', flush=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Packaged ARM scalar PCS export: LE/BE8, base/VFP, wide and exhausted arguments."""
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


facts = load('pcs_elf', source / 'arm-thumb-mode-check.py')
reference = load('pcs_reference', source / 'arm-pcs-call-reference.py')
dies = load('pcs_dies', source / 'arm-dynamic-pcs-check.py')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    parser.add_argument('--qemu-arm', required=True)
    parser.add_argument('--qemu-armeb', required=True)
    parser.add_argument('--order', choices=('little', 'big'), required=True)
    parser.add_argument('--pcs', choices=('softfp', 'hard'), required=True)
    parser.add_argument('--implicit-default', action='store_true', help='Preserve unknown recorded conventions with default dynamic VFP storage')
    parser.add_argument('--guard-controls', action='store_true', help='Keep unresolved custom storage and function-pointer types uncallable')
    parser.add_argument('--declarations', action='store_true', help='Validate addressless external signatures without inventing symbols')
    parser.add_argument('--metadata', choices=('original', 'absent', 'conflict'), default='original',
        help='Preserve, remove, or contradict the original floating PCS attributes in a generated fixture')
    parser.add_argument('--failure-controls', action='store_true', help='Run genuine decompilation failure and production cancellation controls')
    args = parser.parse_args()
    if args.guard_controls and not args.implicit_default:
        parser.error('--guard-controls requires --implicit-default')
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    output = repository / 'build/test-results/arm-pcs-profile'
    output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.order + '.' + args.pcs + '.', dir=output))
    print(case, flush=True)
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    objcopy = os.environ.get('ARM32_OBJCOPY', 'arm-linux-gnueabihf-objcopy')
    emulator = args.qemu_armeb if args.order == 'big' else args.qemu_arm
    protected = [Path(__file__), source / 'arm-pcs-profile-gdb.py', source / 'arm-pcs-profile-runtime.sh',
        source / 'ghidra_scripts/PrepareArmPcsProfile.java', source / 'qemu-socket.sh',
        source / 'arm-thumb-mode-check.py', source / 'arm-dynamic-pcs-check.py',
        source / 'arm-pcs-call-reference.py', source / 'check-dwarfdump.py',
        repository / 'src/test/fixtures/arm-pcs-profile.c', repository / 'src/test/fixtures/arm-pcs-start.S',
        args.gdb.resolve(strict=True)]
    protected += [Path(shutil.which(tool)).resolve(strict=True) for tool in (compiler, objcopy, emulator)]
    if args.failure_controls:
        protected += [source / 'arm-pcs-failure-controls.py', source / 'ghidra_scripts/AbiDecompilerFailureExport.java',
            source / 'ghidra_scripts/CancelDuringElfCopy.java']
    protected += [p for base in (module, args.gdb_data) for p in base.rglob('*') if p.is_file()]
    before = {str(p): digest(p) for p in protected}
    commands = []
    java_version = subprocess.run([str(Path(os.environ['JAVA_HOME']) / 'bin/java'), '-Xshare:off', '-version'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    assert not java_version.stdout
    (case / 'java-version.stderr').write_bytes(java_version.stderr)

    def write(name, data):
        (case / name).write_text(json.dumps(data, indent=4) + '\n')

    def run(label, command, timeout=180):
        command = list(map(str, command))
        commands.append({'label': label, 'command': command})
        write('commands.json', commands)
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.err')).open('wb') as err:
            process = subprocess.run(command, stdout=log, stderr=err, timeout=timeout)
        assert process.returncode == 0, (case, label, process.returncode)
        stderr = (case / (label + '.err')).read_bytes()
        if Path(command[0]).name == 'analyzeHeadless':
            assert stderr == java_version.stderr, (label, 'unexpected headless stderr')
            assert not re.search(r'(?m)^ERROR (?!GhidraDwarfForge.java> GhidraDwarfForge: )',
                (case / (label + '.log')).read_text()), label
        else:
            assert not stderr, (label, 'unexpected stderr')

    write('profile.json', {'order': args.order, 'pcs': args.pcs, 'implicitDefault': args.implicit_default,
        'guardControls': args.guard_controls, 'declarations': args.declarations, 'metadata': args.metadata})
    run('compile', [compiler, '-marm', '-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=' + args.pcs,
        '-O0', '-g3', '-gdwarf-5', '-fno-omit-frame-pointer', '-nostdlib', '-nostartfiles', '-static',
        '-fno-pie', '-no-pie', '-Wl,--build-id=none', '-Wl,-e,_start',
        *(['-mbig-endian', '-Wl,--be8'] if args.order == 'big' else []),
        repository / 'src/test/fixtures/arm-pcs-start.S', repository / 'src/test/fixtures/arm-pcs-profile.c',
        '-o', case / 'calls.reference'])
    run('strip', [objcopy, '--strip-all', case / 'calls.reference', case / 'calls.input'])
    unmodified = (case / 'calls.input').read_bytes()
    if args.metadata == 'absent':
        run('remove-attributes', [objcopy, '--remove-section=.ARM.attributes', case / 'calls.input', case / 'calls.control'])
        (case / 'calls.control').replace(case / 'calls.input')
    elif args.metadata == 'conflict':
        changed = bytearray(unmodified)
        flags = int.from_bytes(changed[36:40], args.order)
        assert flags & 0x600 == (0x400 if args.pcs == 'hard' else 0x200)
        changed[36:40] = ((flags & ~0x600) | (0x200 if args.pcs == 'hard' else 0x400)).to_bytes(4, args.order)
        (case / 'calls.input').write_bytes(changed)
        assert changed[:36] == unmodified[:36] and changed[40:] == unmodified[40:]
    write('metadata-control.json', {'mode': args.metadata, 'unmodifiedSha256': hashlib.sha256(unmodified).hexdigest(),
        'fixtureSha256': digest(case / 'calls.input')})
    before.update({str(p): digest(p) for p in (case / 'calls.reference', case / 'calls.input')})
    write('protected-before.json', before)
    original = facts.elf(case / 'calls.input', allow_big_endian=True)
    compiler_elf = facts.elf(case / 'calls.reference', allow_big_endian=True)
    allocated = lambda elf: [(row['name'], row['row'][3], row['data']) for row in elf['sections'] if row['row'][2] & 2]
    assert allocated(original) == allocated(compiler_elf), 'metadata control changed allocated target sections'
    assert any(row['name'] == '.ARM.attributes' for row in original['sections']) == (args.metadata != 'absent')
    names = [pcs + '_' + kind for pcs in ('base', 'vfp') for kind in ('float', 'double', 'wide', 'many')]
    labels = names + [name + '_pointer' for name in names] + ['seen_float', 'seen_double', 'seen_wide', 'calls', 'marker']
    entries = {}
    for name in labels:
        symbol, = [row for row in compiler_elf['symbols'] if row['name'] == name]
        entries[name] = symbol['raw']
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(address) + '\n' for name, address in entries.items()))
    (case / 'project').mkdir()
    run('import', [ghidra / 'support/analyzeHeadless', case / 'project', 'Pcs', '-import', case / 'calls.input',
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120'])
    assert 'REPORT: Import succeeded' in (case / 'import.log').read_text()
    for phase in ('curate', 'inspect'):
        run(phase, [ghidra / 'support/analyzeHeadless', case / 'project', 'Pcs', '-process', 'calls.input',
            '-noanalysis', *(['-readOnly'] if phase == 'inspect' else []),
            '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareArmPcsProfile.java', phase,
            case / 'labels.txt', case / (phase + '.json'), *(['implicit-default'] if args.implicit_default else []),
            *(['guard-controls'] if args.guard_controls else []),
            *(['declarations'] if args.declarations else []),
            '-postScript', 'GhidraDwarfForge.java', '--packaged-natives',
            '--output=' + str(case / 'calls.dbg')])
        log = (case / (phase + '.log')).read_text()
        assert 'arm-pcs-profile-preparation=PASS' in log and 'GhidraDwarfForge symbol export PASS' in log
        if phase == 'curate':
            for leaf in ('calls.dbg', 'calls.dbg.c'):
                shutil.copyfile(case / leaf, case / ('first-' + leaf))
            program_before = {str(p.relative_to(case / 'project')): digest(p)
                for p in (case / 'project').rglob('*') if p.is_file()}
            write('program-before.json', program_before)
    assert json.loads((case / 'curate.json').read_text()) == json.loads((case / 'inspect.json').read_text())
    reports = [facts.transcript(case / (phase + '.log'), 'GhidraDwarfForge report: ') for phase in ('curate', 'inspect')]
    assert reports[0] == reports[1] and reports[0]['failure'] is None
    write('report.json', reports[0])
    if args.metadata == 'conflict':
        for name in names:
            for target in [name, 'function type ' + name + '_type',
                    *(['pcs_declarations::' + name] if args.declarations else [])]:
                matching = [message for message in reports[0]['diagnostics'] if message.startswith(
                    'Debugger-injected calls disabled for ' + target + ': ')]
                assert any('ARM floating PCS flags contradict build attributes' in message for message in matching), target
    observed = json.loads((case / 'inspect.json').read_text())
    for function in observed['functions']:
        name = function['name']
        expected = 'unknown' if args.implicit_default and name.startswith('vfp') else (
            '__stdcall_softfp' if name.startswith('base') else '__stdcall')
        assert function['convention'] == expected
        assert function['resolvedConvention'] == ('' if expected == 'unknown' else expected)
        assert function['customStorage'] == (args.guard_controls and name == 'vfp_float')
    origin = urlsplit(observed['origin'])
    assert origin.scheme == 'file' and not origin.netloc and not origin.query and not origin.fragment
    assert Path(unquote(origin.path)) == module / 'lib/GhidraDwarfForge.jar'
    for leaf in ('calls.dbg', 'calls.dbg.c'):
        assert (case / leaf).read_bytes() == (case / ('first-' + leaf)).read_bytes()
    program_after = {str(p.relative_to(case / 'project')): digest(p)
        for p in (case / 'project').rglob('*') if p.is_file()}
    changed = [p for p in program_before.keys() | program_after.keys() if program_before.get(p) != program_after.get(p)]
    assert set(changed) <= {'Pcs.rep/idata/~index.bak', 'Pcs.rep/idata/~journal.bak'}, changed
    for variant, path in [('compiler', case / 'calls.reference'), ('forge', case / 'calls.dbg')]:
        for view, option in [('header', '-h'), ('sections', '-SW'), ('attributes', '-A'), ('notes', '-n'),
                ('info', '--debug-dump=info'), ('abbrev', '--debug-dump=abbrev'), ('aranges', '--debug-dump=aranges'),
                ('line', '--debug-dump=decodedline')]:
            run(variant + '-' + view, ['readelf', option, path])
        run(variant + '-llvm', ['llvm-dwarfdump', '--verify', path])
        assert 'No errors.' in (case / (variant + '-llvm.log')).read_text()
        run(variant + '-strict', ['python3', source / 'check-dwarfdump.py', path, case / (variant + '-strict-report.log'),
            *(['--original', case / 'calls.input'] if variant == 'forge' else [])])
    exported = facts.elf(case / 'calls.dbg', allow_big_endian=True)
    assert exported['data'][:16] == original['data'][:16]
    assert exported['header'][:4] == original['header'][:4] and exported['header'][6] == original['header'][6]
    assert exported['header'][4] == exported['header'][9] == 0
    for section in ('.text', *(['.ARM.attributes'] if args.metadata != 'absent' else [])):
        assert facts.section(exported, section)['data'] == facts.section(original, section)['data']
    assert any(row['name'] == '.ARM.attributes' for row in exported['sections']) == (args.metadata != 'absent')
    records = dies.records((case / 'forge-info.log').read_text())
    by_offset = {record['offset']: record for record in records if record['tag'] is not None}
    raw = []
    for name in names:
        for tag, spelling in [('DW_TAG_subprogram', name), ('DW_TAG_subroutine_type', name + '_type'),
                *([('DW_TAG_subprogram', 'pcs_declarations::' + name)] if args.declarations else [])]:
            consumer = 'base' if args.metadata == 'absent' or args.pcs == 'softfp' else 'vfp'
            blocked = args.metadata == 'conflict' or not (name.endswith('wide') or name.startswith(consumer))
            blocked |= args.guard_controls and (name == 'vfp_float' or (tag == 'DW_TAG_subroutine_type' and name == 'vfp_double'))
            expected = 3 if blocked else 1
            record, = [row for row in records if row['tag'] == tag and dies.name(row) == spelling]
            convention = record['attrs'].get('DW_AT_calling_convention')
            if convention is None:
                # An omitted convention means DW_CC_normal. The exporter keeps
                # the recorded unknown name even when dynamic storage resolves
                # through Ghidra's default model; it need not emit normal here.
                assert expected == 1 and args.implicit_default and tag == 'DW_TAG_subprogram', record
                assert name.startswith('vfp'), record
            else:
                assert int(convention.split()[0]) == expected, record
            if spelling.startswith('pcs_declarations::'):
                assert record['attrs']['DW_AT_declaration'] == record['attrs']['DW_AT_external'] == '1'
                forbidden = {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges', 'DW_AT_entry_pc',
                    'DW_AT_location', 'DW_AT_frame_base', 'DW_AT_decl_file', 'DW_AT_decl_line'}
                assert not forbidden.intersection(record['attrs']), record
                children = []
                for child in records[records.index(record) + 1:]:
                    if child['depth'] <= record['depth']:
                        break
                    if child['tag'] == 'DW_TAG_formal_parameter':
                        children.append(child)
                        assert 'DW_AT_location' not in child['attrs'] and 'DW_AT_const_value' not in child['attrs']
                assert len(children) == (10 if name.endswith('many') else 2), record
                expected_names = list('abcdefghij') if name.endswith('many') else ['first', 'second']
                assert [dies.name(child) for child in children] == expected_names
                assert all(child['attrs']['DW_AT_type'] == record['attrs']['DW_AT_type'] for child in children)
                referred = int(re.fullmatch(r'<0x([0-9a-f]+)>', record['attrs']['DW_AT_type'])[1], 16)
                returned = by_offset[referred]
                assert returned['tag'] == 'DW_TAG_base_type'
                assert returned['attrs']['DW_AT_byte_size'] == ('4' if name.endswith('float') else '8')
                assert int(returned['attrs']['DW_AT_encoding'].split()[0]) == (5 if name.endswith('wide') else 4)
            raw.append(record)
    observations = []
    for variant in ('compiler', 'forge'):
        run(variant + '-runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, variant,
            emulator, args.gdb, args.gdb_data])
        observed = json.loads((case / (variant + '-gdb.json')).read_text())
        assert observed['status'] == 'PASS' and observed['exitCode'] == 0
        warnings = (case / (variant + '.stderr')).read_text().splitlines()
        assert len(warnings) <= 1
        for warning in warnings:
            if warning == 'Failed to read a valid object file image from memory.':
                reference.corroborate_unmapped_vdso_sections(observed)
            else:
                assert re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', warning)
        assert (case / (variant + '.qemu.status')).read_text() == 'exit=0\n'
        assert not (case / (variant + '.qemu.stderr')).read_bytes()
        observations.append(observed)
    after = {path: digest(Path(path)) for path in before}
    assert before == after
    result = {'status': 'PASS_BASELINE' if args.failure_controls else 'PASS', 'profile': vars(args) | {'ghidra': str(ghidra), 'gdb': str(args.gdb),
        'gdb_data': str(args.gdb_data)}, 'rawCallingConventions': raw, 'gdb': observations,
        'protectedBefore': before, 'protectedAfter': after, 'programBefore': program_before,
        'programAfter': program_after, 'rotatedBackups': changed}
    write('result.json', result)
    if args.failure_controls:
        run('failure-controls', ['python3', source / 'arm-pcs-failure-controls.py', case])
        result['failureControls'] = json.loads((case / 'failure-controls.json').read_text())
        assert result['failureControls']['status'] == 'PASS'
        result['status'] = 'PASS'
        write('result.json', result)
    print('arm-pcs-profile=PASS ' + str(case))


if __name__ == '__main__':
    main()

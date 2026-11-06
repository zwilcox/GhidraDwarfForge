#!/usr/bin/env python3
"""Validate real imported-program/native exports against independent unwind fixtures."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'cfi-encoder.py'))
metadata, decode = (helpers[name] for name in ('metadata', 'decode'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(argv, log, env=None):
    argv = list(map(str, argv))
    Path(str(log) + '.command.json').write_text(json.dumps(argv) + '\n')
    with log.open('w') as stream:
        subprocess.run(argv, stdout=stream, stderr=subprocess.STDOUT, check=True,
            timeout=360, env={**os.environ, 'LC_ALL': 'C', **(env or {})})
    return log.read_text()


def normalized(record):
    trace = copy.deepcopy(record['trace'])
    for stack in trace:
        for frame in stack:
            frame['pc'] -= record['checkpointAddress']
    return trace


def add_original_frames(case, target, encoding):
    """Keep original leaf and terminal-boundary FDEs; recover the recursive caller."""
    original, reference = case / 'original', case / 'reference'
    original_bytes, original_meta = original.read_bytes(), metadata(original)
    section, = [s for s in metadata(reference)['sections'] if s['name'] == '.debug_frame']
    raw = reference.read_bytes()[section['offset']:section['offset'] + section['size']]
    cie_end = 4 + int.from_bytes(raw[:4], 'little')
    fde_end = cie_end + 4 + int.from_bytes(raw[cie_end:cie_end + 4], 'little')
    assert 0 < cie_end < fde_end <= len(raw) and fde_end % 8 == 0
    assert raw[4:8] == b'\xff' * 4 and raw[cie_end + 4:cie_end + 8] == b'\0' * 4
    address = int.from_bytes(raw[cie_end + 8:cie_end + 16], 'little')
    size = int.from_bytes(raw[cie_end + 16:cie_end + 24], 'little')
    recursive_end = fde_end + 4 + int.from_bytes(raw[fde_end:fde_end + 4], 'little')
    terminal_end = recursive_end + 4 + int.from_bytes(raw[recursive_end:recursive_end + 4], 'little')
    assert fde_end < recursive_end < terminal_end == len(raw)
    assert raw[recursive_end + 4:recursive_end + 8] == b'\0' * 4
    # The original leaf explicitly omits some preserved-register values. Keep
    # the assembler's explicit outer boundary too: no generated rule may invent
    # those values to make fallback unwinding outside the proved group succeed.
    original_prefix = raw[:fde_end] + raw[recursive_end:terminal_end]
    prefix = case / 'assembler-prefix.frame'; prefix.write_bytes(original_prefix)
    tool = 'objcopy' if target == 'x86_64' else 'aarch64-linux-gnu-objcopy'
    decorated = case / 'decorated-original'
    run([tool, '--add-section', '.debug_frame=' + str(prefix), '--set-section-alignment', '.debug_frame=8',
        '--set-section-flags', '.debug_frame=readonly,debug', original, decorated], case / 'add-original-frame.log')
    if encoding != 'plain':
        run([tool, '--compress-debug-sections=' + ('zlib-gabi' if encoding == 'gabi' else 'zlib-gnu'), decorated],
            case / 'compress-original-frame.log')
    changed_bytes, changed_meta = decorated.read_bytes(), metadata(decorated)
    assert original_meta['profile'] == changed_meta['profile']
    assert all(original_meta[key] == changed_meta[key] for key in ('phoff', 'phsize', 'phcount'))
    first = original_meta['phoff']; last = first + original_meta['phsize'] * original_meta['phcount']
    assert original_bytes[first:last] == changed_bytes[first:last]
    for old in (s for s in original_meta['sections'] if s['flags'] & 2):
        new, = [s for s in changed_meta['sections'] if s['name'] == old['name']]
        assert all(old[key] == new[key] for key in ('type', 'flags', 'address', 'offset', 'size'))
        if old['type'] != 8:
            assert original_bytes[old['offset']:old['offset'] + old['size']] == changed_bytes[new['offset']:new['offset'] + new['size']]
    decorated.replace(original)
    return original_prefix, (address, size)


def generated_suffix(raw, prefix, expected):
    """Check prefix identity and appended CIE references before standalone decoding."""
    assert raw.startswith(prefix)
    suffix = bytearray(raw[len(prefix):])
    assert len(suffix) >= 8 and suffix[4:8] == b'\xff' * 4
    offset = 4 + int.from_bytes(suffix[:4], 'little')
    count = 0
    while offset < len(suffix):
        length = int.from_bytes(suffix[offset:offset + 4], 'little')
        assert length >= 20 and offset + 4 + length <= len(suffix)
        assert int.from_bytes(suffix[offset + 4:offset + 8], 'little') == len(prefix)
        suffix[offset + 4:offset + 8] = b'\0' * 4
        offset += 4 + length
        count += 1
    assert offset == len(suffix) and count == len(expected)
    assert decode(suffix, 8, 'little') == expected


def add_runtime_frames(case, target, role, family, expected, dwarfdump, processor_type=False):
    """Source-build partial runtime CFI and an independent complete reference."""
    source = ROOT / 'src/test/fixtures' / ('cfi-' + family + '-' + target + '.S')
    text = source.read_text()
    first, tail = text.split('cf_recurse:', 1)
    middle, last = tail.split('    .size cf_recurse,.-cf_recurse', 1)
    middle = '\n'.join(line for line in middle.split('\n')
        if not line.strip().startswith('.cfi_') and line.strip() != 'ordinary_rules')
    partial = (first + 'cf_recurse:' + middle + '    .size cf_recurse,.-cf_recurse' + last)
    partial = partial.replace('.cfi_sections .debug_frame', '.cfi_sections .eh_frame')
    complete = text.replace('.cfi_sections .debug_frame', '.cfi_sections .eh_frame, .debug_frame')
    if processor_type:
        assert target == 'x86_64'
        partial = partial.replace('    .cfi_sections', '    .section .eh_frame,"a",@unwind\n    .cfi_sections', 1)
        complete = complete.replace('    .cfi_sections', '    .section .eh_frame,"a",@unwind\n    .cfi_sections', 1)
    prefix = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
    flags = {'exec': ['-static', '-no-pie'], 'pie': ['-fPIE', '-static-pie'],
        'shared': ['-fPIC', '-shared', '-Wl,-Bsymbolic', '-DCFI_SHARED']}[role]
    previous = case / 'prior-original'
    shutil.copy2(case / 'original', previous)
    for name, content in (('original', partial), ('reference', complete)):
        generated = case / (name + '.S'); generated.write_text(content)
        for suffix in ('', '-repeat'):
            run([prefix + 'gcc', '-nostdlib', *flags, '-Wl,--build-id=none', '-Wl,--eh-frame-hdr',
                generated, '-o', case / (name + suffix)], case / (name + suffix + '-build.log'))
        assert (case / name).read_bytes() == (case / (name + '-repeat')).read_bytes()

    def symbols(path):
        found = {}
        for line in run(['readelf', '-Ws', path], case / (path.name + '-symbols.log')).splitlines():
            fields = line.split()
            if len(fields) == 8 and fields[7] in ('cf_checkpoint', 'cf_recurse', '_start'):
                found[fields[7]] = (int(fields[1], 16), int(fields[2]))
        assert len(found) == 3
        return found

    original, reference = case / 'original', case / 'reference'
    old_symbols, new_symbols = symbols(previous), symbols(original)
    assert new_symbols == symbols(reference)
    old_meta, new_meta, ref_meta = map(metadata, (previous, original, reference))
    for info in (new_meta, ref_meta):
        frame, = [s for s in info['sections'] if s['name'] == '.eh_frame']
        assert frame['type'] == (0x70000001 if processor_type else 1)
    for name in ('.text', '.rodata'):
        new, = [s for s in new_meta['sections'] if s['name'] == name]
        ref, = [s for s in ref_meta['sections'] if s['name'] == name]
        assert new['address'] == ref['address'] and new['size'] == ref['size']
        assert original.read_bytes()[new['offset']:new['offset'] + new['size']] == \
            reference.read_bytes()[ref['offset']:ref['offset'] + ref['size']]
    # Adding runtime headers may move text. Reuse earlier recovered rows only
    # after proving the recursive function's actual instructions are identical.
    old_text, = [s for s in old_meta['sections'] if s['name'] == '.text']
    new_text, = [s for s in new_meta['sections'] if s['name'] == '.text']
    old_address, size = old_symbols['cf_recurse']
    new_address, new_size = new_symbols['cf_recurse']
    assert size == new_size
    old_offset = old_text['offset'] + old_address - old_text['address']
    new_offset = new_text['offset'] + new_address - new_text['address']
    assert previous.read_bytes()[old_offset:old_offset + size] == original.read_bytes()[new_offset:new_offset + size]
    delta = new_address - old_address
    assert all(new_symbols[name] == (address + delta, length) for name, (address, length) in old_symbols.items())
    expected = copy.deepcopy(expected)
    for frame in expected:
        frame['address'] += delta
        for row in frame['rows']:
            row['address'] += delta
    original_range = new_symbols['cf_checkpoint']
    checker = runpy.run_path(str(SCRIPTS / 'check-dwarfdump.py'))
    for name, path in (('original', original), ('reference', reference)):
        text = run(['readelf', '-h', '-S', '--debug-dump=frames', path], case / (name + '-gnu.log'))
        assert not re.search(r'warning:|error:', text, re.IGNORECASE)
        run(['llvm-dwarfdump', '--verify', path], case / (name + '-llvm.log'))
        frames = run([dwarfdump, '--no-follow-debuglink', '--print-eh-frame', '--print-frame', path],
            case / (name + '-frames.log'))
        assert '\nfde:\n' in frames and '\ncie:\n' in frames
        assert not re.search(r'DW_DLE_|\b(?:warning|error|fatal):', frames, re.IGNORECASE)
        text = run([dwarfdump, '--no-follow-debuglink', '-ka', '-ki', '-kd', path], case / (name + '-strict.log'))
        # Assembler controls have no compilation units; exported sidecars below
        # still use the ordinary nonzero-CU strict validation contract.
        # GNU runtime FDEs are four-byte aligned. The pinned libdwarf checker
        # also diagnoses records not aligned to the eight-byte address size.
        # Independently reconstruct every such notice from the actual input
        # bytes; do not accept an arbitrary diagnostic merely because it exists.
        unused, raw = checker['elf_frame_identity'](path)
        offset, notices = 0, []
        while offset < len(raw):
            length = int.from_bytes(raw[offset:offset + 4], 'little')
            if length == 0:
                assert not any(raw[offset:])
                break
            total = length + 4
            assert 4 <= length < 0xfffffff0 and offset + total <= len(raw) and total % 4 == 0
            if total % 8:
                kind = 'cie' if raw[offset + 4:offset + 8] == b'\0' * 4 else 'fde'
                notices.append('*** DWARF CHECK: DW_DLE_DEBUG_FRAME_LENGTH_NOT_MULTIPLE '
                    f'len=0x{length:08x}, len size=0x00000004, extn size=0x00000000, '
                    f'totl length=0x{total:08x}, addr size=0x00000008, mod=0x{total % 8:08x} '
                    f'must be zero in {kind}, offset 0x{offset:08x}. ***')
            offset += total
        checked = checker['validate_output'](text, notices, original=True)
        checked['inputFrameNoticesConfirmedFromBytes'] = notices
        (case / (name + '-input-validation.json')).write_text(json.dumps(checked, indent=4) + '\n')
    return expected, original_range


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('recovery_cases', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--libdwarf', type=Path)
    parser.add_argument('--libdwarfp', type=Path)
    parser.add_argument('--target', choices=('x86_64', 'aarch64', 'all'), default='all')
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie', 'shared'), default=('exec', 'pie', 'shared'))
    parser.add_argument('--failed-source-name', default='none')
    originals = parser.add_mutually_exclusive_group()
    originals.add_argument('--original-encoding', choices=('plain', 'gabi', 'gnu'),
        help='Retain assembler leaf/outer-boundary records and recover only the uncovered recursive frame')
    originals.add_argument('--original-runtime', action='store_true',
        help='Source-build original leaf/outer-boundary .eh_frame and recover the recursive frame')
    parser.add_argument('--runtime-section-type', choices=('progbits', 'processor'), default='progbits',
        help='Processor type requires --original-runtime --target x86_64')
    args = parser.parse_args()
    if args.runtime_section_type == 'processor' and (not args.original_runtime or args.target != 'x86_64'):
        parser.error('processor section type requires --original-runtime --target x86_64')
    assert bool(args.libdwarf) == bool(args.libdwarfp)
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve(strict=True)
    natives = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/os/linux_x86_64'
    args.libdwarf = args.libdwarf or next(natives.glob('libdwarf.so.*.*.*'))
    args.libdwarfp = args.libdwarfp or next(natives.glob('libdwarfp.so.*.*.*'))
    prior = json.loads((args.recovery_cases / 'result.json').read_text())
    assert prior['status'] == 'PASS_NATIVE_RECOVERED_CFI'
    protected = {str(p.resolve()): digest(p) for p in (args.libdwarf, args.libdwarfp,
        ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar',
        SCRIPTS / 'ghidra_scripts/ExportRecoveredFrames.java',
        SCRIPTS / 'ghidra_scripts/RecoveredFrameExportControls.java')}
    if args.original_runtime:
        for source in (ROOT / 'src/test/fixtures').glob('cfi-*.S'):
            protected[str(source.resolve())] = digest(source)
    outcomes = []
    for item in prior['cases']:
        target, role, family = (item[key] for key in ('target', 'role', 'fixtureFamily'))
        if (args.target != 'all' and target != args.target) or role not in args.roles:
            continue
        source = args.recovery_cases.resolve() / (target + '-' + role)
        case = work / source.name; case.mkdir()
        outputs = case / 'outputs'; outputs.mkdir()
        project = case / 'project'; project.mkdir()
        inputs = ['original', 'reference'] + (['driver'] if role == 'shared' else [])
        for name in inputs:
            shutil.copy2(source / name, case / name)
        shutil.copy2(source / 'none.frame', case / 'expected.frame')
        inputs.append('expected.frame')
        original, reference = case / 'original', case / 'reference'
        expected = decode((case / 'expected.frame').read_bytes(), 8, 'little')
        original_prefix, original_range = b'', None
        remaining = expected
        if args.original_encoding:
            original_prefix, original_range = add_original_frames(case, target, args.original_encoding)
        if args.original_runtime:
            expected, original_range = add_runtime_frames(case, target, role, family, expected, args.dwarfdump,
                args.runtime_section_type == 'processor')
            inputs += ['original.S', 'reference.S', 'prior-original']
        if original_range:
            remaining = [f for f in expected if (f['address'], f['size']) != original_range]
            assert len(remaining) == len(expected) - 1 and remaining
        before = {str(case / name): digest(case / name) for name in inputs}
        log = run([ghidra / 'support/analyzeHeadless', project, 'Frames', '-import', original,
            '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'RecoveredFrameExportControls.java',
            args.libdwarf.resolve(), args.libdwarfp.resolve(), outputs, args.failed_source_name], case / 'export.log')
        assert 'native-frame-export-controls=PASS successful=9 controls=2' in log
        assert log.count('native-frame-export=PASS ') == 9
        assert log.count('native-frame-staging-control=PASS ') == 2
        assert re.findall(r'native-frame-export=PASS frames=(\d+)', log) == [str(len(remaining))] * 9
        deltas = [int(value) for value in re.findall(r'native-frame-export=PASS .* delta=(\d+)', log)]
        assert deltas == [deltas[0]] * 4 + [deltas[0] + 0x400000] * 5, deltas
        artifacts = []
        for variant in ('none', 'zlib', 'before-rebase-none', 'before-rebase-zlib'):
            compression = variant.rsplit('-', 1)[-1]
            artifact = outputs / (variant + '.dbg')
            sections = metadata(artifact)['sections']
            section, = [s for s in sections if s['name'] in ('.debug_frame', '.zdebug_frame')]
            assert section['name'] == '.debug_frame'
            raw = artifact.read_bytes()[section['offset']:section['offset'] + section['size']]
            if compression == 'zlib':
                assert section['flags'] & 0x800 and int.from_bytes(raw[:4], 'little') == 1
                size = int.from_bytes(raw[8:16], 'little')
                raw = zlib.decompress(raw[24:]); assert len(raw) == size
            else:
                assert not section['flags'] & 0x800
            if args.original_encoding:
                generated_suffix(raw, original_prefix, remaining)
                inherited, = [s for s in metadata(original)['sections'] if s['name'] in ('.debug_frame', '.zdebug_frame')]
                preserved, = [s for s in sections if s['name'] == '.forge.stale' + inherited['name']]
                assert all(preserved[k] == inherited[k] for k in ('offset', 'size', 'type', 'flags', 'address'))
                assert artifact.read_bytes()[preserved['offset']:preserved['offset'] + preserved['size']] == \
                    original.read_bytes()[inherited['offset']:inherited['offset'] + inherited['size']]
            else:
                assert decode(raw, 8, 'little') == remaining, 'real import changed recovered frame rules'
            if args.original_runtime:
                for name in ('.eh_frame', '.eh_frame_hdr'):
                    inherited, = [s for s in metadata(original)['sections'] if s['name'] == name]
                    preserved, = [s for s in sections if s['name'] == name]
                    assert all(preserved[k] == inherited[k] for k in ('offset', 'size', 'type', 'flags', 'address'))
                    assert artifact.read_bytes()[preserved['offset']:preserved['offset'] + preserved['size']] == \
                        original.read_bytes()[inherited['offset']:inherited['offset'] + inherited['size']]
            (case / (variant + '.frame')).write_bytes(raw)
            text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact], case / (variant + '-gnu.log'))
            assert 'warning:' not in text.lower() and 'error:' not in text.lower()
            if args.failed_source_name != 'none':
                dies = re.split(r'(?m)^ <\d+><[0-9a-f]+>: ', text)
                failed_die, = [die for die in dies if re.match(r'Abbrev Number: \d+ \(DW_TAG_subprogram\)', die) and
                    re.search(r'DW_AT_name\s*:.*: ' + re.escape(args.failed_source_name) + r'\n', die)]
                assert set(re.findall(r'DW_AT_\w+', failed_die)) == {'DW_AT_name', 'DW_AT_low_pc', 'DW_AT_high_pc'}
                assert 'Decompilation unavailable for ' + args.failed_source_name in Path(str(artifact) + '.c').read_text()
            run(['llvm-dwarfdump', '--verify', artifact], case / (variant + '-llvm.log'))
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact,
                case / (variant + '-strict.log'), '--tool', args.dwarfdump, '--original', original],
                case / (variant + '-strict-command.log'))
            if variant.startswith('before-rebase-'):
                artifacts.append({'mode': variant, 'sha256': digest(artifact),
                    'sourceSha256': digest(Path(str(artifact) + '.c'))})
                continue
            report = json.loads(Path(str(artifact) + '.report.json').read_text())
            assert report['counts']['mappedSourceLines'] > 0 and '.debug_frame' in report['sections']
            failed = report['failedFunctions']
            if args.failed_source_name == 'none':
                assert not failed, failed
            else:
                assert len(failed) == 1 and failed[0]['name'] == args.failed_source_name, failed
            artifacts.append({'mode': compression, 'sha256': digest(artifact),
                'sourceSha256': digest(Path(str(artifact) + '.c')), 'counts': report['counts']})
        env = {'FORGE_FRAME_PROFILE': family, 'FORGE_FRAME_SHARED': '1' if role == 'shared' else '0',
               'FORGE_FRAME_DRIVER': str(case / 'driver')}
        results, warnings = {}, {}
        modes = [('reference', reference), ('absent', original), ('none', outputs / 'none.dbg'),
                 ('zlib', outputs / 'zlib.dbg'), ('disabled', outputs / 'none.dbg'),
                 ('before-rebase-none', outputs / 'before-rebase-none.dbg'),
                 ('before-rebase-zlib', outputs / 'before-rebase-zlib.dbg')]
        for mode, artifact in modes:
            prefix = case / ('gdb-' + mode)
            run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, mode, artifact, original, prefix],
                case / ('gdb-' + mode + '-command.log'), env)
            result = json.loads(Path(str(prefix) + '.json').read_text())
            text = Path(str(prefix) + '.log').read_text()
            bias = result['checkpointAddress'] - min(f['address'] for f in expected)
            selected = sorted(set((int(level), int(pc, 16) - bias)
                for level, pc in re.findall(r'level=(\d+),type=NORMAL_FRAME,unwinder="dwarf2",pc=(0x[0-9a-f]+)', text)
                if any(f['address'] <= int(pc, 16) - bias < f['address'] + f['size'] for f in expected)))
            uses_cfi = mode not in ('absent', 'disabled')
            if mode == 'disabled' or (mode == 'absent' and not original_range):
                assert not selected, selected
            for level in range(4 if family == 'shrinkwrap' else 5):
                wanted = uses_cfi or (mode == 'absent' and original_range and level == 0)
                assert any(found == level for found, pc in selected) == bool(wanted), (mode, level, selected)
            if role == 'shared': assert result['moduleBias'] > 0 and bias == result['moduleBias']
            result['selectedDwarfFrames'] = selected
            results[mode] = result
            warnings[mode] = [line for line in text.splitlines() if 'warning:' in line.lower()]
        assert all(normalized(results[mode]) == normalized(results['reference'])
            for mode in ('none', 'zlib', 'before-rebase-none', 'before-rebase-zlib'))
        for mode, messages in warnings.items():
            # Preserved pre-rebase sidecars still name the final source path.
            # Later deterministic reruns replace that source after this snapshot.
            # Retain GDB's precise timestamp warning; no other new warning is allowed.
            comparable = [line for line in messages if not (mode.startswith('before-rebase-') and
                line == 'warning: Source file is more recent than executable.')]
            assert comparable == warnings['reference'], (mode, messages)
        assert all(target == 'aarch64' and re.fullmatch(
            r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', line)
            for line in warnings['reference'])
        source_results = {}
        for mode in ('none', 'zlib'):
            prefix = case / ('source-' + mode)
            run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, mode, outputs / (mode + '.dbg'), original, prefix],
                case / ('source-' + mode + '-command.log'),
                {**env, 'FORGE_FRAME_GDB_SCRIPT': str(SCRIPTS / 'unwind-source-gdb.py')})
            source_results[mode] = json.loads(Path(str(prefix) + '.json').read_text())
            assert source_results[mode]['status'] == 'PASS_SOURCE_WITH_FRAMES'
            source_warnings = [line for line in Path(str(prefix) + '.log').read_text().splitlines() if 'warning:' in line.lower()]
            assert source_warnings == warnings['reference'], source_warnings
        assert before == {name: digest(Path(name)) for name in before}
        run([sys.executable, SCRIPTS / 'retained-validator-reports.py', case,
            '--output', case / 'retained-validator-reports.json'], case / 'retained-validator-reports.log')
        outcomes.append({'target': target, 'role': role, 'family': family, 'artifacts': artifacts,
            'originalEncoding': args.original_encoding, 'originalFrameRange': original_range,
            'originalRuntime': args.original_runtime,
            'runtimeSectionType': args.runtime_section_type,
            'originalFramePrefixSha256': hashlib.sha256(original_prefix).hexdigest() if original_prefix else None,
            'runtime': results, 'sourceRuntime': source_results, 'warnings': warnings, 'inputHashes': before,
            'successfulExports': 9, 'failureControls': 2})
        (work / 'progress.json').write_text(json.dumps(outcomes, indent=4) + '\n')
        print(target + ' ' + role + ' real native frame export PASS', flush=True)
    assert outcomes
    assert protected == {name: digest(Path(name)) for name in protected}
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_FRAME_EXPORT', 'protected': protected,
        'failedSourceName': args.failed_source_name, 'originalEncoding': args.original_encoding, 'cases': outcomes,
        'originalRuntime': args.original_runtime,
        'runtimeSectionType': args.runtime_section_type,
        'scope': 'Real ELF import, decompiler, native producer and staged frame writer; explicit test entry, not enabled CLI synthesis'}, indent=4) + '\n')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Native instruction recovery to CFI, checked against independent assembler/GDB traces."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'cfi-encoder.py'))
run, metadata, decode = (helpers[name] for name in ('run', 'metadata', 'decode'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('classes', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--java', default='java')
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--target', choices=('x86_64', 'aarch64', 'all'), default='all')
    parser.add_argument('--fixture-family', choices=('encoder', 'shrinkwrap'), default='encoder')
    parser.add_argument('--roles', nargs='+', choices=('exec', 'pie', 'shared'), default=('exec', 'pie', 'shared'))
    parser.add_argument('--gradle-init', type=Path)
    parser.add_argument('--gradle-cache', type=Path)
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    classpath = os.pathsep.join(str(args.classes.resolve() / name) for name in ('main', 'test'))
    gradle = [ROOT / 'gradlew']
    if args.gradle_init: gradle += ['--init-script', args.gradle_init.resolve()]
    if args.gradle_cache: gradle += ['--project-cache-dir', args.gradle_cache.resolve()]
    reports = []
    targets = ('x86_64', 'aarch64') if args.target == 'all' else (args.target,)
    for target in targets:
        for role in args.roles:
            case = work / (target + '-' + role)
            case.mkdir()
            tool = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
            source = ROOT / 'src/test/fixtures' / ('cfi-' + args.fixture_family + '-' + target + '.S')
            reference, original = case / 'reference', case / 'original'
            flags = {'exec': ['-static', '-no-pie'], 'pie': ['-fPIE', '-static-pie'],
                     'shared': ['-fPIC', '-shared', '-Wl,-Bsymbolic', '-DCFI_SHARED']}[role]
            run([tool + 'gcc', '-nostdlib', *flags, '-Wl,--build-id=none', source, '-o', reference], case / 'build.log')
            repeated = case / 'reference-repeat'
            run([tool + 'gcc', '-nostdlib', *flags, '-Wl,--build-id=none', source, '-o', repeated], case / 'build-repeat.log')
            assert reference.read_bytes() == repeated.read_bytes(), 'independent fixture rebuild changed bytes'
            run([tool + 'objcopy', '--strip-debug', reference, original], case / 'strip.log')
            initial = {str(path): digest(path) for path in (source, reference, original)}
            runtime_env = {'FORGE_FRAME_PROFILE': args.fixture_family,
                           'FORGE_FRAME_SHARED': '1' if role == 'shared' else '0'}
            if role == 'shared':
                driver_source = ROOT / 'src/test/fixtures/synthetic-cfi-shared-driver.c'
                driver = case / 'driver'
                run([tool + 'gcc', '-O0', '-g', '-fno-pie', '-no-pie', '-DCFI_ENTRY_NAME="_start"',
                     driver_source, '-ldl', '-o', driver], case / 'driver-build.log')
                runtime_env['FORGE_FRAME_DRIVER'] = str(driver)
                initial.update({str(path): digest(path) for path in (driver_source, driver)})
            info = metadata(original)
            # The PIE linker leaves an empty allocated .eh_frame section. It
            # contains no records and is retained unchanged in the input.
            assert not any(s['name'] in ('.debug_frame', '.eh_frame') and s['size'] for s in info['sections'])
            run(['readelf', '--debug-dump=frames', original], case / 'original-frames.log')
            symbols = {}
            for line in run(['readelf', '-Ws', reference], case / 'symbols.log').splitlines():
                fields = line.split()
                if len(fields) == 8 and fields[7] in ('cf_checkpoint', 'cf_recurse'):
                    symbols[fields[7]] = (int(fields[1], 16), int(fields[2]))
            assert len(symbols) == 2
            records = []
            data = original.read_bytes()
            for name, (address, size) in sorted(symbols.items()):
                section, = [s for s in info['sections'] if s['type'] == 1 and s['flags'] & 4 and
                            s['address'] <= address and address + size <= s['address'] + s['size']]
                offset = section['offset'] + address - section['address']
                records.append(f'{name} {address:x} ' + data[offset:offset + size].hex())
            functions = case / 'functions.txt'
            functions.write_text('\n'.join(records) + '\n')
            plans = []
            for delta in (0, 0x400000):
                plan = case / f'plan-{delta:x}.txt'
                run([*gradle, 'unwindFrameRecoveryProbe', '-PframeInput=' + str(original),
                     '-PframeFunctions=' + str(functions), '-PframePlan=' + str(plan),
                     '-PframeRebase=' + hex(delta)], case / f'recover-{delta:x}.log')
                matched = []
                for line in Path(str(plan) + '.original-bytes.txt').read_text().splitlines():
                    address_text, offset_text, length_text, sha256 = line.split()
                    address, offset, length = int(address_text, 16), int(offset_text, 16), int(length_text)
                    section, = [s for s in info['sections'] if s['type'] == 1 and s['flags'] & 4 and
                                s['address'] <= address and address + length <= s['address'] + s['size']]
                    assert offset == section['offset'] + address - section['address']
                    assert sha256 == hashlib.sha256(data[offset:offset + length]).hexdigest()
                    matched.append((address, address + length))
                for start, size in symbols.values():
                    cursor = start
                    for first, last in sorted(pair for pair in matched if start <= pair[0] < start + size):
                        assert first == cursor and last > first and last <= start + size
                        cursor = last
                    assert cursor == start + size, 'original-byte proof omitted function instructions'
                plans.append(plan)
            assert plans[0].read_bytes() == plans[1].read_bytes(), 'database rebasing changed original-image CFI rules'
            assert Path(str(plans[0]) + '.original-bytes.txt').read_bytes() == Path(str(plans[1]) + '.original-bytes.txt').read_bytes()
            modes = [('reference', reference), ('absent', original)]
            empty_prefix = case / 'empty-original.frame'
            empty_prefix.write_bytes(b'')
            for compression in ('none', 'zlib'):
                artifact, raw = case / (compression + '.dbg'), case / (compression + '.frame')
                command = [args.java, '-cp', classpath, 'ghidradwarfforge.unwind.CallFrameEncoderProbe',
                           plans[0], original, artifact, raw, compression, empty_prefix, 'from-original']
                run(command, case / (compression + '-encode.log'))
                first = artifact.read_bytes()
                run(command, case / (compression + '-repeat.log'))
                assert first == artifact.read_bytes()
                frames = decode(raw.read_bytes(), 8, 'little')
                assert [(f['address'], f['size']) for f in frames] == sorted(symbols.values())
                assert all(f['rows'][0]['address'] == f['address'] for f in frames)
                text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact],
                           case / (compression + '-gnu.log'))
                assert 'warning' not in text.lower() and 'error' not in text.lower()
                run(['llvm-dwarfdump', '--verify', artifact], case / (compression + '-llvm.log'))
                run(['llvm-dwarfdump', '--debug-frame', artifact], case / (compression + '-llvm-frame.log'))
                run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact,
                     case / (compression + '-strict.log'), '--tool', args.dwarfdump], case / (compression + '-strict-driver.log'))
                modes.append((compression, artifact))
            assert (case / 'none.frame').read_bytes() == (case / 'zlib.frame').read_bytes()
            modes.append(('disabled', case / 'none.dbg'))
            results, warnings = {}, {}
            for mode, artifact in modes:
                prefix = case / ('gdb-' + mode)
                run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, mode, artifact, original, prefix],
                    case / ('gdb-' + mode + '-driver.log'), env=runtime_env)
                results[mode] = json.loads(Path(str(prefix) + '.json').read_text())
                if role == 'shared':
                    assert results[mode]['moduleBias'] > 0, 'shared object did not relocate'
                    assert results[mode]['checkpointAddress'] - results[mode]['moduleBias'] == symbols['cf_checkpoint'][0]
                text = Path(str(prefix) + '.log').read_text()
                bias = results[mode]['checkpointAddress'] - symbols['cf_checkpoint'][0]
                # A fallback may wander into libc, whose genuine CFI is unrelated
                # to this fixture. Require the selected unwinder's PC to belong
                # to the exact recovered instruction ranges, not just its level.
                selected_frames = sorted(set((int(level), int(pc, 16) - bias)
                    for level, pc in re.findall(r'level=(\d+),type=NORMAL_FRAME,unwinder="dwarf2",pc=(0x[0-9a-f]+)', text)
                    if any(start <= int(pc, 16) - bias < start + size for start, size in symbols.values())))
                results[mode]['selectedDwarfFrames'] = selected_frames
                uses_cfi = mode not in ('absent', 'disabled')
                if not uses_cfi:
                    assert not selected_frames, (target, role, mode, selected_frames)
                for level in range(4 if args.fixture_family == 'shrinkwrap' else 5):
                    assert any(found == level for found, pc in selected_frames) == uses_cfi, (target, role, mode, level)
                warnings[mode] = [line for line in text.splitlines() if 'warning:' in line.lower()]
            def normalized(result):
                trace = copy.deepcopy(result['trace'])
                for stack in trace:
                    for frame in stack: frame['pc'] -= result['checkpointAddress']
                return trace
            assert normalized(results['reference']) == normalized(results['none']) == normalized(results['zlib'])
            assert all(value == warnings['reference'] for value in warnings.values())
            assert all(target == 'aarch64' and re.fullmatch(
                r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', line)
                for line in warnings['reference'])
            assert initial == {path: digest(Path(path)) for path in initial}
            reports.append({'target': target, 'role': role, 'fixtureFamily': args.fixture_family,
                            'inputHashes': initial, 'planSha256': digest(plans[0]),
                            'frameSha256': digest(case / 'none.frame'), 'runtime': results, 'warnings': warnings})
            print(target + ' ' + role + ' native recovered CFI PASS', flush=True)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_RECOVERED_CFI', 'cases': reports,
        'scope': 'Actual runtime bytes decoded by Sleigh, closed-group proof and row projection; test-only byte importer and CU, not production exporter acceptance'}, indent=4) + '\n')


if __name__ == '__main__':
    main()

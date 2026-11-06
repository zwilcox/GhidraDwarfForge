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
        for role in ('exec', 'pie'):
            case = work / (target + '-' + role)
            case.mkdir()
            tool = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
            source = ROOT / 'src/test/fixtures' / ('cfi-encoder-' + target + '.S')
            reference, original = case / 'reference', case / 'original'
            flags = ['-static', '-no-pie'] if role == 'exec' else ['-fPIE', '-static-pie']
            run([tool + 'gcc', '-nostdlib', *flags, '-Wl,--build-id=none', source, '-o', reference], case / 'build.log')
            run([tool + 'objcopy', '--strip-debug', reference, original], case / 'strip.log')
            initial = {str(path): digest(path) for path in (source, reference, original)}
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
                plans.append(plan)
            assert plans[0].read_bytes() == plans[1].read_bytes(), 'database rebasing changed original-image CFI rules'
            modes = [('reference', reference), ('absent', original)]
            for compression in ('none', 'zlib'):
                artifact, raw = case / (compression + '.dbg'), case / (compression + '.frame')
                command = [args.java, '-cp', classpath, 'ghidradwarfforge.unwind.CallFrameEncoderProbe',
                           plans[0], original, artifact, raw, compression]
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
            results, warnings = {}, {}
            for mode, artifact in modes:
                prefix = case / ('gdb-' + mode)
                run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, mode, artifact, original, prefix],
                    case / ('gdb-' + mode + '-driver.log'))
                results[mode] = json.loads(Path(str(prefix) + '.json').read_text())
                text = Path(str(prefix) + '.log').read_text()
                for level in range(5):
                    selected = f'level={level},type=NORMAL_FRAME,unwinder="dwarf2",pc='
                    assert (selected in text) == (mode != 'absent'), (target, role, mode, level)
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
            reports.append({'target': target, 'role': role, 'inputHashes': initial, 'planSha256': digest(plans[0]),
                            'frameSha256': digest(case / 'none.frame'), 'runtime': results, 'warnings': warnings})
            print(target + ' ' + role + ' native recovered CFI PASS', flush=True)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_RECOVERED_CFI', 'cases': reports,
        'scope': 'Actual runtime bytes decoded by Sleigh, closed-group proof and row projection; test-only byte importer and CU, not production exporter acceptance'}, indent=4) + '\n')


if __name__ == '__main__':
    main()

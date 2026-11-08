#!/usr/bin/env python3
"""Append generated frames to an unchanged compiler CIE/FDE prefix and run GDB."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import sys
import zlib

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'cfi-encoder.py'))
run, metadata, decode = (helpers[name] for name in ('run', 'metadata', 'decode'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(record):
    trace = copy.deepcopy(record['trace'])
    for stack in trace:
        for frame in stack:
            frame['pc'] -= record['checkpointAddress']
    return trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('classes', type=Path)
    parser.add_argument('encoder_results', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--java', default='java')
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--original-encoding', choices=('plain', 'gabi', 'gnu'),
        help='Exercise qualified writer composition from an original ELF containing the compiler prefix')
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    classpath = os.pathsep.join(str(args.classes.resolve() / name) for name in ('main', 'test'))
    prior = json.loads((args.encoder_results / 'result.json').read_text())
    assert prior['status'] == 'PASS_FRAME_ENCODER'
    outcomes = []
    for item in prior['cases']:
        if 'runtime' not in item:
            continue
        source = Path(item['directory'])
        target = source.name.rsplit('-', 1)[0]
        case = work / source.name
        case.mkdir()
        reference, original = source / 'reference', source / 'original'
        before = {str(path): digest(path) for path in (reference, original)}
        section, = [s for s in metadata(reference)['sections'] if s['name'] == '.debug_frame']
        raw = reference.read_bytes()[section['offset']:section['offset'] + section['size']]
        # These compiler fixtures deliberately emit DWARF32 records for ELF64 LE.
        cie_end = 4 + int.from_bytes(raw[:4], 'little')
        fde_end = cie_end + 4 + int.from_bytes(raw[cie_end:cie_end + 4], 'little')
        assert 0 < cie_end < fde_end <= len(raw) and fde_end % 8 == 0
        assert raw[4:8] == b'\xff' * 4 and raw[cie_end + 4:cie_end + 8] == b'\0' * 4
        address = int.from_bytes(raw[cie_end + 8:cie_end + 16], 'little')
        size = int.from_bytes(raw[cie_end + 16:cie_end + 24], 'little')
        prefix = case / 'compiler-prefix.frame'
        prefix.write_bytes(raw[:fde_end])
        if args.original_encoding:
            decorated = case / 'original'
            objcopy = 'objcopy' if target == 'x86_64' else 'aarch64-linux-gnu-objcopy'
            run([objcopy, '--add-section', '.debug_frame=' + str(prefix), '--set-section-alignment',
                '.debug_frame=8', '--set-section-flags', '.debug_frame=readonly,debug', original, decorated], case / 'add-original-frame.log')
            if args.original_encoding != 'plain':
                run([objcopy, '--compress-debug-sections=' + ('zlib-gabi' if args.original_encoding == 'gabi' else 'zlib-gnu'),
                    decorated], case / 'compress-original-frame.log')
            original = decorated
            before[str(original)] = digest(original)
        expected = decode((source / 'none.frame').read_bytes(), 8, 'little')
        selected, = [f for f in expected if f['address'] == address and f['size'] == size]
        expected.remove(selected)
        lines = (source / 'plan.txt').read_text().splitlines()
        kept, omit = lines[:2], False
        for line in lines[2:]:
            if line.startswith('frame '):
                omit = int(line.split()[1], 16) == address
            if not omit:
                kept.append(line)
        plan = case / 'plan.txt'
        plan.write_text('\n'.join(kept) + '\n')
        results = {}
        for mode in ('none', 'zlib'):
            artifact, frame = case / (mode + '.dbg'), case / (mode + '.frame')
            command = [args.java, '-cp', classpath, 'ghidradwarfforge.unwind.CallFrameEncoderProbe',
                plan, original, artifact, frame, mode, prefix]
            if args.original_encoding:
                command.extend(['from-original', 'controls'])
            run(command, case / (mode + '-encode.log'))
            first = digest(artifact)
            run(command, case / (mode + '-repeat.log'))
            assert first == digest(artifact)
            data = frame.read_bytes()
            assert data[:fde_end] == prefix.read_bytes()
            sections = metadata(artifact)['sections']
            active, = [s for s in sections if s['name'] in ('.debug_frame', '.zdebug_frame')]
            assert active['name'] == '.debug_frame'
            payload = artifact.read_bytes()[active['offset']:active['offset'] + active['size']]
            assert (zlib.decompress(payload[24:]) if active['flags'] & 0x800 else payload) == data
            if args.original_encoding:
                inherited, = [s for s in metadata(original)['sections'] if s['name'] in ('.debug_frame', '.zdebug_frame')]
                preserved, = [s for s in sections if s['name'] == '.forge.stale' + inherited['name']]
                assert all(preserved[k] == inherited[k] for k in ('offset', 'size', 'type', 'flags', 'address'))
                assert artifact.read_bytes()[preserved['offset']:preserved['offset'] + preserved['size']] == \
                    original.read_bytes()[inherited['offset']:inherited['offset'] + inherited['size']]
            # Independently inspect appended CIE pointers before decoding its rows
            # in a temporary zero-based view with the test-only consumer.
            suffix = bytearray(data[fde_end:])
            offset = 4 + int.from_bytes(suffix[:4], 'little')
            count = 0
            while offset < len(suffix):
                length = int.from_bytes(suffix[offset:offset + 4], 'little')
                assert int.from_bytes(suffix[offset + 4:offset + 8], 'little') == fde_end
                suffix[offset + 4:offset + 8] = b'\0' * 4
                assert length > 0
                offset += 4 + length
                count += 1
            assert offset == len(suffix) and count == len(expected)
            assert decode(suffix, 8, 'little') == expected
            log = run(['readelf', '-h', '-S', '--debug-dump=frames', artifact], case / (mode + '-gnu.log'))
            assert not re.search(r'warning|error', log, re.I)
            run(['llvm-dwarfdump', '--verify', artifact], case / (mode + '-llvm.log'))
            run(['llvm-dwarfdump', '--debug-frame', artifact], case / (mode + '-llvm-frame.log'))
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', artifact, case / (mode + '-strict.log'),
                '--tool', args.dwarfdump], case / (mode + '-strict-driver.log'))
            run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, mode, artifact, original,
                case / ('gdb-' + mode)], case / ('gdb-' + mode + '-driver.log'))
            result = json.loads((case / ('gdb-' + mode + '.json')).read_text())
            assert normalized(result) == normalized(item['runtime']['reference'])
            log = (case / ('gdb-' + mode + '.log')).read_text()
            assert 'level=0,type=NORMAL_FRAME,unwinder="dwarf2",pc=' + hex(result['checkpointAddress']) in log
            warnings = [line for line in log.splitlines() if 'warning:' in line.lower()]
            assert warnings == item['warnings']['reference']
            results[mode] = {'artifactSha256': first, 'runtime': result}
        assert before == {path: digest(Path(path)) for path in before}
        outcomes.append({'target': target, 'role': source.name.rsplit('-', 1)[1], 'compilerPrefixSha256': digest(prefix),
            'originalEncoding': args.original_encoding, 'prefixBytes': fde_end,
            'originalRange': [address, size], 'generatedRanges': len(expected), 'results': results})
        print(source.name + ' mixed compiler/generated CFI PASS', flush=True)
    assert outcomes
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_FRAME_COMPOSITION', 'cases': outcomes,
        'scope': 'Explicit plans and preserved compiler prefix; not production recovery or writer collision authorization'}, indent=4) + '\n')


if __name__ == '__main__':
    main()

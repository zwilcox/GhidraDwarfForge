#!/usr/bin/env python3
"""Compare real plain/compressed exports, validators and GDB on built target fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zlib


ROOT = Path(__file__).resolve().parents[3]
LIMIT = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode(payload, wide, order):
    size = 24 if wide else 12
    require(len(payload) >= size, 'truncated compression header')
    fields = struct.unpack_from(order + ('IIQQ' if wide else 'III'), payload)
    require(fields[0] == 1 and (not wide or fields[1] == 0), 'invalid compression type/reserved')
    count, alignment = fields[-2:]
    require(0 < count <= LIMIT and alignment == 1, 'invalid source size/alignment')
    inflater = zlib.decompressobj()
    plain = inflater.decompress(payload[size:], count + 1)
    require(len(plain) == count and inflater.eof and not inflater.unused_data
        and not inflater.unconsumed_tail, 'invalid compressed stream')
    require(len(payload) < len(plain), 'compression grew the section')
    return plain


def sections(path):
    raw = path.read_bytes()
    require(raw[:4] == b'\x7fELF' and raw[4] in (1, 2) and raw[5] in (1, 2), 'invalid ELF')
    wide, order = raw[4] == 2, '<' if raw[5] == 1 else '>'
    table, = struct.unpack_from(order + ('Q' if wide else 'I'), raw, 40 if wide else 32)
    stride, count, name_index = struct.unpack_from(order + 'HHH', raw, 58 if wide else 46)
    layout = order + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII')
    require(stride == struct.calcsize(layout) and table > 0, 'invalid section table')
    zero = struct.unpack_from(layout, raw, table)
    count = count or zero[5]
    name_index = zero[6] if name_index == 0xffff else name_index
    require(0 < name_index < count and table + stride * count <= len(raw), 'truncated section table')
    headers = [struct.unpack_from(layout, raw, table + i * stride) for i in range(count)]
    names_header = headers[name_index]
    names = raw[names_header[4]:names_header[4] + names_header[5]]
    result = {}
    for header in headers:
        require(header[0] < len(names), 'invalid section name')
        name = names[header[0]:].split(b'\0', 1)[0].decode('ascii')
        if not name.startswith('.debug_'):
            continue
        kind, flags, address, offset, size = header[1:6]
        require(name not in result and kind == 1 and address == 0 and flags in (0, 0x800),
            'invalid Forge debug section')
        require(offset + size <= len(raw), 'truncated section')
        payload = raw[offset:offset + size]
        if flags:
            require(header[8] == (8 if wide else 4) and offset % header[8] == 0,
                'misaligned compressed section')
            plain = decode(payload, wide, order)
            # Independent negative controls: reject damaged headers and incomplete/trailing streams.
            for damaged in (bytes(4) + payload[4:], payload[:-1], payload + b'!'):
                try:
                    decode(damaged, wide, order)
                except (ValueError, zlib.error):
                    continue
                raise ValueError('compression oracle accepted damaged section')
        else:
            require(header[8] == 1, 'unexpected plain section alignment')
            plain = payload
        result[name] = {'plainSha256': hashlib.sha256(plain).hexdigest(),
            'plainBytes': len(plain), 'storedBytes': size, 'compressed': bool(flags)}
    require('.debug_info' in result and '.debug_line' in result, 'missing DWARF')
    return result


def run(arguments, env, log):
    with log.open('x') as stream:
        subprocess.run([str(arg) for arg in arguments], cwd=ROOT, env=env,
            stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=900)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=['x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'])
    parser.add_argument('--roles', nargs='+', default=['exec', 'pie', 'shared', 'exec.no-sections', 'rebased-pie'],
        choices=['exec', 'pie', 'shared', 'exec.no-sections', 'rebased-pie'])
    args = parser.parse_args()
    ghidra = args.ghidra.resolve()
    native = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/os/linux_x86_64'
    results = ROOT / 'build/test-results/compression-export'
    results.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=args.target + '.', dir=results))
    print(f'compression-export results={work}', flush=True)
    receipt = {'status': 'RUNNING', 'target': args.target, 'cases': {}}
    for case in args.roles:
        role = 'pie' if case == 'rebased-pie' else case
        stem = 'libsemantic.so' if role == 'shared' else f'semantic.{role}'
        fixture = ROOT / 'build/fixtures' / args.target
        original = fixture / (stem + '.stripped')
        artifact = fixture / (stem + '.ghidra-forge.dbg')
        source = Path(str(artifact) + '.c')
        original_hash = digest(original)
        case_dir = work / case
        case_dir.mkdir()
        states = []
        for label, mode in (('plain', 'none'), ('zlib', 'zlib'), ('repeat', 'zlib')):
            directory = case_dir / label
            directory.mkdir()
            env = dict(os.environ, GHIDRA_DEBUG_COMPRESSION=mode, FIXTURE_ROLE=role,
                FORGE_SYMBOL_RESULTS=str(directory / 'validators'),
                FORGE_GDB_SYMBOL_RESULTS=str(directory / 'gdb'),
                GHIDRA_REBASE_DELTA='0x200000' if case == 'rebased-pie' else '0')
            run(['bash', ROOT / 'src/test/integration/headless-symbol-export.sh', ghidra,
                native / 'libdwarf.so.2.3.2', native / 'libdwarfp.so.2.3.2', args.target],
                env, directory / 'export.log')
            gdb = 'shared-object-gdb.sh' if role == 'shared' else 'qemu-gdb-symbols.sh'
            run(['bash', ROOT / 'src/test/integration' / gdb, args.target], env, directory / 'gdb.log')
            require(digest(original) == original_hash, 'original changed')
            state = {'artifactSha256': digest(artifact), 'sourceSha256': digest(source),
                'fileBytes': artifact.stat().st_size, 'sections': sections(artifact)}
            shutil.copy2(artifact, directory / 'artifact.dbg')
            shutil.copy2(source, directory / 'artifact.dbg.c')
            (directory / 'receipt.json').write_text(json.dumps(state, indent=4) + '\n')
            states.append(state)
        plain, compressed, repeat = states
        require(plain['sections'].keys() == compressed['sections'].keys(), 'section set changed')
        require(not any(s['compressed'] for s in plain['sections'].values()), 'default is compressed')
        require(any(s['compressed'] for s in compressed['sections'].values()), 'opt-in did not compress')
        require(compressed['fileBytes'] < plain['fileBytes'], 'fixture sidecar did not shrink')
        for name, value in plain['sections'].items():
            require(value['plainSha256'] == compressed['sections'][name]['plainSha256'],
                'decompressed DWARF changed: ' + name)
        require(plain['sourceSha256'] == compressed['sourceSha256'], 'source changed')
        require(compressed == repeat, 'compressed export is not deterministic')
        receipt['cases'][case] = {'status': 'PASS', 'originalSha256': original_hash,
            'plain': plain, 'zlib': compressed}
        (work / 'receipt.json').write_text(json.dumps(receipt, indent=4) + '\n')
        print(f'compression-export {args.target}/{case}=PASS', flush=True)
    receipt['status'] = 'PASS'
    (work / 'receipt.json').write_text(json.dumps(receipt, indent=4) + '\n')


if __name__ == '__main__':
    main()

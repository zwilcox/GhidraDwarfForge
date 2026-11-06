#!/usr/bin/env python3
"""Compiler/loader oracle for COPY size, descriptor width and sectionless parity."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def run(command, log, env=None):
    command = list(map(str, command))
    log.with_suffix(log.suffix + '.command.json').write_text(json.dumps(command, indent=4) + '\n')
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
        env={**os.environ, 'LC_ALL': 'C', **(env or {})})
    log.write_bytes(result.stdout)
    log.with_suffix(log.suffix + '.stderr').write_bytes(result.stderr)
    assert result.returncode == 0, (command, result.returncode, result.stderr.decode(errors='replace'))
    assert not result.stderr, (command, result.stderr)
    return result.stdout.decode()


def original(data):
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', data, 54)
    segments = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(phcount)]

    def locate(address, size):
        load, = [s for s in segments if s[0] == 1 and s[3] <= address and address + size <= s[3] + s[5]]
        return load[2] + address - load[3]

    dynamic, = [s for s in segments if s[0] == 2]
    tags = {}
    for at in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from('<qQ', data, at)
        if not tag:
            break
        if tag != 1:
            assert tag not in tags
            tags[tag] = value
    # The fixture deliberately includes SysV hashes, giving sectionless inputs
    # an independently bounded count even when GNU buckets have no definitions.
    count = struct.unpack_from('<I', data, locate(tags[4], 8) + 4)[0]
    assert tags[11] == 24
    start = locate(tags[6], count * 24)
    symbols = [struct.unpack_from('<IBBHQQ', data, start + 24 * i) for i in range(count)]
    return segments, tags, symbols


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--classes', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--java', default='java')
    parser.add_argument('--lld', default='ld.lld-18', help='AArch64 PIE COPY linker; GNU ld rejects the direct reference')
    parser.add_argument('--target', choices=['x86_64', 'aarch64'], required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    cc = 'gcc' if args.target == 'x86_64' else 'aarch64-linux-gnu-gcc'
    dialect = '-mtls-dialect=gnu2' if args.target == 'x86_64' else '-mtls-dialect=desc'
    copy_type, descriptor_type = (5, 36) if args.target == 'x86_64' else (1024, 1031)
    for tool in (cc, args.java, 'readelf'):
        run([tool, '--version'], output / (Path(tool).name + '-version.log'))
    common = [cc, '-O0', '-g', '-Wl,--hash-style=both']
    if args.target == 'aarch64':
        linker = Path(shutil.which(args.lld) or args.lld).resolve()
        assert linker.is_file(), linker
        run([args.lld, '--version'], output / 'lld-version.log')
        run([shutil.which('qemu-aarch64') or 'qemu-aarch64-static', '--version'], output / 'qemu-version.log')
        common += ['-fuse-ld=lld', '-B' + str(linker.parent) + '/']
    fixtures = ROOT / 'src/test/fixtures'
    provider = output / 'libeffects-provider.so'
    consumer = output / 'libeffects-consumer.so'
    run([*common, '-shared', '-fPIC', fixtures / 'relocation-effects-provider.c', '-o', provider], output / 'provider-build.log')
    run([*common, '-shared', '-fPIC', dialect, fixtures / 'relocation-effects-consumer.c',
        '-L' + str(output), '-leffects-provider', '-o', consumer], output / 'consumer-build.log')
    records = []
    for mode in ['exec', 'pie']:
        binary = output / mode
        # AArch64 -fPIE normally uses the GOT for extern data; PC-relative
        # -fno-pic code linked as PIE deliberately exercises the COPY case.
        run([*common, '-fPIE' if mode == 'pie' and args.target == 'x86_64' else '-fno-pic', '-no-pie' if mode == 'exec' else '-pie',
            fixtures / 'relocation-effects-main.c', '-L' + str(output), '-leffects-consumer', '-leffects-provider',
            '-o', binary], output / (mode + '-build.log'))
        command = [binary] if args.target == 'x86_64' else [shutil.which('qemu-aarch64') or 'qemu-aarch64-static', '-L', '/usr/aarch64-linux-gnu', binary]
        run(command, output / (mode + '-runtime.log'), {'LD_LIBRARY_PATH': str(output)})
    for name, kind in [('exec', 'copy'), ('pie', 'copy'), (consumer.name, 'descriptor')]:
        binary = output / name
        data = binary.read_bytes()
        segments, tags, symbols = original(data)
        oracle = run(['readelf', '-Wr', binary], output / (name + '-readelf.log'))
        typ = copy_type if kind == 'copy' else descriptor_type
        pattern = r'^\s*([0-9a-f]+)\s+([0-9a-f]+)\s+R_\S+_' + ('COPY' if kind == 'copy' else 'TLSDESC') + r'\s'
        matches = re.findall(pattern, oracle, re.M)
        assert len(matches) == 1, (name, matches, oracle)
        address, info = (int(value, 16) for value in matches[0])
        assert info & 0xffffffff == typ
        symbol = info >> 32
        size = symbols[symbol][5] if kind == 'copy' else 16
        assert size == (37 if kind == 'copy' else 16)
        if kind == 'copy':
            assert symbols[symbol][4] == address and symbols[symbol][3] > 0
        before = hashlib.sha256(data).hexdigest()
        variants = [binary, output / (name + '-sectionless')]
        stripped = bytearray(data)
        struct.pack_into('<Q', stripped, 40, 0)
        struct.pack_into('<HH', stripped, 60, 0, 0)
        variants[1].write_bytes(stripped)
        results = []
        for path in variants:
            text = run([args.java, '-cp', args.classes, 'ghidradwarfforge.elf.ElfRelocationEffectsSmoke', path],
                output / (path.name + '-effects.log'))
            writes = [line.split() for line in text.splitlines()]
            actual, = [row for row in writes if int(row[3]) == typ]
            # Independently locate the implicit destinations: reserved GOT words
            # and the writable value field of DT_DEBUG (not its pointed-to value).
            expected_implicit = {}
            if 3 in tags:
                expected_implicit['loader-tag-3'] = (tags[3] + 8, 16)
            if 0x6ffffef7 in tags:
                expected_implicit['loader-tag-6ffffef7'] = (tags[0x6ffffef7], 8)
            if 21 in tags:
                dynamic, = [segment for segment in segments if segment[0] == 2]
                entries = range(dynamic[2], dynamic[2] + dynamic[5], 16)
                slot, = [at for at in entries if struct.unpack_from('<q', data, at)[0] == 21]
                expected_implicit['loader-DT_DEBUG'] = (dynamic[3] + slot - dynamic[2] + 8, 8)
            observed_implicit = {row[1]: (int(row[5]), int(row[6])) for row in writes if int(row[3]) == -2}
            assert observed_implicit == expected_implicit, (observed_implicit, expected_implicit)
            assert int(actual[4]) == symbol and int(actual[5]) == address and int(actual[6]) == size, actual
            load, = [s for s in segments if s[0] == 1 and s[3] <= address and address + size <= s[3] + s[6]]
            file_bytes = min(size, max(0, load[5] - (address - load[3])))
            assert int(actual[8]) == file_bytes
            assert int(actual[7]) == (-1 if not file_bytes else load[2] + address - load[3])
            results.append(text)
        assert results[0] == results[1]
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
        records.append({'file': name, 'sha256': before, 'kind': kind, 'address': address, 'size': size,
            'namedSectionlessEqual': True})
    (output / 'summary.json').write_text(json.dumps({'target': args.target, 'runtimeCases': 2, 'artifacts': records}, indent=4) + '\n')
    print(f'relocation-effects-{args.target}=PASS')


if __name__ == '__main__':
    main()

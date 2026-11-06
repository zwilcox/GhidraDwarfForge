#!/usr/bin/env python3
"""Compare gABI runtime table inventories with compiler ELF bytes and GNU readelf."""
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


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, log):
    command = list(map(str, command))
    log.with_suffix(log.suffix + '.command.json').write_text(json.dumps(command, indent=4) + '\n')
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180,
        env={**os.environ, 'LC_ALL': 'C'})
    log.write_bytes(result.stdout)
    log.with_suffix(log.suffix + '.stderr').write_bytes(result.stderr)
    assert result.returncode == 0, (command, result.stderr.decode(errors='replace'))
    assert not result.stderr, (command, result.stderr)
    return result.stdout.decode()


def independent(data):
    # Native fixtures are ELF64; the Java component suite separately covers both
    # classes and byte orders, without claiming another runtime ABI profile.
    assert data[:6] == b'\x7fELF\x02\x01'
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phcount = struct.unpack_from('<HH', data, 54)
    segments = [struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize) for i in range(phcount)]

    def locate(address, size):
        loads = [s for s in segments if s[0] == 1 and s[3] <= address and address + size <= s[3] + s[5]]
        load, = loads
        return load[2] + address - load[3]

    dynamic, = [s for s in segments if s[0] == 2]
    tags = {}
    for at in range(dynamic[2], dynamic[2] + dynamic[5], 16):
        tag, value = struct.unpack_from('<qQ', data, at)
        if tag == 0:
            break
        if tag in (2, 7, 8, 9, 17, 18, 19, 20, 23, 35, 36, 37):
            assert tag not in tags
            tags[tag] = value
    tables = []
    for role, fmt, pointer, length, entry in [('DT_RELR', 'RELR', 36, 35, 37),
            ('DT_REL', 'REL', 17, 18, 19), ('DT_RELA', 'RELA', 7, 8, 9),
            ('DT_JMPREL', 'RELA' if tags.get(20) == 7 else 'REL', 23, 2, None)]:
        if pointer not in tags:
            continue
        size = 8 if fmt == 'RELR' else 24 if fmt == 'RELA' else 16
        assert entry is None or tags[entry] == size
        start = locate(tags[pointer], tags[length]) if tags[length] else 0
        raw = data[start:start + tags[length]]
        rows = []
        cursor = None
        for at in range(0, len(raw), size):
            values = struct.unpack_from('<' + ('Q' if fmt == 'RELR' else 'QQq' if fmt == 'RELA' else 'QQ'), raw, at)
            if fmt != 'RELR':
                rows.append([start + at, values[0], values[1], values[2] if fmt == 'RELA' else None])
            elif values[0] & 1:
                assert cursor is not None
                bits = values[0] >> 1
                for slot in range(63):
                    if bits & (1 << slot):
                        rows.append([start + at, cursor + slot * 8, None, None])
                cursor += 63 * 8
            else:
                cursor = values[0] + 8
                rows.append([start + at, values[0], None, None])
        tables.append({'role': role, 'format': fmt, 'address': tags[pointer], 'offset': start,
            'size': len(raw), 'entrySize': size, 'sha256': digest(raw), 'rows': rows})
    return tables


def parse_java(text):
    tables = []
    for line in text.splitlines():
        fields = line.split()
        if fields[0] == 'TABLE':
            _, role, fmt, address, offset, size, width, sha = fields
            tables.append({'role': role, 'format': fmt, 'address': int(address), 'offset': int(offset),
                'size': int(size), 'entrySize': int(width), 'sha256': sha, 'rows': []})
        else:
            assert fields[0] == 'ROW'
            _, at, address, info, addend = fields
            tables[-1]['rows'].append([int(at), int(address), None if info == 'none' else int(info),
                None if addend == 'null' else int(addend)])
    return tables


def gnu_rows(text):
    result = {}
    role = None
    for line in text.splitlines():
        header = re.match(r"'(REL|RELA|RELR|PLT)' relocation section", line)
        if header:
            role = {'PLT': 'DT_JMPREL'}.get(header[1], 'DT_' + header[1])
            assert role not in result
            result[role] = []
        elif re.fullmatch(r'[0-9a-f]{16}', line):
            assert role == 'DT_RELR'
            result[role].append((int(line, 16), None))
        elif match := re.match(r'^([0-9a-f]{16})\s+([0-9a-f]{16})\s+R_', line):
            assert role in ('DT_REL', 'DT_RELA', 'DT_JMPREL')
            result[role].append((int(match[1], 16), int(match[2], 16)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('classes', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--java', default='java')
    parser.add_argument('--target', choices=['x86_64', 'aarch64'])
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--lld', default='ld.lld-18', help='LLD for AArch64 RELR (GNU ld 2.42 does not implement it)')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / 'src/test/fixtures/runtime-relocations.c'
    original_source = source.read_bytes()
    for tool in ('readelf', 'llvm-dwarfdump', args.java):
        run([tool, '--version'], args.output / (Path(tool).name + '-version.log'))
    classpath = os.pathsep.join(str((args.classes / p).resolve()) for p in ('main', 'test'))
    outcomes = []
    for target in ([args.target] if args.target else ['x86_64', 'aarch64']):
        cc = 'gcc' if target == 'x86_64' else 'aarch64-linux-gnu-gcc'
        run([cc, '--version'], args.output / (target + '-compiler-version.log'))
        if target == 'aarch64':
            run([args.lld, '--version'], args.output / 'lld-version.log')
        for kind in ('exec', 'pie', 'shared'):
            for packing in ('plain', 'relr'):
                case = args.output / (target + '-' + kind + '-' + packing)
                case.mkdir()
                original, rebuild = case / 'original', case / 'rebuild'
                flags = {'exec': ['-fno-pie', '-no-pie'], 'pie': ['-fPIE', '-pie'], 'shared': ['-fPIC', '-shared']}[kind]
                if target == 'aarch64' and packing == 'relr':
                    linker = shutil.which(args.lld)
                    assert linker is not None, 'AArch64 RELR requires the explicit LLD tool; do not count an ignored packing flag'
                    directory = Path(linker).resolve().parent
                    assert (directory / 'ld.lld').exists()
                    flags += ['-fuse-ld=lld', '-B' + str(directory) + '/']
                command = [cc, '-g', '-gdwarf-5', '-O0', '-Wl,--emit-relocs', *flags,
                    *(['-Wl,-z,pack-relative-relocs'] if packing == 'relr' else []), source]
                for filename in (original, rebuild):
                    run(command + ['-o', filename], case / (filename.name + '-compile.log'))
                before = original.read_bytes()
                assert before == rebuild.read_bytes()
                expected = independent(before)
                gnu = gnu_rows(run(['readelf', '-rW', '--use-dynamic', original], case / 'named-gnu.log'))
                assert gnu == {t['role']: [(r[1], r[2]) for r in t['rows']] for t in expected if t['size']}
                assert any(t['role'] == 'DT_JMPREL' and t['rows'] for t in expected)
                if kind == 'pie' and packing == 'relr':
                    assert sum(len(t['rows']) for t in expected if t['format'] == 'RELR') >= 80
                run(['readelf', '-hSWn', original], case / 'identity.log')
                assert 'No errors.' in run(['llvm-dwarfdump', '--verify', original], case / 'llvm.log')
                run(['python3', ROOT / 'src/test/integration/check-dwarfdump.py', original,
                    case / 'strict.log', '--tool', args.dwarfdump, '--original', rebuild], case / 'strict-driver.log')
                variants = []
                for mode in ('named', 'sectionless'):
                    binary = original
                    if mode == 'sectionless':
                        binary = case / mode
                        modified = bytearray(before)
                        modified[40:48] = bytes(8)
                        modified[58:64] = bytes(6)
                        binary.write_bytes(modified)
                    binary_before = binary.read_bytes()
                    observed = parse_java(run([args.java, '-cp', classpath,
                        'ghidradwarfforge.elf.ElfRuntimeRelocationsSmoke', binary], case / (mode + '-java.log')))
                    assert observed == expected
                    # GNU readelf on this host cannot resolve dynamic symbol
                    # indices in the GNU-hash-only sectionless copy. Compare
                    # both readers to the unmodified GNU oracle, without
                    # suppressing its errors or changing dynamic metadata.
                    assert independent(binary_before) == expected
                    assert binary.read_bytes() == binary_before
                    variants.append({'mode': mode, 'sha256': digest(binary_before), 'tableCount': len(observed),
                        'recordCount': sum(len(t['rows']) for t in observed)})
                assert original.read_bytes() == before
                outcomes.append({'target': target, 'kind': kind, 'packing': packing,
                    'tables': expected, 'variants': variants,
                    'strict': json.loads((case / 'strict.log.check.json').read_text())})
    assert source.read_bytes() == original_source
    result = {'status': 'PASS_RUNTIME_RELOCATION_INVENTORY', 'cases': outcomes,
        'sourceSha256': digest(original_source), 'sourceAndOriginalsUnchanged': True,
        'limit': 'Read-only gABI inventory, not relocation effect qualification, recovered unwind behavior or production synthesis.'}
    (args.output / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('runtime-relocation-inventory=PASS cases=' + str(len(outcomes)) + ' variants=' + str(len(outcomes) * 2))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Packaging experiment only: compiler DWARF in a newly constructed non-loadable ELF32.

This is not the production firmware exporter or a claim of recovered DWARF. The
compiler input supplies oracle DWARF/symbols and allocation extents solely to test
GDB's container behavior while QEMU boots the independently extracted raw bytes.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def container(reference):
    original = reference.read_bytes()
    assert original[:7] == b'\x7fELF\x01\x01\x01'
    header = struct.unpack_from('<16sHHIIIIIHHHHHH', original)
    assert header[2] == 40 and header[11] == 40 and 0 < header[12] < 0xff00
    sections = [list(struct.unpack_from('<10I', original, header[6] + i * 40))
        for i in range(header[12])]
    strings = sections[header[13]]
    old_names = original[strings[4]:strings[4] + strings[5]]
    names = bytearray(b'\0')
    body = bytearray(52)
    out = [[0] * 10]
    allocations = []
    for index, section in enumerate(sections[1:], 1):
        name = old_names[section[0]:].split(b'\0', 1)[0].decode('ascii')
        sh_type, flags, address, offset, size, link, info, alignment, entsize = section[1:]
        if flags & 2:
            # No firmware payload, original build-ID note, entry point or load segment.
            name = '.forge.region.' + str(index)
            allocations.append({'name': name, 'address': address, 'size': size, 'flags': flags & 7})
            sh_type, flags, offset, link, info, alignment, entsize = 8, flags & 7, 0, 0, 0, 1, 0
        elif name == '.shstrtab':
            sh_type, flags, address, offset, size, link, info, alignment, entsize = 3, 0, 0, 0, 0, 0, 0, 1, 0
        elif name.startswith('.debug_') or name in ('.ARM.attributes', '.symtab', '.strtab'):
            body.extend(b'\0' * (-len(body) % max(1, alignment)))
            payload = original[offset:offset + size]
            offset = len(body)
            body.extend(payload)
        else:
            name = '.experiment.omitted.' + str(index)
            sh_type, flags, address, offset, size, link, info, alignment, entsize = 8, 0, 0, 0, 0, 0, 0, 1, 0
        name_index = len(names)
        names.extend(name.encode('ascii') + b'\0')
        out.append([name_index, sh_type, flags, address, offset, size, link, info, alignment, entsize])
    out[header[13]][4:6] = [len(body), len(names)]
    body.extend(names)
    body.extend(b'\0' * (-len(body) % 4))
    table_offset = len(body)
    for section in out:
        body.extend(struct.pack('<10I', *section))
    # Explicitly selected Cortex-M3/base-AAPCS descriptor, no original ELF identity.
    ident = b'\x7fELF\x01\x01\x01' + bytes(9)
    struct.pack_into('<16sHHIIIIIHHHHHH', body, 0,
        ident, 2, 40, 1, 0, 0, table_offset, 0x05000000, 52, 0, 0, 40, len(out), header[13])
    return bytes(body), allocations


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--objcopy', default='arm-none-eabi-objcopy')
    args = parser.parse_args()
    case = args.case.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    reference = case / 'reference.elf'
    before = digest(reference)
    symbols, raw = output / 'synthetic.dbg', output / 'firmware.bin'
    payload, allocations = container(reference)
    symbols.write_bytes(payload)
    commands = []

    def run(label, command):
        commands.append(command)
        with (output / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)

    run('raw', [args.objcopy, '-O', 'binary', str(reference), str(raw)])
    raw_hash = digest(raw)
    run('readelf', ['readelf', '-hSWn', str(symbols)])
    run('readelf-dwarf', ['readelf', '--debug-dump=info,abbrev,aranges,decodedline', str(symbols)])
    run('llvm', ['llvm-dwarfdump', '--verify', str(symbols)])
    run('dwarfdump', ['dwarfdump', str(symbols)])
    assert 'Build ID:' not in (output / 'readelf.log').read_text()
    runtime = runpy.run_path(str(Path(__file__).resolve().parents[2] / 'integration/cortex-m-runtime.py'))
    observed = runtime['debugger'](case, symbols, output, 'compiler', raw_input=raw)
    assert digest(reference) == before and digest(raw) == raw_hash
    (output / 'result.json').write_text(json.dumps({
        'status': 'PASS', 'scope': 'compiler-DWARF packaging experiment; not production raw export',
        'referenceSha256': before, 'rawSha256': raw_hash, 'sidecarSha256': digest(symbols),
        'allocations': allocations, 'commands': commands, 'runtime': observed,
    }, indent=4) + '\n')
    print('firmware-container-experiment=PASS ' + str(output))


if __name__ == '__main__':
    main()

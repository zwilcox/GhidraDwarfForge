#!/usr/bin/env python3
"""ELF section bounds, including low PIE addresses, must govern checker limits."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent


def fixture(wide, order, text_address, dwarf_address):
    width, word = (8, 'Q') if wide else (4, 'I')
    pack = lambda fmt, *values: struct.pack(order + fmt, *values)
    # CU, function, formal and base type. The CU/function agree with each
    # other even in corrupt cases: only the independent ELF bounds differ.
    abbrev = bytes([1, 0x11, 1, 3, 8, 0x25, 8, 0x13, 5, 0x11, 1, 0x12, 6, 0x10, 0x17, 0, 0,
        2, 0x2e, 1, 3, 8, 0x11, 1, 0x12, 6, 0, 0,
        3, 5, 0, 3, 8, 0x49, 0x13, 2, 0x17, 0, 0,
        4, 0x24, 0, 3, 8, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0, 0])
    body = pack('HBBI', 5, 1, width, 0)
    body += b'\x01bounds.c\0Forge bounds fixture\0' + pack('H' + word + 'II', 2, dwarf_address, 4, 0)
    body += b'\x02function\0' + pack(word + 'I', dwarf_address, 4)
    body += b'\x03argument\0'
    reference = len(body)
    body += bytes(4) + pack('I', 12) + b'\0'
    dtype = len(body) + 4
    body += b'\x04int\0\x04\x05\0'
    body = bytearray(body)
    struct.pack_into(order + 'I', body, reference, dtype)
    info = pack('I', len(body)) + body
    loc = pack('HBBI', 5, width, 0, 0) + b'\x07' + pack(word * 2, dwarf_address, dwarf_address + 4)
    loc += bytes([1, 0x50, 0])
    loc = pack('I', len(loc)) + loc
    # A standard DWARF4 line table used by the DWARF5 CU. Its one-past
    # sequence end must remain valid; no synthetic instruction is executed.
    prologue = bytes([1, 1, 1, 251, 14, 13, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0])
    prologue += b'bounds.c\0' + bytes(4)
    program = bytes([0, width + 1, 2]) + pack(word, dwarf_address) + bytes([1, 2, 4, 0, 1, 1])
    line = pack('HI', 4, len(prologue)) + prologue + program
    line = pack('I', len(line)) + line
    sections = [('.text', bytes(4), 1, 6, text_address),
        ('.empty-low', b'', 1, 6, 0), ('.empty-high', b'', 1, 6, 0xf0000000),
        ('.nonalloc', bytes(4), 1, 0, 1),
        ('.debug_abbrev', abbrev, 1, 0, 0), ('.debug_info', info, 1, 0, 0),
        ('.debug_loclists', loc, 1, 0, 0), ('.debug_line', line, 1, 0, 0)]
    names = b'\0' + b''.join(name.encode() + b'\0' for name, *_ in sections) + b'.shstrtab\0'
    sections.append(('.shstrtab', names, 3, 0, 0))
    header_size, section_size = (64, 64) if wide else (52, 40)
    data = bytearray(header_size)
    rows = [(0,) * 10]
    for name, payload, kind, flags, address in sections:
        rows.append((names.index(name.encode()), kind, flags, address, len(data), len(payload), 0, 0, 1, 0))
        data.extend(payload)
    data.extend(bytes(-len(data) % 8))
    shoff = len(data)
    for row in rows:
        data.extend(pack('II4QII2Q' if wide else '10I', *row))
    data[:16] = b'\x7fELF' + bytes([2 if wide else 1, 1 if order == '<' else 2, 1]) + bytes(9)
    struct.pack_into(order + 'HHI', data, 16, 3, 62 if wide else 8, 1)
    struct.pack_into(order + word * 3 + 'I6H', data, 24, text_address, 0, shoff, 0,
        header_size, 0, 0, section_size, len(rows), len(rows) - 1)
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', type=Path)
    parser.add_argument('--previous-tool', type=Path)
    args = parser.parse_args()
    root = source.parents[2] / 'build/test-results/dwarfdump-elf-bounds'
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    rows = []
    for wide in (False, True):
        for order in ('<', '>'):
            for base in (0, 0x100, 0x1fc, 0x200, 0x1000):
                for mode, address in [('valid', base), ('after', base + 8)] + ([('before', base - 4)] if base else []):
                    label = f"elf{64 if wide else 32}-{'le' if order == '<' else 'be'}-{base:x}-{mode}"
                    data = fixture(wide, order, base, address)
                    path = work / (label + '.elf')
                    path.write_bytes(data)
                    digest = hashlib.sha256(data).hexdigest()
                    if mode == 'valid':
                        for tool, command in [('gnu', ['readelf', '-hSW', '--debug-dump=info,abbrev,loc,decodedline', path]),
                                ('llvm', ['llvm-dwarfdump', '--verify', path])]:
                            result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=30)
                            (work / (label + '.' + tool)).write_text(result.stdout + result.stderr)
                            assert result.returncode == 0 and not result.stderr, (label, tool, result.stderr)
                            assert 'warning:' not in result.stdout.lower() and 'error:' not in result.stdout.lower()
                    tools = [(False, args.tool)]
                    if args.previous_tool and (mode == 'valid' and 0 < base < 512 or base == 0x1000 and mode != 'valid'):
                        tools.append((True, args.previous_tool))
                    for previous, tool in tools:
                        log = work / (label + ('-previous' if previous else '') + '.log')
                        result = subprocess.run([sys.executable, source / 'check-dwarfdump.py', path, log, '--tool', tool],
                            capture_output=True, text=True, timeout=30)
                        Path(str(log) + '.runner').write_text(result.stdout + result.stderr)
                        # The old heuristic also enlarges both ends of a high
                        # image's allowed interval; retain those false passes.
                        positive = mode == 'valid' if not previous else mode != 'valid'
                        assert (result.returncode == 0) == positive, (label, previous, result.stdout, result.stderr)
                        metadata = json.loads(Path(str(log) + '.check.json').read_text())
                        assert metadata['status'] == ('PASS' if positive else 'FAILED')
                        if not positive:
                            assert 'outside a valid .text range' in log.read_text(), label
                        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
                        rows.append({'fixture': label, 'previous': previous, 'accepted': positive, 'sha256': digest})
    (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'cases': rows}, indent=4) + '\n')
    print('dwarfdump-elf-bounds=PASS cases=' + str(len(rows)) + ' ' + str(work))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Location-view offsets must not be traversed as DIEs; actual DIE references stay checked."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('elf_fixture', source / 'dwarfdump-extended-programs.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def fixture(wide, order, version, bad_type=False, bad_view_form=False):
    data = fixtures.fixture(wide, order)
    word = 'Q' if wide else 'I'
    width = 8 if wide else 4
    pack = lambda fmt, *values: struct.pack(order + fmt, *values)
    fmt = order + ('II4QII2Q' if wide else '10I')
    size = struct.calcsize(fmt)
    shoff = struct.unpack_from(order + word, data, 40 if wide else 32)[0]
    rows = [list(struct.unpack_from(fmt, data, shoff + index * size)) for index in range(5)]
    abbrev = bytes([1, 0x11, 1, 3, 8, 0x25, 8, 0x13, 5, 0x11, 1, 0x12, 6, 0, 0,
        2, 0x24, 0, 3, 8, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0,
        3, 0x34, 0, 3, 8, 0x49, 0x13, 2, 0x17, 0xb7, 0x42, 0x17, 0, 0, 0])
    if bad_view_form:
        abbrev = abbrev.replace(bytes([0xb7, 0x42, 0x17]), bytes([0xb7, 0x42, 0x13]))
    body = pack('HBBI', 5, 1, width, 0) if version == 5 else pack('HIB', 4, 0, width)
    body += b'\x01locviews-long.c\0Forge validation fixture\0' + pack('H' + word + 'I', 2, 0x1000, 4)
    type_offset = len(body) + 4
    body += b'\x02int\0\x04\x05'
    loc = bytearray(pack('HBBI', 5, width, 0, 0)) if version == 5 else bytearray()
    for index in range(2):
        views = len(loc) + (4 if version == 5 else 0)
        loc += bytes(2)
        location = len(loc) + (4 if version == 5 else 0)
        if version == 5:
            loc += bytes([8]) + pack(word, 0x1000) + bytes([4, 1, 0x50, 0])
        else:
            loc += pack(word * 2 + 'H', 0, 4, 1) + bytes([0x50]) + bytes(width * 2)
        body += b'\x03value' + str(index).encode() + b'\0' + pack('III',
            20 if bad_type else type_offset, location, views)
    body += b'\0'
    if version == 5:
        loc = pack('I', len(loc)) + loc
    loc_name = b'.debug_loclists' if version == 5 else b'.debug_loc'
    info = pack('I', len(body)) + body
    names = data[rows[4][4]:rows[4][4] + rows[4][5]]
    name_index = len(names)
    names += loc_name + b'\0'
    for index, payload in ((2, abbrev), (3, info), (4, names)):
        rows[index][4:6] = [len(data), len(payload)]
        data.extend(payload)
    rows.append([name_index, 1, 0, 0, len(data), len(loc), 0, 0, 1, 0])
    data.extend(loc)
    data.extend(bytes(-len(data) % 8))
    struct.pack_into(order + word, data, 40 if wide else 32, len(data))
    struct.pack_into(order + 'H', data, 60 if wide else 48, len(rows))
    for row in rows:
        data.extend(struct.pack(fmt, *row))
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', type=Path)
    parser.add_argument('--previous-tool', type=Path)
    args = parser.parse_args()
    root = source.parents[2] / 'build/test-results/dwarfdump-locviews'
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    rows = []
    for wide in (False, True):
        for order in ('<', '>'):
            for version in (4, 5):
                for mode in ('valid-views', 'bad-type', 'bad-view-reference-form'):
                    bad_type = mode == 'bad-type'
                    label = f"elf{64 if wide else 32}-{'le' if order == '<' else 'be'}-dwarf{version}-{mode}"
                    path = work / (label + '.elf')
                    data = fixture(wide, order, version, bad_type, mode == 'bad-view-reference-form')
                    path.write_bytes(data)
                    digest = hashlib.sha256(data).hexdigest()
                    if mode == 'valid-views':
                        for name, command in [('gnu', ['readelf', '-hSW', '--debug-dump=info,abbrev,loc', path]),
                                ('llvm', ['llvm-dwarfdump', '--verify', path])]:
                            verified = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=30)
                            (work / (label + '.' + name + '.log')).write_text(verified.stdout + verified.stderr)
                            assert verified.returncode == 0 and not verified.stderr.strip(), (label, name, verified.stderr)
                            assert 'warning:' not in verified.stdout.lower() and 'error:' not in verified.stdout.lower()
                    for previous, tool in [(False, args.tool)] + ([(True, args.previous_tool)] if args.previous_tool else []):
                        log = work / (label + ('-previous' if previous else '') + '.log')
                        run = subprocess.run([sys.executable, source / 'check-dwarfdump.py', path, log, '--tool', tool],
                            capture_output=True, text=True, timeout=30)
                        Path(str(log) + '.runner').write_text(run.stdout + run.stderr)
                        expected = not previous and mode == 'valid-views'
                        assert (run.returncode == 0) == expected, (label, previous, run.stdout, run.stderr)
                        metadata = json.loads(Path(str(log) + '.check.json').read_text())
                        assert metadata['status'] == ('PASS' if expected else 'FAILED')
                        if not expected:
                            assert 'DW_DLE_' in log.read_text() or 'DWARF CHECK:' in log.read_text()
                        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
                        rows.append({'fixture': label, 'previous': previous, 'accepted': expected})
    (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'cases': rows}, indent=4) + '\n')
    print('dwarfdump-locviews=PASS cases=' + str(len(rows)) + ' ' + str(work))


if __name__ == '__main__':
    main()

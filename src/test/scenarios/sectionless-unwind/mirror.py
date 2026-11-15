#!/usr/bin/env python3
"""Trusted-fixture experiment: expose existing unwind bytes in a new sidecar copy."""
import argparse
import json
from pathlib import Path
import struct
from discover import discover


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('sidecar', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    original = args.original.read_bytes()
    frame = discover(original)
    assert frame is not None, 'no proven frame inventory'
    data = bytearray(args.sidecar.read_bytes())
    assert data[:16] == original[:16]
    wide, order = data[4] == 2, '<' if data[5] == 1 else '>'
    header = struct.unpack_from(order + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), data, 16)
    assert header[4] == header[8] == header[9] == 0 and 0 < header[11] < 0xff00
    assert data[header[7]:len(original)] == original[header[7]:]
    fmt, width = ('IIQQQQIIQQ', 64) if wide else ('IIIIIIIIII', 40)
    sections = [list(struct.unpack_from(order + fmt, data, header[5] + i * width)) for i in range(header[11])]
    strings = sections[header[12]]
    names = data[strings[4]:strings[4] + strings[5]]
    assert all(names[s[0]:].split(b'\0', 1)[0] != b'.eh_frame' for s in sections)
    index = len(names)
    names += b'.eh_frame\0'
    strings[4], strings[5] = len(data), len(names)
    data += names
    sections.append([index, 1, 2, frame['address'], frame['offset'], frame['size'], 0, 0, 1, 0])
    while len(data) % (8 if wide else 4):
        data.append(0)
    table = len(data)
    for section in sections:
        data += struct.pack(order + fmt, *section)
    struct.pack_into(order + ('Q' if wide else 'I'), data, 40 if wide else 32, table)
    struct.pack_into(order + 'H', data, 60 if wide else 48, len(sections))
    with args.output.open('xb') as stream:
        stream.write(data)
    print(json.dumps(frame, sort_keys=True))


if __name__ == '__main__':
    main()

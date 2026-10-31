#!/usr/bin/env python3
"""Exact ELF symbol extents and original inventory for the x86-64 split-body oracle."""
import hashlib
import json
from pathlib import Path
import struct
import sys


def elf(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    assert header[0] in (2, 3) and header[1] == 62 and header[10] == 64
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, header[5] + index * 64) for index in range(header[11])]
    names = rows[header[12]]
    names = data[names[4]:names[4] + names[5]]
    return header, {names[row[0]:].split(b'\0', 1)[0].decode(): (index, row,
        b'' if row[1] == 8 else data[row[4]:row[4] + row[5]]) for index, row in enumerate(rows)}


original_path, sidecar_path, labels_path = map(Path, sys.argv[1:])
labels = {name: int(value, 16) for name, value in (line.split() for line in labels_path.read_text().splitlines())}
a_header, original = elf(original_path)
b_header, emitted = elf(sidecar_path)
assert a_header[:4] == b_header[:4] and a_header[6] == b_header[6]
assert b_header[4] == b_header[8] == b_header[9] == 0
assert '.symtab' not in original
_, table, raw = emitted['.symtab']
_, dynamic, old_raw = original['.dynsym']
_, old_names_row, old_names = next(v for v in original.values() if v[0] == dynamic[6])
_, names_row, names = next(v for v in emitted.values() if v[0] == table[6])
assert table[1] == 2 and table[2:4] == (0, 0) and table[9] == dynamic[9] == 24
assert table[7] == dynamic[7] + 2
assert raw[:dynamic[7] * 24] + raw[table[7] * 24:] == old_raw
assert names.startswith(old_names)
assert emitted['.dynsym'][2] == old_raw
assert emitted['.dynstr'][2] == old_names
expected = {
    'secondary_below': (labels['below_entry'], labels['below_entry_end'] - labels['below_entry']),
    'secondary_middle': (labels['middle_entry'], labels['middle_end'] - labels['middle_entry'])}
observed = {}
for at in range(dynamic[7] * 24, table[7] * 24, 24):
    offset, info, other, index, address, size = struct.unpack_from('<IBBHQQ', raw, at)
    name = names[offset:].split(b'\0', 1)[0].decode()
    assert name in expected and name not in observed
    assert info == 2 and other == 0 and index == original['.text'][0]
    assert (address, size) == expected[name]
    observed[name] = {'address': address, 'size': size, 'section': index}
assert observed.keys() == expected.keys()
print(json.dumps({'status': 'PASS', 'symbols': observed,
    'inputSha256': hashlib.sha256(original_path.read_bytes()).hexdigest(),
    'sidecarSha256': hashlib.sha256(sidecar_path.read_bytes()).hexdigest()}, indent=4))

#!/usr/bin/env python3
"""Small trusted-fixture experiment; buffers input, never used by production."""
from pathlib import Path
import struct


def discover(data):
    assert data[:4] == b'\x7fELF' and data[4] in (1, 2) and data[5] in (1, 2)
    wide, order = data[4] == 2, '<' if data[5] == 1 else '>'
    header = struct.unpack_from(order + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), data, 16)
    assert header[5] == header[11] == header[12] == 0, 'discovery must not use a section table'
    loads, candidates = [], []
    for i in range(header[9]):
        record = struct.unpack_from(order + ('IIQQQQQQ' if wide else 'IIIIIIII'), data, header[4] + i * header[8])
        if wide:
            kind, flags, offset, address, _, size, memory, align = record
        else:
            kind, offset, address, _, size, memory, flags, align = record
        if kind == 1:
            loads.append((offset, address, size, memory))
        if kind == 0x6474e550:
            candidates.append((offset, address, size))
    if not candidates:
        return None
    assert len(candidates) == 1

    def locate(address, size):
        overlaps = [row for row in loads if address < row[1] + row[3] and row[1] < address + size]
        assert len(overlaps) == 1
        offset, start, file_size, _ = overlaps[0]
        assert start <= address and address + size <= start + file_size
        assert offset + address - start + size <= len(data)
        return offset + address - start

    def unsigned(address, size):
        offset = locate(address, size)
        return int.from_bytes(data[offset:offset + size], 'little' if order == '<' else 'big')

    offset, base, size = candidates[0]
    assert size >= 4 and locate(base, size) == offset
    version, pointer_encoding, count_encoding, table_encoding = data[offset:offset + 4]
    assert version == 1 and count_encoding & 0xf0 == 0
    cursor = base + 4

    def encoded(encoding):
        nonlocal cursor
        form = encoding & 15
        width = {0: 8 if wide else 4, 2: 2, 3: 4, 4: 8, 10: 2, 11: 4, 12: 8}[form]
        assert cursor + width <= base + size
        where = locate(cursor, width)
        value = int.from_bytes(data[where:where + width], 'little' if order == '<' else 'big', signed=form >= 10)
        application = encoding & 0xf0
        assert application in (0, 0x10, 0x30)
        result = value + (cursor if application == 0x10 else base if application == 0x30 else 0)
        cursor += width
        return result

    start = encoded(pointer_encoding)
    count = encoded(count_encoding)
    assert 0 < count <= 262144 and table_encoding != 255
    entries = [(encoded(table_encoding), encoded(table_encoding)) for _ in range(count)]
    assert all(entries[i][0] < entries[i + 1][0] for i in range(count - 1))
    referenced = {entry[1] for entry in entries}
    assert len(referenced) == count
    end = start
    for address in referenced:
        length = unsigned(address, 4)
        assert 4 <= length < 0xfffffff0  # Research profile: ordinary DWARF32 records.
        end = max(end, address + 4 + length)
    assert 0 < end - start <= 64 * 1024 * 1024
    frame_offset = locate(start, end - start)
    cies, fdes = set(), set()
    cursor = start
    while cursor < end:
        length = unsigned(cursor, 4)
        assert 4 <= length < 0xfffffff0 and cursor + 4 + length <= end
        identity = unsigned(cursor + 4, 4)
        if identity == 0:
            cies.add(cursor)
        else:
            assert cursor + 4 - identity in cies
            fdes.add(cursor)
        cursor += 4 + length
    assert cursor == end and fdes == referenced
    return {'address': start, 'offset': frame_offset, 'size': end - start,
        'fdeCount': len(fdes), 'cieCount': len(cies), 'encodings': [pointer_encoding, count_encoding, table_encoding]}

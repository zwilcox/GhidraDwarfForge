#!/usr/bin/env python3
"""Independent raw DWARF ranges and source-hole checks for the split fixture."""
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

source = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, source / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


elf = module('split_elf_facts', 'arm-thumb-mode-check.py')
dies = module('split_die_facts', 'dynamic-parameter-storage-check.py')


def range_offset(attribute):
    match = re.fullmatch(r'(?:\(sec_offset\)\s+)?(0x[0-9a-f]+)', attribute)
    assert match is not None, attribute
    return int(match[1], 16)


def check_ranges(raw, offset, start):
    length, version, address_size, segment_size, entries = struct.unpack_from('<IHBBI', raw)
    assert (length, version, address_size, segment_size, entries) == (len(raw) - 4, 5, 4, 0, 0)
    assert 12 <= offset < len(raw)
    ranges = []
    while raw[offset] != 0:
        assert raw[offset] == 6, 'fixture requires DW_RLE_start_end'
        begin, end = struct.unpack_from('<II', raw, offset + 1)
        ranges.append((begin - start, end - start))
        offset += 9
        assert len(ranges) <= 2
    assert ranges == [(0, 4), (8, 48)], ranges
    return ranges


def check_lines(text, start):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\S+\s+(\d+|-)\s+(0x[0-9a-f]+)\s', line)
        if match is None or match[1] == '-':
            continue
        offset = int(match[2], 16) - start
        if 0 <= offset < 52:
            assert offset in (0, 8, 12, 16, 20, 24, 26, 28, 30, 32, 36, 40, 44), (offset, line)
            rows.append({'offset': offset, 'line': int(match[1])})
    assert rows and any(row['offset'] == 0 for row in rows) and any(row['offset'] >= 8 for row in rows)
    return rows


def main(case):
    labels = json.loads((case / 'labels.json').read_text())
    assert labels['split']
    start = labels['start']
    artifact = case / 'curated.dbg'
    texts = {}
    for view in ('info', 'decodedline'):
        result = subprocess.run(['readelf', '--debug-dump=' + view, str(artifact)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        assert result.returncode == 0 and not result.stderr
        texts[view] = result.stdout.decode()
        (case / ('split-' + view + '.txt')).write_text(texts[view])
    function, = [row for row in dies.die_records(texts['info']) if row['tag'] == 'DW_TAG_subprogram'
        and dies.die_name(row) == 'recovered_mixed_body']
    assert 'DW_AT_low_pc' not in function['attrs'] and 'DW_AT_high_pc' not in function['attrs']
    offset = range_offset(function['attrs']['DW_AT_ranges'])
    raw = elf.section(elf.elf(artifact), '.debug_rnglists')['data']
    ranges = check_ranges(raw, offset, start)
    rows = check_lines(texts['decodedline'], start)
    rejected = []
    for name, at, value in (('cover-data-hole', offset + 10, start + 4),
            ('drop-entry-instruction', offset + 1, start + 1),
            ('include-trailing-literal', offset + 14, start + 52)):
        altered = bytearray(raw)
        struct.pack_into('<I', altered, at, value)
        try:
            check_ranges(altered, offset, start)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError('range oracle accepted corruption: ' + name)
    for at in (4, 5, 6, 7, 48, 49, 50, 51):
        try:
            check_lines(texts['decodedline'] + f'\ncurated.dbg.c 82 0x{start + at:x} x\n', start)
        except AssertionError:
            rejected.append('executable-data-byte-' + str(at))
        else:
            raise AssertionError('line oracle accepted data byte')
    (case / 'split-dwarf-ranges.json').write_text(json.dumps({'status': 'PASS', 'rangeListOffset': offset,
        'ranges': ranges, 'rows': rows, 'rejectedCorruptions': rejected}, indent=4) + '\n')


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve())

#!/usr/bin/env python3
"""Independently decode complete piece expressions and marker availability."""
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

case, target = Path(sys.argv[1]), sys.argv[2]
spec = importlib.util.spec_from_file_location('dies', Path(__file__).with_name('check-stack-first-use.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
labels = json.loads((case / 'labels.json').read_text())
prepared = json.loads((case / 'prepared.json').read_text())
records = helper.parse_dies((case / 'fixed-info.log').read_text())
by_offset = {row['offset']: row for row in records}
offsets = {}
for index, record in enumerate(records):
    name = helper.text_value(record['attributes'].get('DW_AT_name', ''))
    if record['tag'] != 'DW_TAG_subprogram' or name not in labels['order']:
        continue
    parameters = []
    for child in records[index + 1:]:
        if child['depth'] <= record['depth']:
            break
        if child['tag'] == 'DW_TAG_formal_parameter':
            assert child['depth'] == record['depth'] + 1
            parameters.append(child)
    parameter, = parameters
    attrs = parameter['attributes']
    assert helper.text_value(attrs['DW_AT_name']) == 'value'
    assert not {'DW_AT_const_value', 'DW_AT_start_scope'} & attrs.keys()
    match = re.fullmatch(r'(0x[0-9a-f]+) \(location list\)', attrs['DW_AT_location'])
    assert match, attrs
    offsets[name] = int(match[1], 16)
    dtype = by_offset[int(re.fullmatch(r'<0x([0-9a-f]+)>', attrs['DW_AT_type'])[1], 16)]
    assert dtype['tag'] == 'DW_TAG_structure_type' and helper.number(dtype['attributes']['DW_AT_byte_size']) == 16
    members = []
    for child in records[records.index(dtype) + 1:]:
        if child['depth'] <= dtype['depth']:
            break
        if child['tag'] == 'DW_TAG_member':
            member = child['attributes']
            base = by_offset[int(re.fullmatch(r'<0x([0-9a-f]+)>', member['DW_AT_type'])[1], 16)]
            assert base['tag'] == 'DW_TAG_base_type' and helper.number(base['attributes']['DW_AT_byte_size']) == 8
            assert helper.number(base['attributes']['DW_AT_encoding']) == 7
            members.append((helper.text_value(member['DW_AT_name']), helper.number(member['DW_AT_data_member_location'])))
    assert members == [('first', 0), ('second', 8)], members
assert set(offsets) == set(labels['order'])
section_dump = subprocess.run(['readelf', '-SW', str(case / 'local.dbg')], text=True, capture_output=True, check=True)
assert not section_dump.stderr
section, = re.findall(r'^\s*\[\s*\d+\]\s+\.debug_loclists\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b', section_dump.stdout, re.M)
offset, size = map(lambda value: int(value, 16), section)
raw = (case / 'local.dbg').read_bytes()
assert raw[:6] == b'\x7fELF\x02\x01'
data = raw[offset:offset + size]
assert struct.unpack_from('<IHBBI', data) == (size - 4, 5, 8, 0, 0)


def leb(index, signed=False):
    value = shift = 0
    while True:
        byte = data[index]
        index += 1
        value |= (byte & 127) << shift
        shift += 7
        assert shift <= 70
        if not byte & 128:
            break
    if signed and byte & 64:
        value -= 1 << shift
    return value, index


locations = {}
for name, cursor in offsets.items():
    row = labels['functions'][name]
    intervals = []
    while data[cursor]:
        assert data[cursor] == 7
        start, end = struct.unpack_from('<QQ', data, cursor + 1)
        length, cursor = leb(cursor + 17)
        expression_end = cursor + length
        pieces = []
        for piece in range(2):
            opcode = data[cursor]
            register, cursor = leb(cursor + 1)
            item = {'register': register}
            if opcode == 0x92:
                displacement, cursor = leb(cursor, True)
                assert register == (7 if target == 'x86_64' else 31)
                assert -4096 <= displacement <= 4096
                item.update(kind='stack', offset=displacement)
            else:
                assert opcode == 0x90 and 0 <= register < (16 if target == 'x86_64' else 31)
                item.update(kind='register')
            assert data[cursor] == 0x9d
            bits, cursor = leb(cursor + 1)
            bit_offset, cursor = leb(cursor)
            assert bits == 64 and bit_offset == 0
            pieces.append(item)
        assert cursor == expression_end and row['entry'] <= start < end <= row['end']
        if intervals:
            assert intervals[-1]['end'] <= start
        intervals.append({'start': start, 'end': end, 'pieces': pieces})
    boundary = row['returned'] if name == 'pieces_volatile_call' else row['alias_done'] if 'alias' in name else row['lost']
    assert intervals and intervals[0]['start'] == row['entry'] and intervals[-1]['end'] == boundary, (name, intervals)
    gaps = [(a['end'], b['start']) for a, b in zip(intervals, intervals[1:]) if a['end'] != b['start']]
    assert gaps == ([(row['hole'], row['afterhole'])] if name == 'pieces_split' else []), (name, gaps)
    if name == 'pieces_split':
        assert all(i['end'] <= row['hole'] or i['start'] >= row['afterhole'] for i in intervals)
        assert len(prepared[name + '_body']) == 2
    instructions = prepared[name + '_instructions']
    assert all(any(i['address'] == interval['start'] for i in instructions) and
        any(i['next'] == interval['end'] for i in instructions) for interval in intervals)
    expected = {'second_ready': ['register', 'register'], 'first_memory': ['stack', 'register']}
    if 'alias' not in name:
        expected.update(second_memory=['stack', 'stack'], first_loaded=['register', 'stack'],
            slot_changed=['register', 'stack'], second_loaded=['register', 'register'])
    for marker, kinds in expected.items():
        interval, = [i for i in intervals if i['start'] <= row[marker] < i['end']]
        assert [p['kind'] for p in interval['pieces']] == kinds, (name, marker, interval)
    locations[name] = intervals
(case / 'locations.json').write_text(json.dumps(locations, indent=4) + '\n')
print('composite-value-flow-locations=PASS functions=' + str(len(locations)))

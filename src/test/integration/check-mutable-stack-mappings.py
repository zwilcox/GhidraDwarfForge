#!/usr/bin/env python3
"""Read raw local locations and require the independent machine marker boundaries."""
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
storage = json.loads((case / 'compiler-storage.json').read_text())
prepared = json.loads((case / 'prepared.json').read_text())
records = helper.parse_dies((case / 'fixed-info.log').read_text())
offsets = {}
for index, record in enumerate(records):
    if record['tag'] != 'DW_TAG_subprogram':
        continue
    name = helper.text_value(record['attributes'].get('DW_AT_name', ''))
    if name not in labels['order']:
        continue
    locals_found = []
    for child in records[index + 1:]:
        if child['depth'] <= record['depth']:
            break
        if child['tag'] == 'DW_TAG_variable':
            attrs = child['attributes']
            assert child['depth'] == record['depth'] + 1
            local_name = helper.text_value(attrs['DW_AT_name'])
            if local_name == 'other':
                assert name == 'mutable_conflict'
                continue
            assert local_name == 'value'
            if name == 'mutable_conflict':
                assert 'DW_AT_location' not in attrs
                locals_found.append(None)
                continue
            assert 'DW_AT_type' in attrs and not {'DW_AT_const_value', 'DW_AT_start_scope'} & attrs.keys()
            match = re.fullmatch(r'(0x[0-9a-f]+) \(location list\)', attrs['DW_AT_location'])
            assert match, attrs
            locals_found.append(int(match[1], 16))
    assert len(locals_found) == 1 and name not in offsets
    offsets[name] = locals_found[0]
assert set(offsets) == set(labels['order'])
sections = subprocess.run(['readelf', '-SW', str(case / 'local.dbg')], text=True, capture_output=True, check=True)
assert not sections.stderr
section, = re.findall(r'^\s*\[\s*\d+\]\s+\.debug_loclists\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b', sections.stdout, re.M)
offset, size = [int(value, 16) for value in section]
with (case / 'local.dbg').open('rb') as stream:
    assert stream.read(6) == b'\x7fELF\x02\x01'
    stream.seek(offset)
    data = stream.read(size)
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
    if cursor is None:
        assert name == 'mutable_conflict'
        locations[name] = []
        continue
    intervals = []
    while data[cursor]:
        assert data[cursor] == 7
        low, high = struct.unpack_from('<QQ', data, cursor + 1)
        length, cursor = leb(cursor + 17)
        end = cursor + length
        opcode = data[cursor]
        register, cursor = leb(cursor + 1)
        interval = {'start': low, 'end': high, 'register': register}
        if opcode == 0x92:
            displacement, cursor = leb(cursor, True)
            assert register == (7 if target == 'x86_64' else 31)
            assert displacement == storage[name]['spOffset']
            interval.update(kind='stack', offset=displacement)
        else:
            assert opcode == 0x90
            assert 0 <= register < (16 if target == 'x86_64' else 31)
            interval.update(kind='register')
        assert cursor == end and low < high
        if intervals:
            assert intervals[-1]['end'] == low
        intervals.append(interval)
    assert len(intervals) >= 2 and intervals[0]['kind'] == 'stack'
    assert intervals[0]['start'] == row['live'] and intervals[-1]['end'] == row['availableEnd'], (name, intervals, row)
    assert any(item['kind'] == 'register' and item['register'] == (10 if target == 'x86_64' else 9) for item in intervals)
    definition, load, update = prepared[name]
    assert [item['name'] for item in prepared[name]] == ['value', 'value$1', 'value$2']
    assert load['definition'] == row['load'] and update['definition'] == row['update']
    for mapping, ready in [(load, row['loaded']), (update, row['updated'])]:
        instruction, = [item for item in prepared[name + '_instructions'] if item['address'] == mapping['definition']]
        assert instruction['next'] == ready and instruction['bytes'] == mapping['bytes']
        assert instruction['pcode'] == mapping['pcode']
    assert definition['firstUse'] > 0 and definition['stackOffset'] == storage[name]['offset']
    instruction, = [item for item in prepared[name + '_instructions'] if item['address'] == definition['definition']]
    assert instruction['next'] == row['live'] and instruction['bytes'] == definition['bytes']
    assert sum(' STORE ' in op for op in instruction['pcode']) == 1
    assert instruction['pcode'] == definition['pcode']
    effect, = [item for item in prepared[name + '_instructions'] if item['next'] == row['lost']]
    assert sum(' STORE ' in op for op in effect['pcode']) == 1
    expected = [(row['live'], row['loaded'], 'stack'),
        (row['loaded'], row['killed'], 'register')]
    if name != 'mutable_unsaved':
        expected += [(row['killed'], row['reloaded'], 'stack'), (row['reloaded'], row['lost'], 'register')]
    assert [(item['start'], item['end'], item['kind']) for item in intervals] == expected, (name, intervals, expected)
    for item in intervals:
        if item['kind'] == 'register':
            assert item['register'] == (10 if target == 'x86_64' else 9)
    locations[name] = intervals
(case / 'locations.json').write_text(json.dumps(locations, indent=4) + '\n')
print('mutable-stack-mappings-locations=PASS functions=' + str(len(locations)))

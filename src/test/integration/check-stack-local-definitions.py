#!/usr/bin/env python3
"""Independently check actual local DIEs, raw loclists and every GDB boundary."""
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

case, target = Path(sys.argv[1]), sys.argv[2]
source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('first_use', source / 'check-stack-first-use.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
labels = json.loads((case / 'labels.json').read_text())
prepared = json.loads((case / 'prepared.json').read_text())
storage = json.loads((case / 'compiler-storage.json').read_text())
records = helper.parse_dies((case / 'info.txt').read_text())
offsets = {}
for index, record in enumerate(records):
    if record['tag'] != 'DW_TAG_subprogram' or helper.text_value(record['attributes'].get('DW_AT_name', '')) != 'stack_scope':
        continue
    for child in records[index + 1:]:
        if child['depth'] <= record['depth']:
            break
        if child['tag'] != 'DW_TAG_variable':
            continue
        assert child['depth'] == record['depth'] + 1, 'function-owned locals must not acquire invented lexical blocks'
        attrs = child['attributes']
        name = helper.text_value(attrs['DW_AT_name'])
        assert name in ('first', 'second') and name not in offsets
        assert 'DW_AT_type' in attrs and 'DW_AT_const_value' not in attrs and 'DW_AT_start_scope' not in attrs
        match = re.fullmatch(r'(0x[0-9a-f]+) \(location list\)', attrs['DW_AT_location'])
        assert match, attrs
        offsets[name] = int(match[1], 16)
assert set(offsets) == {'first', 'second'}
sections = subprocess.run(['readelf', '-SW', str(case / 'stack.dbg')], text=True, capture_output=True, check=True)
assert not sections.stderr
section, = re.findall(r'^\s*\[\s*\d+\]\s+\.debug_loclists\s+PROGBITS\s+[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b', sections.stdout, re.M)
offset, size = [int(value, 16) for value in section]
with (case / 'stack.dbg').open('rb') as stream:
    assert stream.read(6) == b'\x7fELF\x02\x01'
    stream.seek(offset)
    data = stream.read(size)
assert struct.unpack_from('<IHBBI', data) == (size - 4, 5, 8, 0, 0)


def leb(data, index, signed=False):
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


actual = {}
for name, cursor in offsets.items():
    intervals = []
    while data[cursor]:
        assert data[cursor] == 7
        low, high = struct.unpack_from('<QQ', data, cursor + 1)
        length, cursor = leb(data, cursor + 17)
        expression = data[cursor:cursor + length]
        cursor += length
        if expression[0] == 0x92:
            register, pos = leb(expression, 1)
            displacement, pos = leb(expression, pos, True)
            assert pos == len(expression) and register == (7 if target == 'x86_64' else 31)
            assert displacement == storage['runtime_sp_offset']
            kind = 'stack'
        else:
            assert expression[0] == 0x90
            register, pos = leb(expression, 1)
            assert pos == len(expression) and register == (0 if target == 'x86_64' else 1)
            kind = 'register'
        intervals.append((low, high, kind))
    assert len(intervals) == 2 and [row[2] for row in intervals] == ['stack', 'register'], intervals
    assert intervals[0][1] == intervals[1][0]
    assert intervals[0][0] == labels['stack_scope'][name + '_live']
    assert intervals[1][1] == labels['stack_scope']['between_scopes' if name == 'first' else 'after_scopes']
    # Correlate the physical handoff with the decoded source instruction and bytes.
    load, = [row for row in prepared['stack_scope_instructions'] if row['next'] == intervals[1][0]]
    assert sum(' LOAD ' in op for op in load['pcode']) == 1
    actual[name] = intervals
observed = json.loads((case / 'forge-instruction-gdb.json').read_text())
assert [row['linkPc'] for row in observed] == [row['address'] for row in prepared['stack_scope_instructions']]
for row in observed:
    for name in ('first', 'second'):
        available = any(low <= row['linkPc'] < high for low, high, kind in actual[name])
        assert row['values'][name] == (('11' if name == 'first' else '22') if available else '<optimized out>')
if (case / 'previous-instruction-gdb.json').is_file():
    previous = json.loads((case / 'previous-instruction-gdb.json').read_text())
    assert [row['linkPc'] for row in previous] == [row['linkPc'] for row in observed]
    assert all(value == '<optimized out>' for row in previous for value in row['values'].values())
definitions = {row['name']: row for row in prepared['stack_scope']}
assert definitions['first']['symbolId'] != definitions['second']['symbolId']
assert all(row['firstUse'] > 0 and row['stackOffset'] == storage['scope_offset'] for row in definitions.values())
for name, row in definitions.items():
    instruction, = [i for i in prepared['stack_scope_instructions'] if i['address'] == row['definition']]
    assert row['bytes'] == instruction['bytes'] and instruction['next'] == actual[name][0][0]
    assert row['pcode'] == instruction['pcode'] and sum(' STORE ' in op for op in row['pcode']) == 1
print(json.dumps({'status': 'PASS', 'instructionObservations': len(observed), 'locations': actual}, indent=4))

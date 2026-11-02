#!/usr/bin/env python3
"""Decode the actual indirect-argument DWARF bytes for the runtime carrier oracle."""
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

spec = importlib.util.spec_from_file_location('dies', Path(__file__).with_name('check-stack-first-use.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def leb(data, cursor, signed=False):
    value = shift = 0
    while True:
        byte = data[cursor]
        cursor += 1
        value |= (byte & 127) << shift
        shift += 7
        assert shift <= 70
        if not byte & 128:
            break
    if signed and byte & 64:
        value -= 1 << shift
    return value, cursor


def main(case, failed=None):
    artifact = case / 'abi.dbg'
    result = subprocess.run(['readelf', '-SW', '--debug-dump=info', artifact],
        text=True, capture_output=True, check=True, timeout=60)
    assert not result.stderr
    records = helper.parse_dies(result.stdout)
    by_offset = {row['offset']: row for row in records}
    section, = re.findall(r'^\s*\[\s*\d+\]\s+\.debug_loclists\s+PROGBITS\s+'
        r'[0-9a-f]+\s+([0-9a-f]+)\s+([0-9a-f]+)\b', result.stdout, re.M)
    offset, size = (int(value, 16) for value in section)
    raw = artifact.read_bytes()
    assert raw[:6] == b'\x7fELF\x02\x01'
    data = raw[offset:offset + size]
    assert struct.unpack_from('<IHBBI', data) == (size - 4, 5, 8, 0, 0)
    symbols = json.loads((case / 'metadata.json').read_text())['symbols']
    names = {'abi_large', 'abi_large_stack', 'abi_large_spill', 'abi_large_spill_alias'}
    if 'abi_pair_chain' in symbols: names.add('abi_pair_chain')
    assert failed is None or failed in names
    locations = {}
    failed_range = None
    for index, row in enumerate(records):
        name = helper.text_value(row['attributes'].get('DW_AT_name', '')).removeprefix('curated_')
        if row['tag'] != 'DW_TAG_subprogram' or name not in names:
            continue
        assert name not in locations
        low = helper.number(row['attributes']['DW_AT_low_pc'])
        high = low + helper.number(row['attributes']['DW_AT_high_pc'])
        assert low == symbols[name]
        parameters = []
        for child in records[index + 1:]:
            if child['depth'] <= row['depth']:
                break
            if name == failed:
                assert child['tag'] is None, 'failed function retained a child DIE'
            if child['tag'] == 'DW_TAG_formal_parameter' and helper.text_value(
                    child['attributes'].get('DW_AT_name', '')) == ('object' if name == 'abi_pair_chain' else 'value'):
                assert child['depth'] == row['depth'] + 1
                parameters.append(child)
        if name == failed:
            assert not parameters
            assert not {'DW_AT_type', 'DW_AT_decl_file', 'DW_AT_decl_line', 'DW_AT_specification'} & row['attributes'].keys()
            failed_range = (low, high)
            continue
        parameter, = parameters
        attrs = parameter['attributes']
        assert not {'DW_AT_const_value', 'DW_AT_start_scope'} & attrs.keys()
        reference = re.search(r'<0x([0-9a-f]+)>', attrs['DW_AT_type'])
        dtype = by_offset[int(reference[1], 16)]
        assert dtype['tag'] == 'DW_TAG_structure_type'
        assert helper.number(dtype['attributes']['DW_AT_byte_size']) == 24
        match = re.search(r'(0x[0-9a-f]+) \(location list\)$', attrs['DW_AT_location'])
        assert match, attrs
        cursor = int(match[1], 16)
        assert 12 <= cursor < len(data)
        intervals = []
        while data[cursor]:
            assert data[cursor] == 7, 'expected DW_LLE_start_end'
            start, end = struct.unpack_from('<QQ', data, cursor + 1)
            length, cursor = leb(data, cursor + 17)
            expression = data[cursor:cursor + length]
            cursor += length
            assert expression[0] == 0x92, 'formal object must have an address'
            register, position = leb(expression, 1)
            displacement, position = leb(expression, position, signed=True)
            suffix = expression[position:]
            assert 0 <= register <= 31 and suffix in (b'', b'\x06'), expression.hex()
            assert low <= start < end <= high and (start - low) % 4 == (end - low) % 4 == 0
            assert not intervals or intervals[-1]['end'] <= start - low
            intervals.append({'start': start - low, 'end': end - low, 'register': register,
                'displacement': displacement, 'dereference': bool(suffix), 'bytes': expression.hex()})
        assert intervals and intervals[0]['start'] == 0
        assert any(row['dereference'] for row in intervals) == (name != 'abi_large')
        locations[name] = intervals
    assert set(locations) == names - ({failed} if failed else set())
    if failed:
        assert failed_range is not None
        # Check every physical list, including anything no DIE references.
        cursor = 12
        while cursor < len(data):
            if data[cursor] == 0:
                cursor += 1
                continue
            assert data[cursor] == 7
            start, end = struct.unpack_from('<QQ', data, cursor + 1)
            assert end <= failed_range[0] or start >= failed_range[1], 'orphan failed-owner location'
            length, cursor = leb(data, cursor + 17)
            cursor += length
        assert cursor == len(data)
    expected_slots = {
        'abi_narrow_stack': {'low': (0, 1, 5), 'high': (8, 2, 7), 'middle': (16, 4, 5), 'wide': (24, 8, 5)},
        'abi_aligned_stack': {'lead': (0, 1, 5), 'wide': (16, 16, 5), 'tail': (32, 1, 5)},
        'abi_pair_stack': {'value': (0, 16, None), 'tail': (16, 8, 5)},
        'abi_pair_chain': {'value': (0, 16, None), 'tail': (16, 8, 5), 'wide': (32, 16, 5)},
        'abi_pair_variadic': {'value': (0, 16, None), 'tail': (16, 8, 5)},
    }
    slots = {}
    for index, row in enumerate(records):
        name = helper.text_value(row['attributes'].get('DW_AT_name', '')).removeprefix('curated_')
        if row['tag'] != 'DW_TAG_subprogram' or name not in expected_slots:
            continue
        wanted = expected_slots[name]
        observed = {}
        for child in records[index + 1:]:
            if child['depth'] <= row['depth']: break
            parameter = helper.text_value(child['attributes'].get('DW_AT_name', ''))
            if child['tag'] != 'DW_TAG_formal_parameter' or parameter not in wanted: continue
            displacement, width, encoding = wanted[parameter]
            attrs = child['attributes']
            match = re.search(r'(\d+) byte block: ([0-9a-f ]+)\s+\(DW_OP_', attrs['DW_AT_location'])
            assert match, (name, parameter, attrs)
            expression = bytes(int(value, 16) for value in match[2].split())
            assert len(expression) == int(match[1]) and expression == bytes((0x92, 31, displacement)), (name, parameter, expression.hex())
            dtype = by_offset[int(re.search(r'<0x([0-9a-f]+)>', attrs['DW_AT_type'])[1], 16)]
            assert helper.number(dtype['attributes']['DW_AT_byte_size']) == width
            if encoding is None:
                assert dtype['tag'] == 'DW_TAG_structure_type'
            else:
                assert dtype['tag'] == 'DW_TAG_base_type'
                assert helper.number(dtype['attributes']['DW_AT_encoding']) == encoding
            observed[parameter] = {'offset': displacement, 'bytes': width, 'encoding': encoding, 'expression': expression.hex()}
        assert set(observed) == set(wanted)
        slots[name] = observed
    assert set(slots) == set(expected_slots) & set(symbols)
    (case / 'allocation-locations.json').write_text(json.dumps(slots, indent=4) + '\n')
    (case / 'indirect-locations.json').write_text(json.dumps(locations, indent=4) + '\n')
    print('aarch64-indirect-locations=PASS functions=' + str(len(locations)))


if __name__ == '__main__':
    main(Path(sys.argv[1]), sys.argv[2] if len(sys.argv) == 3 else None)

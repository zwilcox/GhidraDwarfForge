#!/usr/bin/env python3
"""Decode emitted parameter expressions for independent physical-carrier checks."""
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import arm_stack_aggregate_contract as contract


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def expression(data, width):
    pieces, cursor = [], 0
    while cursor < len(data):
        opcode = data[cursor]
        register, cursor = leb(data, cursor + 1)
        assert opcode in (0x90, 0x92), ('unsupported expression', data.hex())
        if opcode == 0x92:
            assert register == 13, ('memory carrier must be entry-derived stack', register)
            displacement, cursor = leb(data, cursor, True)
            piece = {'kind': 'stack', 'register': register, 'displacement': displacement}
        else:
            assert 0 <= register <= 15 or 64 <= register <= 95 or 256 <= register <= 287
            piece = {'kind': 'register', 'register': register}
        if cursor == len(data):
            assert not pieces, 'unbounded trailing piece'
            bits, bit_offset = width * 8, 0
        else:
            assert data[cursor] == 0x9d, ('expected DW_OP_bit_piece', data.hex())
            bits, cursor = leb(data, cursor + 1)
            bit_offset, cursor = leb(data, cursor)
        assert bits > 0 and bits % 8 == bit_offset % 8 == 0
        if piece['kind'] == 'stack':
            assert bit_offset == 0
        piece.update(bits=bits, bitOffset=bit_offset)
        pieces.append(piece)
    assert sum(piece['bits'] for piece in pieces) == width * 8
    return pieces


def main(case):
    source = Path(__file__).resolve().parent
    helper = load('dies', source / 'check-stack-first-use.py')
    elf = load('elf', source / 'arm-thumb-mode-check.py')
    image = elf.elf(case / 'calls.dbg', allow_big_endian=True)
    records = helper.parse_dies((case / 'dbg-info.log').read_text())
    by_offset = {row['offset']: row for row in records}
    data = elf.section(image, '.debug_loclists')['data']
    order = '<' if image['data'][5] == 1 else '>'
    assert struct.unpack_from(order + 'IHBBI', data) == (len(data) - 4, 5, 4, 0, 0)
    inventory = json.loads((case / 'instruction-inventory.json').read_text())
    failed = json.loads((case / 'profile.json').read_text()).get('failedFunction')
    failed_range = None
    sizes = {'pair': 8, 'aligned': 16, 'packed': 5, 'bytes': 3, 'words': 12, 'mixed': 16, 'floats': 12}
    result = {}
    for index, row in enumerate(records):
        name = helper.text_value(row['attributes'].get('DW_AT_name', ''))
        if row['tag'] != 'DW_TAG_subprogram':
            continue
        if name == failed:
            assert failed_range is None
            attrs = row['attributes']
            assert not {'DW_AT_type', 'DW_AT_decl_line', 'DW_AT_frame_base'} & attrs.keys()
            assert index + 1 == len(records) or records[index + 1]['depth'] <= row['depth']
            low = helper.number(attrs['DW_AT_low_pc'])
            failed_range = (low, low + helper.number(attrs['DW_AT_high_pc']))
            continue
        if name not in contract.FUNCTIONS:
            continue
        assert name not in result
        expected = inventory[name]
        low = helper.number(row['attributes']['DW_AT_low_pc'])
        high = low + helper.number(row['attributes']['DW_AT_high_pc'])
        assert (low, high - low) == (expected['entry'], expected.get('codeSize', expected['size'])), name
        kind = name.split('_')[1]
        widths = {letter: 8 if kind == 'floats' else 4 for letter in ('abcdefg' if kind == 'floats' else 'abc')}
        widths.update(value=sizes[kind], tail=4)
        parameters = {}
        for child in records[index + 1:]:
            if child['depth'] <= row['depth']:
                break
            if child['tag'] != 'DW_TAG_formal_parameter':
                continue
            assert child['depth'] == row['depth'] + 1
            attrs = child['attributes']
            parameter = helper.text_value(attrs['DW_AT_name'])
            assert parameter in widths and parameter not in parameters
            assert not {'DW_AT_const_value', 'DW_AT_start_scope'} & attrs.keys()
            dtype = by_offset[int(re.fullmatch(r'<0x([0-9a-f]+)>', attrs['DW_AT_type'])[1], 16)]
            assert helper.number(dtype['attributes']['DW_AT_byte_size']) == widths[parameter]
            assert dtype['tag'] == ('DW_TAG_structure_type' if parameter == 'value' else 'DW_TAG_base_type')
            if parameter != 'value':
                assert helper.number(dtype['attributes']['DW_AT_encoding']) == (4 if kind == 'floats' else 5)
            location = attrs['DW_AT_location']
            listed = re.fullmatch(r'(0x[0-9a-f]+) \(location list\)', location)
            intervals = []
            if listed:
                cursor = int(listed[1], 16)
                assert 12 <= cursor < len(data)
                while data[cursor]:
                    assert data[cursor] == 7, 'expected DW_LLE_start_end'
                    start, end = struct.unpack_from(order + 'II', data, cursor + 1)
                    length, cursor = leb(data, cursor + 9)
                    raw = data[cursor:cursor + length]
                    cursor += length
                    assert low <= start < end <= high and (start - low) % 4 == (end - low) % 4 == 0
                    assert not intervals or intervals[-1]['end'] <= start - low
                    intervals.append({'start': start - low, 'end': end - low,
                        'bytes': raw.hex(), 'pieces': expression(raw, widths[parameter])})
            else:
                inline = re.fullmatch(r'(\d+) byte block: ([0-9a-f ]+)\s+\(DW_OP_.*\)', location)
                assert inline, (name, parameter, location)
                raw = bytes(int(part, 16) for part in inline[2].split())
                assert len(raw) == int(inline[1])
                intervals.append({'start': 0, 'end': high - low,
                    'bytes': raw.hex(), 'pieces': expression(raw, widths[parameter])})
            assert intervals and intervals[0]['start'] == 0, (name, parameter)
            parameters[parameter] = intervals
        assert set(parameters) == set(widths), (name, parameters.keys())
        # Independently prescribed entry allocation, including partial-word
        # padding. Later choices are read physically at each actual GDB stop.
        first = parameters['value'][0]['bytes']
        if kind in ('pair', 'packed', 'words'):
            trailing = {'pair': '20', 'packed': '08', 'words': '40'}[kind]
            assert first == '90039d2000920d009d' + trailing + '00', (name, first)
        elif kind == 'bytes':
            assert first == ('9003' if order == '<' else '90039d1808'), (name, first)
        else:
            displacement = 40 if kind == 'floats' and name.startswith('base_') else 0
            assert first == bytes((0x92, 13, displacement)).hex(), (name, first)
        result[name] = parameters
    assert set(result) == set(contract.FUNCTIONS) - {failed}
    if failed:
        assert failed_range is not None
        # A failed function must not retain orphan ranges, including in lists
        # which no surviving parameter DIE references.
        cursor = 12
        while cursor < len(data):
            if data[cursor] == 0:
                cursor += 1
                continue
            assert data[cursor] == 7
            start, end = struct.unpack_from(order + 'II', data, cursor + 1)
            assert end <= failed_range[0] or start >= failed_range[1], 'orphan failed-owner location'
            length, cursor = leb(data, cursor + 9)
            cursor += length
        assert cursor == len(data)
    (case / 'parameter-locations.json').write_text(json.dumps(result, indent=4) + '\n')
    print('arm-stack-aggregate-locations=PASS functions=' + str(len(result)))


if __name__ == '__main__':
    main(Path(sys.argv[1]))

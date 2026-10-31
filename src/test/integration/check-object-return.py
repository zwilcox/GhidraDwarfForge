#!/usr/bin/env python3
"""Require separate exact automatic object/return roles and no name-based classification."""
import json
from pathlib import Path
import re
import sys
from alias_relationships import read_dies, value

case = Path(sys.argv[1])
rows = read_dies(case / 'forge.dbg', case / 'raw-info.log')
by_offset = {r['offset']: r for r in rows}
parents, stack = {}, []
for row in rows:
    stack = stack[:row['depth']]
    parents[row['offset']] = stack[-1]['offset'] if stack else None
    stack.append(row)


def name(row):
    return value(row['attrs'].get('DW_AT_name', ''))


def reference(row, key):
    return by_offset[int(re.match(r'<0x([0-9a-f]+)>', row['attrs'][key])[1], 16)]


def children(row):
    return [r for r in rows if parents[r['offset']] == row['offset']]


method, = [r for r in rows if r['tag'] == 'DW_TAG_subprogram' and name(r) == 'recovered::Counter::inspect_result']
result = reference(method, 'DW_AT_type')
assert result['tag'] == 'DW_TAG_structure_type' and result['attrs']['DW_AT_byte_size'] == '24'
declaration = reference(method, 'DW_AT_specification')
assert declaration['attrs']['DW_AT_declaration'] == '1'
assert not {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges', 'DW_AT_location'} & declaration['attrs'].keys()
for owner in [method, declaration]:
    formals = [r for r in children(owner) if r['tag'] == 'DW_TAG_formal_parameter']
    assert [name(r) for r in formals] == ['this', 'amount']
    receiver = reference(owner, 'DW_AT_object_pointer')
    assert receiver == formals[0] and receiver['attrs']['DW_AT_artificial'] == '1'
    assert 'DW_AT_artificial' not in formals[1]['attrs']
    object_type = reference(reference(receiver, 'DW_AT_type'), 'DW_AT_type')
    assert object_type['attrs']['DW_AT_byte_size'] == '8'
    carrier, = [r for r in children(owner) if r['tag'] == 'DW_TAG_variable' and name(r) == '__return_storage_ptr__']
    assert carrier['attrs']['DW_AT_artificial'] == '1'
    assert reference(reference(carrier, 'DW_AT_type'), 'DW_AT_type') == result
    assert carrier['offset'] != receiver['offset']
    if owner == declaration:
        assert all('DW_AT_location' not in r['attrs'] for r in children(owner))
    else:
        assert 'DW_AT_location' in carrier['attrs'] and 'DW_AT_location' in receiver['attrs']
ordinary, = [r for r in rows if r['tag'] == 'DW_TAG_subprogram' and name(r) == 'ordinary_roles']
assert 'DW_AT_object_pointer' not in ordinary['attrs']
formals = [r for r in children(ordinary) if r['tag'] == 'DW_TAG_formal_parameter']
assert [name(r) for r in formals] == ['this', '__return_storage_ptr__', 'amount']
assert all('DW_AT_artificial' not in r['attrs'] for r in formals)
assert not any(r['tag'] == 'DW_TAG_variable' and name(r) == '__return_storage_ptr__' for r in children(ordinary))
(case / 'object-return-check.json').write_text(json.dumps({'status': 'OBJECT_RETURN_RAW_PASS',
    'method': method['offset'], 'declaration': declaration['offset'], 'returnType': result['offset'],
    'ordinary': ordinary['offset']}, indent=4) + '\n')
print('object-return-identity=PASS')

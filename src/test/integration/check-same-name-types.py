#!/usr/bin/env python3
"""Validate canonical type references, namespace associations and cold GDB lookup."""
import json
from pathlib import Path
import re
import subprocess
import sys
from alias_relationships import read_dies, value

case = Path(sys.argv[1])
rows = read_dies(case / 'forge.dbg', case / 'raw-info.log')
by_offset = {row['offset']: row for row in rows}
parents, stack = {}, []
for row in rows:
    stack = stack[:row['depth']]
    parents[row['offset']] = stack[-1]['offset'] if stack else None
    stack.append(row)


def name(row):
    return value(row['attrs'].get('DW_AT_name', ''))


def one(tag, spelling, **attributes):
    selected, = [row for row in rows if row['tag'] == tag and name(row) == spelling and
        all(row['attrs'].get(key) == val for key, val in attributes.items())]
    return selected


def reference(row, key='DW_AT_type'):
    return by_offset[int(re.match(r'<0x([0-9a-f]+)>', row['attrs'][key])[1], 16)]


def base(row):
    seen = set()
    while row['tag'] in ['DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type']:
        assert row['offset'] not in seen
        seen.add(row['offset'])
        row = reference(row)
    return row


def children(row, tag):
    return [child for child in rows if parents[child['offset']] == row['offset'] and child['tag'] == tag]


objects, categories, states = [], [], []
for namespace, size, field_width, state_value in [('alpha', 16, 4, 5), ('beta', 24, 8, 17)]:
    owner = one('DW_TAG_namespace', namespace)
    variable = one('DW_TAG_variable', namespace + '::object')
    assert variable['depth'] == 1 and 'DW_AT_location' in variable['attrs']
    alias = reference(variable)
    assert alias['tag'] == 'DW_TAG_typedef' and name(alias) == 'Record'
    node = base(alias)
    assert node['tag'] == 'DW_TAG_structure_type' and name(node) == 'Node'
    assert int(node['attrs']['DW_AT_byte_size'], 0) == size
    declaration = reference(node, 'DW_AT_specification')
    assert parents[declaration['offset']] == owner['offset']
    members = {name(child): child for child in children(node, 'DW_TAG_member')}
    assert int(base(reference(members['value']))['attrs']['DW_AT_byte_size'], 0) == field_width
    pointer = reference(members['next'])
    assert pointer['tag'] == 'DW_TAG_pointer_type' and reference(pointer)['offset'] == node['offset']
    if namespace == 'beta':
        assert int(members['extra']['attrs']['DW_AT_data_member_location'], 0) == 16
    method = one('DW_TAG_subprogram', namespace + '::Node::inspect')
    receiver = reference(method, 'DW_AT_object_pointer')
    assert parents[receiver['offset']] == method['offset'] and receiver['tag'] == 'DW_TAG_formal_parameter'
    assert reference(base(reference(receiver)))['offset'] == node['offset']
    state = one('DW_TAG_variable', namespace + '::state')
    enum = base(reference(state))
    assert enum['tag'] == 'DW_TAG_enumeration_type' and name(enum) == 'State'
    enumerators = {name(child): int(child['attrs']['DW_AT_const_value'].split()[0], 0)
        for child in children(enum, 'DW_TAG_enumerator')}
    assert enumerators[namespace.upper() + '_READY'] == state_value
    assert enumerators['SHARED'] == (1 if namespace == 'alpha' else 2)
    states.append(enum['offset'])
    objects.append(node['offset'])
    for global_die in [variable, state]:
        imports = [row for row in children(owner, 'DW_TAG_imported_declaration')
            if reference(row, 'DW_AT_import')['offset'] == global_die['offset']]
        imported, = imports
        assert set(imported['attrs']) == {'DW_AT_import'}, 'ambiguous leaf must not shadow another object'
        location = global_die['attrs']['DW_AT_location']
        assert sum(row['tag'] == 'DW_TAG_variable' and row['attrs'].get('DW_AT_location') == location for row in rows) == 1
for variable_name, size, width in [('category_small', 4, 4), ('category_large', 16, 8)]:
    variable = one('DW_TAG_variable', variable_name)
    alias = reference(variable)
    assert alias['tag'] == 'DW_TAG_typedef' and name(alias) == 'Handle'
    node = base(alias)
    assert node['tag'] == 'DW_TAG_structure_type' and name(node) == 'Packet'
    assert int(node['attrs']['DW_AT_byte_size'], 0) == size and node['depth'] == 1
    members = {name(child): child for child in children(node, 'DW_TAG_member')}
    assert int(base(reference(members['code']))['attrs']['DW_AT_byte_size'], 0) == width
    categories.append(node['offset'])
assert len(set(objects + states + categories)) == 6
assert not any(name(row) in ['AnalystCategories', 'first', 'second'] for row in rows if row['tag'] == 'DW_TAG_namespace')
queries = [
    ("ptype 'alpha::Node'", ['int value;', 'inspect(int)'], ['extra;']),
    ("ptype 'beta::Node'", ['longlong value;', 'int extra;', 'inspect(int)'], []),
    ("ptype 'alpha::object'", ['int value;'], ['extra;']),
    ("ptype 'beta::object'", ['longlong value;', 'int extra;'], []),
    ("ptype 'alpha::state'", ['ALPHA_READY = 5', 'SHARED = 1'], ['BETA_READY']),
    ("ptype 'beta::state'", ['BETA_READY = 17', 'SHARED = 2'], ['ALPHA_READY']),
    ('ptype category_small', ['int code;'], ['extra;']),
    ('ptype category_large', ['longlong code;', 'int extra;'], [])]
observed = []
for query, required, forbidden in queries:
    command = ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set debuginfod enabled off',
        '-ex', 'set auto-solib-add off', '-ex', 'file ' + str(case / 'stripped'),
        '-ex', 'symbol-file ' + str(case / 'forge.dbg'), '-ex', 'set language c', '-ex', query]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0 and not result.stderr, (query, result.stdout, result.stderr)
    assert all(part in result.stdout for part in required) and not any(part in result.stdout for part in forbidden), (query, result.stdout)
    observed.append({'query': query, 'output': result.stdout})
for spelling in ['AnalystCategories::first::Packet', 'AnalystCategories::second::Handle']:
    command[-1] = "ptype '" + spelling + "'"
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    assert result.returncode != 0 and 'No symbol' in result.stderr
(case / 'type-identity-check.json').write_text(json.dumps({'status': 'SAME_NAME_RAW_AND_COLD_LOOKUP_PASS',
    'classDefinitions': objects, 'categoryDefinitions': categories, 'enumDefinitions': states, 'coldQueries': observed}, indent=4) + '\n')
print('same-name-types-identity=PASS')

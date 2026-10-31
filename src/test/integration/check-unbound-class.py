#!/usr/bin/env python3
"""Rejected/conflicting bindings retain method ownership without inheriting a layout."""
import copy
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('class_checker', Path(__file__).with_name('check-class-scopes.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
one, reference = helper.one, helper.reference


def check(nodes):
    unit, = [node for node in nodes.values() if node['tag'] == 'DW_TAG_compile_unit']
    namespace = one(nodes, 'DW_TAG_namespace', 'recovered', unit['offset'])
    declaration = one(nodes, 'DW_TAG_structure_type', 'Counter', namespace['offset'])
    scope = one(nodes, 'DW_TAG_structure_type', 'recovered::Counter', unit['offset'])
    canonical = one(nodes, 'DW_TAG_structure_type', 'Counter', unit['offset'])
    assert reference(scope, 'DW_AT_specification', nodes) is declaration
    alias = one(nodes, 'DW_TAG_typedef', 'recovered::Counter', unit['offset'])
    assert reference(alias, 'DW_AT_type', nodes) is scope
    for node in [scope, declaration]:
        assert node['attributes']['DW_AT_declaration'] == '1'
        assert not {'DW_AT_byte_size', 'DW_AT_type'} & node['attributes'].keys()
        assert not any(child['parent'] == node['offset'] and child['tag'] == 'DW_TAG_member' for child in nodes.values())
    assert 'DW_AT_specification' not in canonical['attributes']
    assert int(canonical['attributes']['DW_AT_byte_size']) == 4
    assert int(one(nodes, 'DW_TAG_member', 'value', canonical['offset'])['attributes']['DW_AT_data_member_location']) == 0
    method = one(nodes, 'DW_TAG_subprogram', 'inspect_object', scope['offset'])
    definition = one(nodes, 'DW_TAG_subprogram', 'recovered::Counter::inspect_object', unit['offset'])
    assert reference(definition, 'DW_AT_specification', nodes) is method
    assert method['attributes']['DW_AT_declaration'] == '1'
    assert not {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges'} & method['attributes'].keys()
    for owner in [method, definition]:
        parameter = reference(owner, 'DW_AT_object_pointer', nodes)
        assert parameter['tag'] == 'DW_TAG_formal_parameter' and parameter['parent'] == owner['offset']
        pointer = reference(parameter, 'DW_AT_type', nodes)
        assert pointer['tag'] == 'DW_TAG_pointer_type'
        assert reference(pointer, 'DW_AT_type', nodes) is canonical
    return scope, canonical, method, definition


nodes = helper.objects.read_dies(Path(sys.argv[1]).read_text())
scope, canonical, method, definition = check(nodes)
mutations = [(scope['offset'], 'DW_AT_byte_size', '4'),
    (scope['offset'], 'DW_AT_declaration', '0'),
    (canonical['offset'], 'DW_AT_specification', '<0x%x>' % scope['offset']),
    (definition['offset'], 'DW_AT_specification', '<0x%x>' % canonical['offset'])]
for offset, attribute, value in mutations:
    broken = copy.deepcopy(nodes)
    broken[offset]['attributes'][attribute] = value
    try:
        check(broken)
    except (AssertionError, KeyError, ValueError):
        continue
    raise AssertionError('fabricated layout or wrong method ownership accepted')
print('unbound-class=PASS negative-controls=' + str(len(mutations)))

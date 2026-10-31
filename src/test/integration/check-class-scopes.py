#!/usr/bin/env python3
"""Check class definition/declaration ownership and exact method/object references."""
import argparse
import copy
import importlib.util
from pathlib import Path
import re

spec = importlib.util.spec_from_file_location('object_checker', Path(__file__).with_name('check-object-parameters.py'))
objects = importlib.util.module_from_spec(spec)
spec.loader.exec_module(objects)


def reference(node, name, nodes):
    target, = re.findall(r'<0x([0-9a-f]+)>', node['attributes'][name])
    return nodes[int(target, 16)]


def one(nodes, tag, name, parent=None):
    found = [node for node in nodes.values() if node['tag'] == tag and node['name'] == name and
        (parent is None or node['parent'] == parent)]
    assert len(found) == 1, (tag, name, parent, found)
    return found[0]


def check(nodes, isolated=False, failed=False, variant='normal'):
    unit, = [node for node in nodes.values() if node['tag'] == 'DW_TAG_compile_unit']
    namespace_name = 'outer' if isolated else 'recovered'
    canonical = 'StoredCounter' if isolated else 'Counter'
    method_name = 'method' if isolated else 'inspect_object'
    namespace = one(nodes, 'DW_TAG_namespace', namespace_name, unit['offset'])
    declaration = one(nodes, 'DW_TAG_structure_type', 'Counter', namespace['offset'])
    assert declaration['attributes']['DW_AT_declaration'] == '1'
    assert 'DW_AT_byte_size' not in declaration['attributes']
    definition = one(nodes, 'DW_TAG_structure_type', canonical, unit['offset'])
    assert reference(definition, 'DW_AT_specification', nodes) is declaration
    assert int(definition['attributes']['DW_AT_byte_size']) == 4
    member = one(nodes, 'DW_TAG_member', 'value', definition['offset'])
    assert int(member['attributes']['DW_AT_data_member_location']) == 0
    alias = one(nodes, 'DW_TAG_typedef', namespace_name + '::Counter', unit['offset'])
    assert reference(alias, 'DW_AT_type', nodes) is definition
    if isolated and variant == 'normal':
        assert reference(one(nodes, 'DW_TAG_typedef', 'Counter', unit['offset']), 'DW_AT_type', nodes) is definition
    if variant != 'normal':
        assert isolated
        assert not any(n['tag'] == 'DW_TAG_typedef' and n['name'] == 'Counter' for n in nodes.values())
        unrelated = one(nodes, 'DW_TAG_structure_type',
            'Counter' if variant == 'collision' else 'OtherLayout', unit['offset'])
        assert int(unrelated['attributes']['DW_AT_byte_size']) == 8
        for name, offset in [('first', 0), ('second', 4)]:
            assert int(one(nodes, 'DW_TAG_member', name, unrelated['offset'])['attributes']['DW_AT_data_member_location']) == offset
        if variant == 'ambiguous':
            other = one(nodes, 'DW_TAG_namespace', 'other', unit['offset'])
            other_declaration = one(nodes, 'DW_TAG_structure_type', 'Counter', other['offset'])
            assert reference(unrelated, 'DW_AT_specification', nodes) is other_declaration
            assert reference(one(nodes, 'DW_TAG_typedef', 'other::Counter', unit['offset']), 'DW_AT_type', nodes) is unrelated
    full_name = namespace_name + '::Counter::' + method_name
    root_method = one(nodes, 'DW_TAG_subprogram', full_name, unit['offset'])
    pairs = []
    if failed:
        assert 'DW_AT_specification' not in root_method['attributes'] and 'DW_AT_type' not in root_method['attributes']
        assert not any(n['parent'] == root_method['offset'] for n in nodes.values())
        assert not any(n['parent'] == definition['offset'] and n['name'] == method_name for n in nodes.values())
    else:
        pairs.append((root_method, one(nodes, 'DW_TAG_subprogram', method_name, definition['offset']), True))
    if isolated:
        external = one(nodes, 'DW_TAG_subprogram', namespace_name + '::Counter::external', unit['offset'])
        assert external['attributes']['DW_AT_declaration'] == '1'
        assert not {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges'} & external['attributes'].keys()
        pairs.append((external, one(nodes, 'DW_TAG_subprogram', 'external', definition['offset']), True))
        nested_declaration = one(nodes, 'DW_TAG_structure_type', 'Nested', declaration['offset'])
        nested_definition = one(nodes, 'DW_TAG_structure_type', 'outer::Counter::Nested', unit['offset'])
        assert reference(nested_definition, 'DW_AT_specification', nodes) is nested_declaration
        assert nested_definition['attributes']['DW_AT_declaration'] == '1'
        assert 'DW_AT_byte_size' not in nested_definition['attributes']
        pairs.append((one(nodes, 'DW_TAG_subprogram', 'outer::Counter::Nested::static_method', unit['offset']),
            one(nodes, 'DW_TAG_subprogram', 'static_method', nested_definition['offset']), False))
    for root, method, has_object in pairs:
        assert reference(root, 'DW_AT_specification', nodes) is method
        assert method['attributes']['DW_AT_declaration'] == '1'
        assert not {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges'} & method['attributes'].keys()
        assert reference(root, 'DW_AT_type', nodes) is reference(method, 'DW_AT_type', nodes)
        assert ('DW_AT_object_pointer' in root['attributes']) == has_object
        assert ('DW_AT_object_pointer' in method['attributes']) == has_object
        for owner in [root, method]:
            if not has_object:
                continue
            parameter = reference(owner, 'DW_AT_object_pointer', nodes)
            assert parameter['parent'] == owner['offset'] and parameter['tag'] == 'DW_TAG_formal_parameter'
            assert parameter['attributes']['DW_AT_artificial'] == '1'
            pointer = reference(parameter, 'DW_AT_type', nodes)
            while pointer['tag'] in ['DW_TAG_typedef', 'DW_TAG_const_type', 'DW_TAG_volatile_type']:
                pointer = reference(pointer, 'DW_AT_type', nodes)
            assert pointer['tag'] == 'DW_TAG_pointer_type'
            assert reference(pointer, 'DW_AT_type', nodes) is definition
    return unit, definition, alias, pairs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('info', type=Path)
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--failed', action='store_true')
    parser.add_argument('--variant', choices=['normal', 'collision', 'ambiguous'], default='normal')
    args = parser.parse_args()
    nodes = objects.read_dies(args.info.read_text())
    unit, definition, alias, pairs = check(nodes, args.isolated, args.failed, args.variant)
    mutations = [(definition['offset'], 'DW_AT_specification', unit['offset']),
        (alias['offset'], 'DW_AT_type', unit['offset'])]
    for root, method, has_object in pairs:
        mutations.append((root['offset'], 'DW_AT_specification', definition['offset']))
        if has_object:
            mutations.append((method['offset'], 'DW_AT_object_pointer', reference(root, 'DW_AT_object_pointer', nodes)['offset']))
    for offset, attr, target in mutations:
        broken = copy.deepcopy(nodes)
        broken[offset]['attributes'][attr] = '<0x%x>' % target
        try:
            check(broken, args.isolated, args.failed, args.variant)
        except (AssertionError, KeyError, ValueError):
            continue
        raise AssertionError('wrong ownership/reference accepted')
    print('class-scopes-DIE=PASS methods=%d negative-controls=%d' % (len(pairs), len(mutations)))


if __name__ == '__main__':
    main()

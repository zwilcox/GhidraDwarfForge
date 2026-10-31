#!/usr/bin/env python3
"""Check actual object references, including ordinary parameters named this."""
import argparse
import re
from pathlib import Path


def read_dies(text):
    nodes, stack = {}, {}
    for entry in re.split(r'(?m)(?=^ <\d+><[0-9a-f]+>:)', text):
        match = re.match(r' <(\d+)><([0-9a-f]+)>: Abbrev Number: (\d+)(?: \((DW_TAG_\w+)\))?', entry)
        if not match:
            continue
        depth, offset, abbreviation, tag = match.groups()
        depth, offset = int(depth), int(offset, 16)
        stack = {d: node for d, node in stack.items() if d < depth}
        if abbreviation == '0':
            continue
        attributes = dict(re.findall(r'(?m)^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$', entry))
        node = {'offset': offset, 'tag': tag, 'parent': stack.get(depth - 1),
            'attributes': attributes, 'name': attributes.get('DW_AT_name', '').rsplit(': ', 1)[-1]}
        nodes[offset] = node
        stack[depth] = offset
    return nodes


def check(nodes, isolated, failed):
    method_name = 'Counter::method' if isolated else 'recovered::Counter::inspect_object'
    ordinary_name = 'ordinary' if isolated else 'ordinary_object'
    by_name = {node['name']: node for node in nodes.values() if node['tag'] == 'DW_TAG_subprogram'}
    method, ordinary = by_name[method_name], by_name[ordinary_name]
    expected = [] if failed else [method]
    if isolated:
        external = by_name['Counter::external']
        assert 'DW_AT_declaration' in external['attributes']
        assert 'DW_AT_low_pc' not in external['attributes'] and 'DW_AT_ranges' not in external['attributes']
        expected.append(external)
    owners = [node for node in nodes.values() if 'DW_AT_object_pointer' in node['attributes']]
    assert {node['offset'] for node in owners} == {node['offset'] for node in expected}
    for owner in owners:
        reference, = re.findall(r'<0x([0-9a-f]+)>', owner['attributes']['DW_AT_object_pointer'])
        parameter = nodes[int(reference, 16)]
        assert parameter['parent'] == owner['offset'] and parameter['tag'] == 'DW_TAG_formal_parameter'
        assert parameter['name'] == ('receiver' if isolated else 'this')
        assert parameter['attributes']['DW_AT_artificial'] == '1'
        assert 'DW_AT_type' in parameter['attributes']
    ordinary_parameters = [node for node in nodes.values() if node['parent'] == ordinary['offset'] and
        node['tag'] == 'DW_TAG_formal_parameter']
    assert len(ordinary_parameters) == 1 and ordinary_parameters[0]['name'] == 'this'
    assert 'DW_AT_artificial' not in ordinary_parameters[0]['attributes']
    if failed:
        assert not any(node['parent'] == method['offset'] for node in nodes.values())
        assert 'DW_AT_type' not in method['attributes']
    return owners, ordinary_parameters[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('info', type=Path)
    parser.add_argument('--isolated', action='store_true')
    parser.add_argument('--failed', action='store_true')
    args = parser.parse_args()
    text = args.info.read_text()
    nodes = read_dies(text)
    owners, ordinary = check(nodes, args.isolated, args.failed)
    controls = 0
    for owner in owners:
        original = owner['attributes']['DW_AT_object_pointer']
        for target in [ordinary['offset'], owner['offset']]:
            owner['attributes']['DW_AT_object_pointer'] = '<0x%x>' % target
            try:
                check(nodes, args.isolated, args.failed)
            except AssertionError:
                controls += 1
            else:
                raise AssertionError('wrong object target accepted')
        owner['attributes']['DW_AT_object_pointer'] = original
    print('object-parameter-DIE=PASS references=%d negative-controls=%d' % (len(owners), controls))


if __name__ == '__main__':
    main()

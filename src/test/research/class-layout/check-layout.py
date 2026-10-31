#!/usr/bin/env python3
"""Require the selected class declaration/specification/object reference tree."""
import argparse
import copy
from pathlib import Path
import re
import runpy


def reference(node, attribute):
    value, = re.findall(r'<0x([0-9a-f]+)>', node['attributes'][attribute])
    return int(value, 16)


def check(nodes, qualified_class):
    definition, = [node for node in nodes.values() if node['tag'] == 'DW_TAG_subprogram' and
        node['name'] == 'recovered::Counter::inspect_scope' and 'DW_AT_specification' in node['attributes']]
    assert nodes[definition['parent']]['tag'] == 'DW_TAG_compile_unit'
    declaration = nodes[reference(definition, 'DW_AT_specification')]
    assert declaration['tag'] == 'DW_TAG_subprogram' and declaration['name'] == 'inspect_scope'
    assert declaration['attributes']['DW_AT_declaration'] == '1'
    assert 'DW_AT_low_pc' not in declaration['attributes'] and 'DW_AT_ranges' not in declaration['attributes']
    owner = nodes[declaration['parent']]
    assert owner['tag'] in ('DW_TAG_structure_type', 'DW_TAG_class_type')
    assert owner['name'] == ('recovered::Counter' if qualified_class else 'Counter')
    namespace = nodes[owner['parent']]
    assert namespace['tag'] == 'DW_TAG_namespace' and namespace['name'] == 'recovered'
    for method in [declaration, definition]:
        assert 'DW_AT_linkage_name' not in method['attributes']
        parameter = nodes[reference(method, 'DW_AT_object_pointer')]
        assert parameter['tag'] == 'DW_TAG_formal_parameter' and parameter['parent'] == method['offset']
        assert parameter['attributes']['DW_AT_artificial'] == '1'
    return definition, declaration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('info', type=Path)
    parser.add_argument('--qualified-class', action='store_true')
    args = parser.parse_args()
    integration = Path(__file__).resolve().parents[2] / 'integration/check-object-parameters.py'
    read_dies = runpy.run_path(str(integration))['read_dies']
    nodes = read_dies(args.info.read_text())
    definition, declaration = check(nodes, args.qualified_class)
    controls = []
    bad = copy.deepcopy(nodes)
    bad[definition['offset']]['attributes']['DW_AT_specification'] = '<0x%x>' % definition['offset']
    controls.append(bad)
    bad = copy.deepcopy(nodes)
    bad[declaration['offset']]['parent'] = definition['parent']
    controls.append(bad)
    for bad in controls:
        try:
            check(bad, args.qualified_class)
        except AssertionError:
            continue
        raise AssertionError('invalid ownership/reference accepted')
    print('class-layout-tree=PASS negative-controls=2')


if __name__ == '__main__':
    main()

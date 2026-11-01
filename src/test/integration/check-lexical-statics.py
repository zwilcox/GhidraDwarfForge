#!/usr/bin/env python3
"""Require exact static identity, lexical parenting and visibility bounds in raw DIEs."""
import copy
import importlib.util
import json
from pathlib import Path
import re
import sys

spec = importlib.util.spec_from_file_location('classes', Path(__file__).with_name('check-class-scopes.py'))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
case = Path(sys.argv[1])
labels = json.loads((case / 'labels.json').read_text())
objects = json.loads((case / 'compiler-objects.json').read_text())
mode = sys.argv[2] if len(sys.argv) > 2 else 'forge'


def check(nodes):
    unit, = [n for n in nodes.values() if n['tag'] == 'DW_TAG_compile_unit']
    owners = {'global': unit, 'root': helper.one(nodes, 'DW_TAG_subprogram', 'scoped_statics', unit['offset']),
        'other': helper.one(nodes, 'DW_TAG_subprogram', 'other_statics', unit['offset'])}
    blocks = [n for n in nodes.values() if n['tag'] == 'DW_TAG_lexical_block']
    assert len(blocks) == (0 if mode in ['coalesced', 'failed', 'memory-stale', 'memory-failed'] else 3)
    for name in ([] if mode in ['coalesced', 'failed', 'memory-stale', 'memory-failed'] else ['outer', 'inner', 'sibling']):
        block, = [n for n in blocks if int(n['attributes']['DW_AT_low_pc'], 0) == labels[name + '_begin']]
        assert int(block['attributes']['DW_AT_high_pc'], 0) + labels[name + '_begin'] == labels[name + '_end']
        assert block['parent'] == owners['outer' if name == 'inner' else 'root']['offset']
        owners[name] = block
    variables = [n for n in nodes.values() if n['tag'] == 'DW_TAG_variable' and n['name'] == 'shadow']
    omitted = {'stale': {'inner'}, 'conflict': {'inner', 'sibling'},
        'coalesced': {'inner', 'outer', 'sibling'}, 'failed': {'root', 'inner', 'outer', 'sibling'},
        'memory-stale': {'root', 'inner', 'outer', 'sibling'}, 'memory-failed': {'root', 'inner', 'outer', 'sibling'},
        'inferred-stale': {'other'}, 'inferred-namespace': {'other'}, 'inferred-overlap': {'other'}}.get(mode, set())
    assert len(variables) == 6 - len(omitted)
    for name, owner in owners.items():
        if name in omitted:
            assert not any(v['parent'] == owner['offset'] for v in variables)
            continue
        variable = helper.one(nodes, 'DW_TAG_variable', 'shadow', owner['offset'])
        address, = re.findall(r'DW_OP_addr: ([0-9a-f]+)', variable['attributes']['DW_AT_location'])
        assert int(address, 16) == objects[name], (name, address, objects)
        if mode.startswith('memory') or mode.startswith('inferred'):
            same_address = [n for n in nodes.values() if n['tag'] == 'DW_TAG_variable' and
                any(int(value, 16) == objects[name] for value in re.findall(r'DW_OP_addr: ([0-9a-f]+)',
                    n['attributes'].get('DW_AT_location', '')))]
            assert len(same_address) == 1, ('duplicate local/global memory declaration', name, same_address)
        assert 'DW_AT_declaration' not in variable['attributes']
        typ = helper.reference(variable, 'DW_AT_type', nodes)
        assert typ['tag'] == 'DW_TAG_base_type' and int(typ['attributes']['DW_AT_byte_size']) == 4
        assert ('(unsigned)' if mode == 'inferred-curated' and name == 'other' else '(signed)') in typ['attributes']['DW_AT_encoding']
    return owners


nodes = helper.objects.read_dies((case / ('info.log' if mode == 'forge' else mode + '-info.log')).read_text())
owners = check(nodes)
if mode != 'forge':
    print('lexical-statics-dies=' + mode + ' PASS')
    sys.exit(0)
mutations = []
broken = copy.deepcopy(nodes)
inner = helper.one(broken, 'DW_TAG_variable', 'shadow', owners['inner']['offset'])
inner['parent'] = owners['outer']['offset']
mutations.append(broken)
broken = copy.deepcopy(nodes)
broken[owners['inner']['offset']]['attributes']['DW_AT_high_pc'] = str(labels['outer_end'] - labels['inner_begin'])
mutations.append(broken)
broken = copy.deepcopy(nodes)
inner = helper.one(broken, 'DW_TAG_variable', 'shadow', owners['inner']['offset'])
inner['attributes']['DW_AT_location'] = 'DW_OP_addr: %x' % objects['outer']
mutations.append(broken)
for broken in mutations:
    try:
        check(broken)
    except (AssertionError, KeyError, ValueError):
        continue
    raise AssertionError('incorrect static identity or scope accepted')
print('lexical-statics-dies=PASS negative-controls=' + str(len(mutations)))

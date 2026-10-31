#!/usr/bin/env python3
"""Independently check emitted lexical DIE ownership and fixture scope bounds."""
import json
from pathlib import Path
import re
import sys


def check(text, labels):
    entries = re.split(r'(?m)(?=^ <\d+><[0-9a-f]+>:)', text)
    stack = {}
    blocks = []
    variables = []
    for entry in entries:
        header = re.match(r' <(\d+)><([0-9a-f]+)>: Abbrev Number: (\d+)(?: \((DW_TAG_\w+)\))?', entry)
        if not header:
            continue
        depth, offset, abbreviation, tag = header.groups()
        depth, offset = int(depth), int(offset, 16)
        stack = {d: node for d, node in stack.items() if d < depth}
        if abbreviation == '0':
            continue
        parent = stack.get(depth - 1)
        name = re.search(r'DW_AT_name\s+: .*?([^:]+)$', entry, re.M)
        name = name.group(1).strip() if name else None
        node = {'tag': tag, 'offset': offset, 'name': name, 'parent': parent}
        stack[depth] = node
        if tag == 'DW_TAG_lexical_block':
            low = re.findall(r'DW_AT_low_pc\s+: (0x[0-9a-f]+)', entry)
            high = re.findall(r'DW_AT_high_pc\s+: (\d+)', entry)
            assert len(low) == len(high) == 1 and 'DW_AT_ranges' not in entry
            node['start'] = int(low[0], 16)
            node['end'] = node['start'] + int(high[0])
            blocks.append(node)
        if tag == 'DW_TAG_variable' and name == 'shadow':
            assert 'DW_AT_location' in entry and 'DW_AT_type' in entry
            variables.append(node)
    assert len(blocks) == len(variables) == 2
    outer, inner = blocks
    assert outer['parent']['tag'] == 'DW_TAG_subprogram' and outer['parent']['name'] == 'scoped'
    assert inner['parent'] is outer
    for block, label in [(outer, 'outer'), (inner, 'inner')]:
        assert (block['start'], block['end']) == (labels[label + '_begin'], labels[label + '_end'])
        assert sum(variable['parent'] is block for variable in variables) == 1
    assert 'shadow_1' not in text


case = Path(sys.argv[1])
text = (case / 'info.log').read_text()
labels = json.loads((case / 'labels.json').read_text())
check(text, labels)
for key in ['inner_begin', 'inner_end', 'outer_begin', 'outer_end']:
    bad = dict(labels)
    bad[key] += 1
    try:
        check(text, bad)
    except AssertionError:
        continue
    raise AssertionError('accepted incorrect ' + key)
print('lexical-shadow-DIE=PASS negative-controls=4')

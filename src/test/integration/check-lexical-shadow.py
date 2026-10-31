#!/usr/bin/env python3
"""Independently check emitted lexical DIE ownership and fixture scope bounds."""
import json
from pathlib import Path
import re
import sys


def lists(text):
    result = {}
    offset = None
    ranges = []
    for line in text.splitlines():
        row = re.fullmatch(r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)(?:\s+.*)?', line)
        if row:
            current, start, end = [int(value, 16) for value in row.groups()]
            if offset is None:
                offset = current
            assert start < end
            ranges.append((start, end))
        elif '<End of list>' in line:
            assert offset is not None and offset not in result
            result[offset] = ranges
            offset, ranges = None, []
    assert offset is None
    return result


def check(text, labels, ranges, locations):
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
            offsets = re.findall(r'DW_AT_ranges\s+: (0x[0-9a-f]+)', entry)
            if offsets:
                assert len(offsets) == 1 and not low and not high
                node['ranges'] = ranges[int(offsets[0], 16)]
            else:
                assert len(low) == len(high) == 1
                start = int(low[0], 16)
                node['ranges'] = [(start, start + int(high[0]))]
            blocks.append(node)
        if tag == 'DW_TAG_variable' and name == 'shadow':
            assert 'DW_AT_location' in entry and 'DW_AT_type' in entry
            offset = re.findall(r'DW_AT_location\s+: (0x[0-9a-f]+) \(location list\)', entry)
            assert len(offset) == 1
            node['locations'] = locations[int(offset[0], 16)]
            variables.append(node)
    assert len(blocks) == len(variables) == 2
    outer, inner = blocks
    assert outer['parent']['tag'] == 'DW_TAG_subprogram' and outer['parent']['name'] == 'scoped'
    assert inner['parent'] is outer
    for block, label in [(outer, 'outer'), (inner, 'inner')]:
        expected = [(labels[label + '_begin'], labels[label + '_end'])]
        if label == 'inner' and 'inner_gap_begin' in labels:
            expected = [(labels['inner_begin'], labels['inner_gap_begin']), (labels['inner_gap_end'], labels['inner_end'])]
        assert block['ranges'] == expected
        assert sum(variable['parent'] is block for variable in variables) == 1
        variable = next(variable for variable in variables if variable['parent'] is block)
        for start, end in variable['locations']:
            assert any(low <= start < end <= high for low, high in expected)
            assert start >= labels[label + '_live'], 'location before initialization'
    assert 'shadow_1' not in text


case = Path(sys.argv[1])
text = (case / 'info.log').read_text()
labels = json.loads((case / 'labels.json').read_text())
ranges, locations = lists((case / 'Ranges.log').read_text()), lists((case / 'loc.log').read_text())
check(text, labels, ranges, locations)
keys = ['inner_begin', 'inner_end', 'outer_begin', 'outer_end']
if 'inner_gap_begin' in labels:
    keys += ['inner_gap_begin', 'inner_gap_end']
for key in keys:
    bad = dict(labels)
    bad[key] += 1
    try:
        check(text, bad, ranges, locations)
    except AssertionError:
        continue
    raise AssertionError('accepted incorrect ' + key)
print('lexical-shadow-DIE=PASS negative-controls=' + str(len(keys)))

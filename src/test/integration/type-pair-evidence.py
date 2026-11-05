"""Independent raw-DIE oracle for the isolated producer's paired type reports."""
from collections import Counter
import json
import re


def inspect(case, parse_dies):
    states, reports = {}, {}
    for phase in ('before', 'after', 'unattached'):
        report = json.loads((case / f'type-{phase}.dbg.report.json').read_text())
        reports[phase] = report
        coverage = report['coverage']
        assert coverage['definitionVersion'] == 2
        entries = parse_dies((case / f'type-{phase}-info.log').read_text())
        function, = [node for node in entries.values() if node['tag'] == 'DW_TAG_subprogram']
        assert function['name'] == 'observed'
        types = {}
        for key, name in [('a', 'PayloadA'), ('b', 'PayloadB'), ('u64', 'uint64_t')]:
            node, = [node for node in entries.values() if node['name'] == name and node['tag'].endswith('_type')]
            types[key] = node
        assert len([node for node in entries.values() if node['tag'].endswith('_type')]) == 3
        inverse = {node['offset']: key for key, node in types.items()}
        raw_roots = ([function['type']] if function['type'] is not None else [])
        raw_roots += [child['type'] for child in function['children'] if child['type'] is not None]
        attached = set(raw_roots)
        edges = {}
        for key, node in types.items():
            edges[key] = ([node['type']] if node['type'] is not None else [])
            edges[key] += [child['type'] for child in node['children'] if child['type'] is not None]
        pending = list(attached)
        while pending:
            for target in edges[inverse[pending.pop()]]:
                if target not in attached:
                    attached.add(target)
                    pending.append(target)
        states[phase] = {
            key: ('NOT_EMITTED' if node['offset'] not in attached else
                  'OPAQUE' if node['tag'] == 'DW_TAG_unspecified_type' else 'RESOLVED')
            for key, node in types.items()
        }
        nodes = {node['key']: node for node in coverage['typeNodes']}
        assert nodes.keys() == types.keys()
        for key, node in types.items():
            opaque = node['tag'] == 'DW_TAG_unspecified_type'
            assert nodes[key]['kind'] == ('OPAQUE' if opaque else 'RESOLVED')
            assert nodes[key]['emitted'] == 'YES', 'allocated types are distinct from function attachment'
            counts = Counter(inverse[offset] for offset in edges[key])
            for field in ('emittedReferences', 'recoveredReferences'):
                assert {item['key']: int(item['count']) for item in nodes[key][field]} == counts
            if key != 'u64':
                resolved = key == ('a' if phase == 'before' else 'b')
                assert node['tag'] == ('DW_TAG_structure_type' if resolved else 'DW_TAG_unspecified_type')
                assert len(node['children']) == (1 if resolved else 0)
                if resolved:
                    member, = node['children']
                    assert member['name'] == 'value' and member['type'] == types['u64']['offset']
                    assert member['attributes']['data_member_location'] == '0'
        roots, = coverage['functionTypeRoots']
        assert roots['recovered'] == ['a', 'b', 'u64']
        assert roots['emitted'] == sorted(set(inverse[offset] for offset in raw_roots))
        row, = coverage['functions']
        assert int(row['entry'], 16) == int(function['attributes']['low_pc'], 16)
        tally = Counter(states[phase].values())
        assert row['types']['resolvedEmittedNodes'] == str(tally['RESOLVED'])
        assert row['types']['opaqueEmittedNodes'] == str(tally['OPAQUE'])
        assert row['types']['notEmittedNodes'] == str(tally['NOT_EMITTED'])
        assert coverage['summary']['functionTypes'] == row['types']
        if phase == 'unattached':
            assert function['type'] is None and not function['children']
            assert report['status'] == 'PARTIAL'
        else:
            assert {child['name'] for child in function['children']} == {'x', 'payload_a', 'payload_b'}
            assert all('location' not in child['attributes'] for child in function['children'])
    assert reports['before']['coverage']['summary'] == reports['after']['coverage']['summary'], 'offsetting changes keep totals equal'
    for before, after in [('before', 'after'), ('after', 'before'), ('after', 'unattached'), ('after', 'after')]:
        text = (case / f'type-compare-{before}-{after}.log').read_text()
        actual = re.findall(r'^TYPE_STATE_CHANGED\t(0x[0-9a-f]+)\t([^\n]+)$', text, re.M)
        entry = reports[after]['coverage']['functions'][0]['entry']
        expected = [(entry, f'{key}: {states[before][key]} -> {states[after][key]}') for key in sorted(types)
                    if states[before][key] != states[after][key]]
        assert actual == expected, (before, after, actual, expected)
        assert 'Comparison: matching reported binary/profile' in text
        if before == after:
            assert 'Reported changes: 0;' in text
        elif after != 'unattached':
            assert 'TYPE_COUNTS_CHANGED' not in text
    return {'phases': 3, 'deterministicExports': 6, 'comparisons': 4, 'statesFromRawDwarf': states}

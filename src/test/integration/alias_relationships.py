"""Check that alias metadata adds only addressless references to existing DIEs."""
import json
from pathlib import Path
import re
import subprocess


def read_dies(artifact, log):
    result = subprocess.run(['readelf', '--debug-dump=info', str(artifact)],
        capture_output=True, text=True, check=True, timeout=60)
    Path(log).write_text(result.stdout)
    assert not result.stderr and 'Warning:' not in result.stdout
    rows = []
    current = None
    for line in result.stdout.splitlines():
        header = re.match(r'^\s*<(\d+)><([0-9a-f]+)>: Abbrev Number: \d+(?: \((DW_TAG_\w+)\))?', line)
        if header:
            current = None
            if header[3]:
                current = {'depth': int(header[1]), 'offset': int(header[2], 16), 'tag': header[3], 'attrs': {}}
                rows.append(current)
        elif current is not None:
            attr = re.match(r'^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)', line)
            if attr:
                assert attr[1] not in current['attrs']
                current['attrs'][attr[1]] = attr[2]
    assert rows and rows[0]['tag'] == 'DW_TAG_compile_unit'
    return rows


def value(text):
    # readelf exposes the string-table offset, which may move when names are added.
    return re.sub(r'^\((?:indirect string|indirect line string), offset: [^)]+\): ', '', text)


def check_alias_relationships(case, expected):
    """expected maps each new alias to its canonical code entry (without ARM's mode bit)."""
    baseline = read_dies(case / 'baseline.dbg', case / 'baseline-relations-info.log')
    actual = read_dies(case / 'automatic.dbg', case / 'automatic-relations-info.log')
    imports = [row for row in actual if row['tag'] == 'DW_TAG_imported_declaration']
    new = [row for row in imports if value(row['attrs'].get('DW_AT_name', '')) in expected]
    assert len(new) == len(expected)
    by_offset = {row['offset']: row for row in actual}
    for row in new:
        assert row['depth'] == 1
        assert set(row['attrs']) == {'DW_AT_name', 'DW_AT_import'}, 'alias must not own a type, source or address'
        ref = re.match(r'^<0x([0-9a-f]+)>', row['attrs']['DW_AT_import'])
        assert ref
        target = by_offset[int(ref[1], 16)]
        assert target['tag'] == 'DW_TAG_subprogram' and 'DW_AT_declaration' not in target['attrs']
        assert int(target['attrs']['DW_AT_low_pc'], 16) == expected[value(row['attrs']['DW_AT_name'])]
    removed = {row['offset'] for row in new}
    remaining = [row for row in actual if row['offset'] not in removed]

    def canonical(rows):
        offsets = {row['offset']: index for index, row in enumerate(rows)}
        result = []
        for row in rows:
            attrs = {}
            for key, text in row['attrs'].items():
                if key == 'DW_AT_sibling':
                    # DIE insertion changes sibling links. Tree depth is compared below,
                    # and independent validators check serialized sibling references.
                    continue
                text = value(text)
                reference = re.match(r'^<0x([0-9a-f]+)>(.*)$', text)
                if reference:
                    target = int(reference[1], 16)
                    assert target in offsets, 'existing declaration must not acquire an alias dependency'
                    text = ['DIE', offsets[target]]
                attrs[key] = text
            result.append([row['depth'], row['tag'], attrs])
        return result

    assert canonical(baseline) == canonical(remaining), 'aliases changed an existing DIE or duplicated its body'
    result = {'status': 'PASS', 'aliases': expected, 'unchangedExistingDies': len(baseline),
        'newAddresslessImports': len(new)}
    (case / 'alias-relationships.json').write_text(json.dumps(result, indent=4) + '\n')
    return result

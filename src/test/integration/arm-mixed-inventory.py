#!/usr/bin/env python3
"""Audit sectionless mixed-mode additions against original compiler ELF evidence."""
import importlib.util
import json
from pathlib import Path

source = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, source / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


facts = module('mixed_inventory_facts', 'arm-thumb-mode-check.py')
inventory = module('mixed_sectionless_inventory', 'sectionless-alias-check.py')


def verify(case):
    labels = json.loads((case / 'labels.json').read_text())
    assert labels['sectionless']
    reference = facts.elf(case / 'mixed.reference')
    output = facts.elf(case / 'curated.dbg')
    allocation = facts.section(output, labels['mappingAllocation'])
    index, start = allocation['index'], labels['start']
    mappings = {f'${mode}.forge_{index:x}_{start + offset:08x}': (start + offset, index)
                for mode, offset in (('a', 0), ('t', 16), ('a', 24), ('d', 40))}
    aliases, values, modes_checked = [], {}, []
    # These auxiliary homogeneous hints are not the mixed-body acceptance
    # target. Check every supplied hint against compiler mode intervals, without
    # treating output-derived sizes as an independent completeness oracle.
    for symbol in output['symbols']:
        if not symbol['name'].startswith('__forge_arm_mode_'):
            continue
        address, size = symbol['raw'] & ~1, symbol['size']
        assert symbol['info'] == 2 and symbol['other'] == 0 and size > 0
        assert symbol['name'] == f'__forge_arm_mode_{address:08x}'
        original, = [section for section in reference['sections']
            if section['row'][2] & 6 == 6 and section['row'][3] <= address
            and address + size <= section['row'][3] + section['row'][5]]
        mode = '$t' if symbol['raw'] & 1 else '$a'
        alignment = 2 if mode == '$t' else 4
        assert address % alignment == size % alignment == 0
        boundaries = sorted((row['raw'], row['name'].split('.')[0])
            for row in reference['symbols'] if row['section'] == original['index']
            and row['name'].split('.')[0] in ('$a', '$t', '$d'))
        preceding = [row for row in boundaries if row[0] <= address]
        assert preceding and preceding[-1][1] == mode
        assert all(tag == mode for at, tag in boundaries if address < at < address + size)
        aliases.append({'alias': symbol['name'], 'entry': address, 'size': size})
        values[symbol['name']] = symbol['raw']
        modes_checked.append({'address': address, 'size': size, 'mode': mode,
                              'originalSection': original['name']})
    assert aliases, 'fixture must retain auxiliary homogeneous mode hints'
    result = inventory.verify(case / 'mixed.sectioned', case / 'mixed.stripped',
        case / 'curated.dbg', aliases, case / 'raw-inventory.json', values, mappings)
    inventory.corruption_controls(case / 'mixed.sectioned', case / 'mixed.stripped',
        case / 'curated.dbg', aliases, case / 'inventory-negative-controls', values, mappings)
    (case / 'compiler-mode-inventory.json').write_text(json.dumps({
        'status': 'PASS', 'homogeneousModeChecks': modes_checked,
        'requiredMixedMappings': mappings, 'inheritedRecords': result['originalRecords'],
    }, indent=4) + '\n')


if __name__ == '__main__':
    import sys
    verify(Path(sys.argv[1]).resolve())

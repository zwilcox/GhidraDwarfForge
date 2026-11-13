#!/usr/bin/env python3
"""Compare Forge-produced inheritance DIEs against this fixture's compiler evidence."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('object_checker', HERE.parents[1] / 'integration/check-object-parameters.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
CLASSES = ['Base', 'Single', 'Left', 'Right', 'Multiple', 'VirtualBase', 'VirtualLeft', 'VirtualRight', 'Diamond']
GLOBALS = {'single_base': 'Base', 'single_object': 'Single', 'multiple_right': 'Right', 'multiple_object': 'Multiple',
    'diamond_base': 'VirtualBase', 'diamond_right': 'VirtualRight', 'diamond_object': 'Diamond',
    'virtual_left_object': 'VirtualLeft', 'virtual_right_object': 'VirtualRight'}


def text(value):
    return re.sub(r'^\([^)]*\)\s*', '', value.rsplit(': ', 1)[-1]).strip()


def number(value):
    return int(text(value).split()[0], 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--classpath', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=('x86_64', 'aarch64'), default=['x86_64', 'aarch64'])
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    references = args.references.resolve(strict=True)
    commands, observations, controls = [], [], []
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java')
    classpath = args.classpath.read_text().strip()

    def run(label, command):
        argv = list(map(str, command))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=150, check=True)
        return (root / (label + '.log')).read_text()

    for target in args.targets:
        for role in ('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'):
            label = target + '-' + role
            ref = references / label
            case = root / label
            case.mkdir()
            runtime = case / 'runtime.elf'
            shutil.copy2(ref / 'runtime.elf', runtime)
            original = hashlib.sha256(runtime.read_bytes()).hexdigest()
            info = run(label + '-compiler-info', ['readelf', '-W', '--debug-dump=info', ref / 'reference.elf'])
            nodes = checker.read_dies(info)
            classes = {text(n['attributes']['DW_AT_name']): n for n in nodes.values()
                if n['tag'] == 'DW_TAG_structure_type' and 'DW_AT_byte_size' in n['attributes']}
            assert set(CLASSES) <= classes.keys()
            symbols = run(label + '-compiler-symbols', ['readelf', '-Ws', ref / 'reference.elf'])
            inventory = {name: (int(address, 16), int(size), int(index)) for address, size, index, name in re.findall(
                r'^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(\d+)\s+(\S+)\s*$', symbols, re.M)}
            layout = run(label + '-compiler-sections', ['readelf', '-SW', runtime])
            sections = {int(index): (name, int(address, 16)) for index, name, address in
                re.findall(r'\[\s*(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s', layout)}
            model = {'abi': 'ITANIUM_X86_64' if target == 'x86_64' else 'ITANIUM_AARCH64',
                'classes': [], 'bases': [], 'methods': [], 'globals': []}
            occupied = {}
            for class_id, name in enumerate(CLASSES, 1):
                node = classes[name]
                children = [n for n in nodes.values() if n['parent'] == node['offset']]
                members = []
                for child in children:
                    attrs = child['attributes']
                    if child['tag'] == 'DW_TAG_member':
                        member = text(attrs['DW_AT_name'])
                        vptr = member.startswith('_vptr.')
                        members.append({'name': member, 'offset': number(attrs['DW_AT_data_member_location']), 'vptr': vptr})
                    if child['tag'] == 'DW_TAG_subprogram' and 'DW_AT_vtable_elem_location' in attrs:
                        slot, = re.findall(r'DW_OP_constu: (\d+)', attrs['DW_AT_vtable_elem_location'])
                        linkage = text(attrs['DW_AT_linkage_name'])
                        method = {'owner': name, 'name': text(attrs['DW_AT_name']), 'slot': int(slot), 'id': child['offset'] + 1000}
                        if linkage in inventory:
                            address, size, _ = inventory[linkage]
                            method.update(address=address, size=size)
                        model['methods'].append(method)
                occupied[name] = max((m['offset'] + (8 if m['vptr'] else 4) for m in members), default=0)
                model['classes'].append({'name': name, 'id': class_id, 'size': number(node['attributes']['DW_AT_byte_size']), 'members': members})
            for name in CLASSES:
                children = [n for n in nodes.values() if n['parent'] == classes[name]['offset'] and n['tag'] == 'DW_TAG_inheritance']
                for order, child in enumerate(children):
                    attrs = child['attributes']
                    offset, = re.findall(r'<0x([0-9a-f]+)>', attrs['DW_AT_type'])
                    parent = text(nodes[int(offset, 16)]['attributes']['DW_AT_name'])
                    virtual = 'DW_AT_virtuality' in attrs
                    row = {'derived': name, 'base': parent, 'order': order, 'virtual': virtual}
                    if virtual:
                        expression = attrs['DW_AT_data_member_location']
                        slot, = re.findall(r'DW_OP_dup; DW_OP_deref; DW_OP_lit(\d+); DW_OP_minus; DW_OP_deref; DW_OP_plus', expression)
                        row['slotOffset'] = -int(slot)
                    else:
                        row.update(offset=number(attrs['DW_AT_data_member_location']), occupiedBytes=occupied[parent])
                    model['bases'].append(row)
            for name, kind in GLOBALS.items():
                address, size, _ = inventory[name]
                assert size == 8
                model['globals'].append({'name': name, 'type': kind, 'address': address})
            address, size, _ = inventory['inheritance_checkpoint']
            model['checkpoint'] = {'address': address, 'size': size}
            model_path = case / 'model.json'
            model_path.write_text(json.dumps(model, indent=4) + '\n')
            produced = case / 'producer.dbg'
            result = run(label + '-produce', [java, '-cp', classpath, 'ghidradwarfforge.nativeapi.InheritanceProducerProbe',
                os.environ['LIBDWARF'], os.environ['LIBDWARFP'], runtime, model_path, produced])
            assert 'inheritance-producer=PASS' in result
            vtables = []
            for name, (address, size, index) in inventory.items():
                if re.fullmatch(r'_ZTV\d+(?:' + '|'.join(CLASSES) + ')', name):
                    section, base = sections[index]
                    vtables.append({'name': name, 'address': address, 'size': size, 'section': section, 'sectionAddress': base})
            table_path = case / 'vtables.json'
            table_path.write_text(json.dumps(vtables, indent=4) + '\n')
            artifact = case / 'forge-vtables.dbg'
            run(label + '-package', [java, '-cp', classpath, 'ghidradwarfforge.elf.VtablePackagingProbe',
                runtime, produced, table_path, artifact])
            verified = run(label + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
            assert 'No errors.' in verified
            checked = run(label + '-strict', [os.environ['DWARFDUMP'], artifact])
            assert not re.search(r'warning:|error:', checked, re.I)
            decoded = run(label + '-gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', artifact])
            assert not re.search(r'warning:|error:', decoded, re.I)
            emitted = checker.read_dies(decoded)
            definitions = {n['name']: n for n in emitted.values() if n['tag'] == 'DW_TAG_structure_type' and
                'DW_AT_byte_size' in n['attributes']}
            assert set(definitions) == set(CLASSES)
            for name in CLASSES:
                owner = definitions[name]['offset']
                expected_bases = [b for b in model['bases'] if b['derived'] == name]
                actual_bases = [n for n in emitted.values() if n['tag'] == 'DW_TAG_inheritance' and n['parent'] == owner]
                assert len(expected_bases) == len(actual_bases)
                for expected_base, actual_base in zip(expected_bases, actual_bases):
                    attrs = actual_base['attributes']
                    reference, = re.findall(r'<0x([0-9a-f]+)>', attrs['DW_AT_type'])
                    assert int(reference, 16) == definitions[expected_base['base']]['offset']
                    assert number(attrs['DW_AT_accessibility']) == 1
                    if expected_base['virtual']:
                        assert number(attrs['DW_AT_virtuality']) == 1
                        assert 'DW_OP_consts: ' + str(expected_base['slotOffset']) in attrs['DW_AT_data_member_location']
                    else:
                        assert number(attrs['DW_AT_data_member_location']) == expected_base['offset']
                for method in [m for m in model['methods'] if m['owner'] == name]:
                    declaration, = [n for n in emitted.values() if n['parent'] == owner and n['tag'] == 'DW_TAG_subprogram' and
                        n['name'] == method['name']]
                    attrs = declaration['attributes']
                    slot, = re.findall(r'DW_OP_constu: (\d+)', attrs['DW_AT_vtable_elem_location'])
                    assert int(slot) == method['slot'] and number(attrs['DW_AT_virtuality']) == 1
                    assert 'DW_AT_object_pointer' in attrs

            run(label + '-gdb', ['bash', HERE / 'gdb.sh', case, target, 'forge-vtables'])
            actual = json.loads((case / 'forge-vtables.gdb.json').read_text())
            expected = json.loads((ref / 'c11-vtables.gdb.json').read_text())
            for field in ('dynamicTypes', 'baseValues', 'offsets', 'inheritedValues'):
                assert actual[field] == expected[field], (field, actual[field], expected[field])
            assert hashlib.sha256(runtime.read_bytes()).hexdigest() == original
            observations.append({'target': target, 'role': role, 'observed': actual,
                'inputSha256': original, 'artifactSha256': hashlib.sha256(artifact.read_bytes()).hexdigest()})
            if role == 'exec':
                for mutation in ('fixed-base-offset', 'virtual-left-slot', 'virtual-right-slot'):
                    bad = copy.deepcopy(model)
                    if mutation == 'fixed-base-offset':
                        next(b for b in bad['bases'] if b['derived'] == 'Multiple' and b['base'] == 'Right')['offset'] = 12
                    else:
                        owner = 'VirtualLeft' if mutation == 'virtual-left-slot' else 'VirtualRight'
                        next(b for b in bad['bases'] if b['derived'] == owner)['slotOffset'] = -32
                    control = case / mutation
                    control.mkdir()
                    shutil.copy2(runtime, control / 'runtime.elf')
                    bad_model = control / 'model.json'
                    bad_model.write_text(json.dumps(bad, indent=4) + '\n')
                    bad_produced = control / 'producer.dbg'
                    bad_artifact = control / 'forge-vtables.dbg'
                    tag = label + '-' + mutation
                    run(tag + '-produce', [java, '-cp', classpath, 'ghidradwarfforge.nativeapi.InheritanceProducerProbe',
                        os.environ['LIBDWARF'], os.environ['LIBDWARFP'], control / 'runtime.elf', bad_model, bad_produced])
                    run(tag + '-package', [java, '-cp', classpath, 'ghidradwarfforge.elf.VtablePackagingProbe',
                        control / 'runtime.elf', bad_produced, table_path, bad_artifact])
                    assert 'No errors.' in run(tag + '-llvm', ['llvm-dwarfdump', '--verify', bad_artifact])
                    try:
                        run(tag + '-gdb', ['bash', HERE / 'gdb.sh', control, target, 'forge-vtables'])
                        raise AssertionError('runtime oracle accepted ' + mutation)
                    except subprocess.CalledProcessError:
                        observation = json.loads((control / 'forge-vtables.gdb.json').read_text())
                        assert observation['status'] == 'FAIL' and 'dynamicTypes' in observation and 'error' in observation
                        assert any(marker in observation['error'] for marker in
                            ('baseValues', 'inheritedValues', 'virtual baseclass botch')), observation
                    assert hashlib.sha256((control / 'runtime.elf').read_bytes()).hexdigest() == original
                    controls.append({'target': target, 'mutation': mutation, 'status': 'REJECTED_RUNTIME_MUTATION',
                        'structurallyValid': True, 'error': observation['error']})

    (root / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_INHERITANCE', 'cases': observations, 'controls': controls,
        'scope': 'production native emitter and ELF writer with compiler-supplied model; Ghidra extraction not tested'}, indent=4) + '\n')
    print('inheritance-native=PASS', root)


if __name__ == '__main__':
    main()

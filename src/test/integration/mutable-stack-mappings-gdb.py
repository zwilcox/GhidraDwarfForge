"""Check every physical instruction, updated identities and stale slot controls."""
import json
import os
import re
from pathlib import Path

import gdb

case = Path(os.environ['LOCAL_CASE'])
variant = os.environ['LOCAL_VARIANT']
target = os.environ['LOCAL_TARGET']
remote = os.environ.get('LOCAL_REMOTE', '')
compiler = variant == 'compiler'
labels = json.loads((case / 'labels.json').read_text())
width, initial = labels['width'], labels['initial']
storage = {} if compiler else json.loads((case / 'compiler-storage.json').read_text())
locations = json.loads((case / 'locations.json').read_text()) if variant == 'forge' else {}
if target == 'aarch64':
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
input_path = case / ('local.reference' if compiler else 'local.input')
symbol_path = input_path if compiler else case / ('local.dbg' if variant == 'forge' else 'previous.dbg')
gdb.execute('file "' + str(input_path) + '"')
gdb.execute('symbol-file "' + str(symbol_path) + '"')
for name in [*labels['order'], 'navigation_control']:
    assert int(gdb.parse_and_eval('&' + name)) == labels['functions'][name]['entry']
    assert 'void (void)' in gdb.execute('ptype ' + name, to_string=True)
    gdb.execute('list ' + name)
if remote:
    gdb.execute('target remote ' + remote)


def signed(value):
    value = int(value) & ((1 << (width * 8)) - 1)
    return value - (1 << (width * 8)) if value >> (width * 8 - 1) else value


def register(number):
    if target == 'aarch64':
        assert 0 <= number <= 31
        return 'sp' if number == 31 else 'x' + str(number)
    names = ['rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    assert 0 <= number < len(names)
    return names[number]


points, returns, callee_points = [], [], []
for index, name in enumerate(labels['order']):
    row = labels['functions'][name]
    gdb.Breakpoint('*' + name, temporary=True)
    gdb.execute(('continue' if remote else 'run') if index == 0 else 'continue')
    entry = int(gdb.parse_and_eval('&' + name))
    bias = entry - row['entry']
    assert int(gdb.parse_and_eval('$pc')) == entry
    entry_stack = int(gdb.parse_and_eval('$sp'))
    choice = int(gdb.parse_and_eval('path_choice'))
    instructions = gdb.selected_inferior().architecture().disassemble(entry, row['end'] + bias - 1)
    assert instructions[0]['addr'] == entry and instructions[-1]['addr'] + instructions[-1]['length'] == row['end'] + bias
    actual_instructions = [{'address': i['addr'] - bias, 'next': i['addr'] - bias + i['length'],
        'bytes': bytes(gdb.selected_inferior().read_memory(i['addr'], i['length'])).hex()} for i in instructions]
    by_address = {i['address']: i for i in actual_instructions}
    visited = []
    logical, stack_expected, carrier_expected = initial, initial, None
    saved = name != 'mutable_unsaved'
    while True:
        runtime_address = int(gdb.parse_and_eval('$pc'))
        address = runtime_address - bias
        if 'helper' in labels and labels['helper']['entry'] <= address < labels['helper']['end']:
            assert len(callee_points) < 1000
            current = int.from_bytes(gdb.selected_inferior().read_memory(entry_stack + storage[name]['offset'], width), 'little', signed=True)
            assert current == stack_expected
            decoded, = gdb.selected_frame().architecture().disassemble(runtime_address, count=1)
            raw = bytes(gdb.selected_inferior().read_memory(runtime_address, decoded['length'])).hex()
            if not compiler:
                prepared = json.loads((case / 'prepared.json').read_text())
                matched, = [i for i in prepared['inspected_mutable_instructions'] if i['address'] == address]
                assert matched['bytes'] == raw and matched['next'] == address + decoded['length']
            callee_points.append({'function': name, 'invocation': index, 'linkPc': address,
                'next': address + decoded['length'], 'bytes': raw, 'stackValue': current})
            gdb.execute('stepi')
            continue
        if 'helper' in labels and address == row['returned']:
            carrier_expected = 909
        assert address in by_address and len(visited) < 1000
        instruction = by_address[address]
        visited.append(address)
        record = {'function': name, 'invocation': index, 'choice': choice, 'pc': runtime_address,
            'linkPc': address, 'bytes': instruction['bytes'], 'logicalValue': logical}
        if compiler and address == row['live']:
            offset = int(gdb.parse_and_eval('&value')) - entry_stack
            assert -4096 <= offset < 0
            measured = {'offset': offset, 'spOffset': int(gdb.parse_and_eval('&value')) - int(gdb.parse_and_eval('$sp'))}
            if name in storage:
                assert {key: storage[name][key] for key in measured} == measured
            else:
                storage[name] = measured
        if row['live'] <= address < row['lost']:
            current = int.from_bytes(gdb.selected_inferior().read_memory(entry_stack + storage[name]['offset'], width), 'little', signed=True)
            assert current == stack_expected, (name, hex(address), current, stack_expected)
            record['rawStack'] = current
        if carrier_expected is not None:
            backup = signed(gdb.parse_and_eval('$r10' if target == 'x86_64' else '$x9'))
            assert backup == carrier_expected, (name, hex(address), backup, carrier_expected)
            record['rawRegister'] = backup
        value = gdb.parse_and_eval('value')
        assert value.type.strip_typedefs().code == gdb.TYPE_CODE_INT and value.type.sizeof == width
        record['value'] = str(value)
        record['available'] = not value.is_optimized_out
        if compiler:
            if address in [row[key] for key in ('live', 'loaded', 'changed', 'saved', 'killed', 'reloaded', 'lost')]:
                assert not value.is_optimized_out and int(value) == stack_expected, (name, hex(address), str(value), stack_expected)
            if address in [row[key] for key in ('loaded', 'changed', 'saved', 'killed', 'reloaded', 'lost')]:
                working = gdb.parse_and_eval('working')
                assert not working.is_optimized_out and int(working) == record['rawRegister'], (name, hex(address), str(working), record)
                record['working'] = str(working)
        elif variant == 'forge':
            available = name != 'mutable_conflict' and row['live'] <= address < row['availableEnd']
            assert record['available'] == available, (name, hex(address), str(value), available)
            if available:
                assert int(value) == logical
            matches = [item for item in locations[name] if item['start'] <= address < item['end']]
            assert len(matches) == int(available)
            if matches:
                item = matches[0]
                physical = int(gdb.parse_and_eval('$' + register(item['register'])))
                if item['kind'] == 'stack':
                    physical += item['offset']
                    assert physical == entry_stack + storage[name]['offset']
                    actual = int.from_bytes(gdb.selected_inferior().read_memory(physical, width), 'little', signed=True)
                else:
                    actual = signed(physical)
                assert actual == logical
                record['locationValue'] = actual
            if not saved and row['availableEnd'] <= address < row['lost']:
                assert record['rawStack'] == initial != logical
                record['staleSlotRejected'] = True
            if name == 'mutable_conflict' and row['live'] <= address < row['lost']:
                record['conflictingOwnerRejected'] = True
        else:
            record['matchesLogical'] = record['available'] and int(value) == logical
        points.append(record)
        if address == actual_instructions[-1]['address']:
            assert int(gdb.parse_and_eval('effect_sink')) == initial + 123
            assert int(gdb.parse_and_eval('backup_sink')) == (logical if saved else initial)
            returns.append(name)
            break
        gdb.execute('stepi')
        if address == row['load']:
            carrier_expected = stack_expected
        elif address == row['update']:
            logical += 5
            carrier_expected = logical
        elif address == row['save'] and saved:
            stack_expected = logical
        elif address == row['kill']:
            carrier_expected = 909
        elif address == row['reload']:
            carrier_expected = stack_expected
        if int(gdb.parse_and_eval('$pc')) - bias == row['lost']:
            stack_expected = initial + 123
    for instruction in actual_instructions:
        address = instruction['address']
        count = choice + 2 if name == 'mutable_loop' and row['update'] <= address < row['changed'] else (
            0 if name == 'mutable_branch' and choice == 0 and row['update'] <= address < row['changed'] else 1)
        assert visited.count(address) == count, (name, choice, hex(address), visited.count(address), count)
    if compiler:
        if 'helper' in labels:
            candidates = []
            for instruction in instructions:
                if not row['call'] <= instruction['addr'] - bias < row['returned']:
                    continue
                pattern = (r'mov\s+((?:0x[0-9a-f]+)?)\(%rsp\),%[er]di' if target == 'x86_64'
                    else r'ldr\s+[xw]0, \[sp(?:, #(\d+))?\]')
                match = re.fullmatch(pattern, instruction['asm'])
                if match:
                    offset = int(match[1], 0) if match[1] else 0
                    assert offset == storage[name]['spOffset']
                    candidates.append({'definition': instruction['addr'] - bias,
                        'ready': instruction['addr'] - bias + instruction['length'],
                        'register': 5 if target == 'x86_64' else 0})
            argument, = candidates
            storage[name]['callArgument'] = argument
        if 'instructions' in storage[name]:
            assert actual_instructions == storage[name]['instructions']
        storage[name]['instructions'] = actual_instructions
    else:
        assert actual_instructions == storage[name]['instructions']
        prepared = json.loads((case / 'prepared.json').read_text())
        assert [{key: item[key] for key in ('address', 'next', 'bytes')} for item in prepared[name + '_instructions']] == actual_instructions

gdb.Breakpoint('*navigation_control', temporary=True)
gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&navigation_control'))
for command in ('next', 'step'):
    gdb.execute(command)
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
if compiler:
    (case / 'compiler-storage.json').write_text(json.dumps(storage, indent=4) + '\n')
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': points,
    'calleePoints': callee_points, 'returns': returns, 'navigation': ['next', 'step'], 'exitCode': 0}, indent=4) + '\n')
print('mutable-stack-mappings-gdb=' + variant + ' PASS')

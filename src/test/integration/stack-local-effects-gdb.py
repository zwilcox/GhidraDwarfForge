"""Observe real values, stale backups and every exported availability boundary."""
import json
import os
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


points, returns = [], []
for index, name in enumerate(labels['order']):
    row = labels['functions'][name]
    gdb.Breakpoint('*' + name, temporary=True)
    gdb.execute(('continue' if remote else 'run') if index == 0 else 'continue')
    entry = int(gdb.parse_and_eval('&' + name))
    bias = entry - row['entry']
    assert int(gdb.parse_and_eval('$pc')) == entry
    entry_stack = int(gdb.parse_and_eval('$sp'))
    instructions = gdb.selected_inferior().architecture().disassemble(entry, row['end'] + bias - 1)
    assert instructions[0]['addr'] == entry and instructions[-1]['addr'] + instructions[-1]['length'] == row['end'] + bias
    actual_instructions = []
    for instruction in instructions:
        address = instruction['addr'] - bias
        assert int(gdb.parse_and_eval('$pc')) == instruction['addr']
        raw = bytes(gdb.selected_inferior().read_memory(instruction['addr'], instruction['length'])).hex()
        actual_instructions.append({'address': address, 'next': address + instruction['length'], 'bytes': raw})
        record = {'function': name, 'pc': instruction['addr'], 'linkPc': address, 'bytes': raw}
        expected = initial
        if address >= row['after']:
            if name in ('local_partial', 'local_unknown_alias'):
                expected = initial ^ 90
            elif name == 'local_full':
                expected = initial + 123
        if compiler and address == row['live']:
            offset = int(gdb.parse_and_eval('&value')) - entry_stack
            assert -4096 <= offset < 0
            storage[name] = {'offset': offset,
                'spOffset': int(gdb.parse_and_eval('&value')) - int(gdb.parse_and_eval('$sp'))}
        if row['live'] <= address <= row['retired']:
            current = int.from_bytes(gdb.selected_inferior().read_memory(entry_stack + storage[name]['offset'], width), 'little', signed=True)
            assert current == expected, (name, hex(address), current, expected)
            record['rawValue'] = current
        if row['before'] <= address:
            backup = signed(gdb.parse_and_eval('$r10' if target == 'x86_64' else '$x9'))
            assert backup == initial, (name, hex(address), backup)
            record['backup'] = backup
        value = gdb.parse_and_eval('value')
        assert value.type.strip_typedefs().code == gdb.TYPE_CODE_INT and value.type.sizeof == width
        record['value'] = str(value)
        if compiler:
            if address in [row[key] for key in ('live', 'before', 'after', 'retired')]:
                assert not value.is_optimized_out and int(value) == expected, (name, hex(address), str(value), expected)
        else:
            available = variant == 'forge' and row['live'] <= address < row['lost']
            assert not value.is_optimized_out if available else value.is_optimized_out, (name, hex(address), str(value), available)
            if available:
                assert int(value) == initial
            record['available'] = available
            if variant == 'forge':
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
                    assert actual == initial
                    record['locationValue'] = actual
        if address >= row['retired']:
            assert int(gdb.parse_and_eval('effect_sink')) == expected
        if instruction == instructions[-1]:
            assert int(gdb.parse_and_eval('backup_sink')) == initial
            returns.append(name)
        points.append(record)
        if instruction != instructions[-1]:
            gdb.execute('stepi')
    if compiler:
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
    'returns': returns, 'navigation': ['next', 'step'], 'exitCode': 0}, indent=4) + '\n')
print('stack-local-effects-gdb=' + variant + ' PASS')

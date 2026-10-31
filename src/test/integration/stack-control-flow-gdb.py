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
    assert 'void (' in gdb.execute('ptype ' + name, to_string=True)
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
started = False
for seed in [19, -19, initial]:
    for choice in (0, 1):
        for name in labels['order']:
            row = labels['functions'][name]
            gdb.Breakpoint('*' + name, temporary=True)
            gdb.execute('continue' if started or remote else 'run')
            started = True
            entry = int(gdb.parse_and_eval('&' + name))
            bias = entry - row['entry']
            assert int(gdb.parse_and_eval('$pc')) == entry
            entry_stack = int(gdb.parse_and_eval('$sp'))
            assert signed(gdb.parse_and_eval('$rdi' if target == 'x86_64' else '$x0')) == seed
            assert int(gdb.parse_and_eval('$esi' if target == 'x86_64' else '$w1')) == choice
            for parameter, expected in [('seed', seed), ('choice', choice)]:
                observed = gdb.parse_and_eval(parameter)
                if variant != 'previous' or not observed.is_optimized_out:
                    assert int(observed) == expected
            current, defined, retired, definitions = -12345, False, False, 0
            visits = {}
            for step in range(1000):
                address = int(gdb.parse_and_eval('$pc')) - bias
                assert row['entry'] <= address < row['end'], (name, hex(address))
                if name == 'flow_split':
                    assert not row['hole'] <= address < row['afterhole']
                instruction, = gdb.selected_inferior().architecture().disassemble(address + bias, count=1)
                raw = bytes(gdb.selected_inferior().read_memory(address + bias, instruction['length'])).hex()
                visits[address] = visits.get(address, 0) + 1
                if address == row['live']:
                    current = seed + definitions if name == 'flow_redefine' else seed
                    definitions += 1
                    defined = True
                if address == row.get('changed'):
                    current ^= 90
                if address == row['retired']:
                    retired = True
                marker = address in [row.get(key) for key in ('live', 'join', 'retired', 'changed', 'left', 'right', 'loaded', 'loop')]
                value = gdb.parse_and_eval('value')
                assert value.type.strip_typedefs().code == gdb.TYPE_CODE_INT and value.type.sizeof == width
                if compiler and marker:
                    offset = int(gdb.parse_and_eval('&value')) - entry_stack
                    assert -4096 <= offset < 0
                    if name not in storage:
                        storage[name] = {'offset': offset}
                    assert storage[name]['offset'] == offset
                    assert not value.is_optimized_out and int(value) == current, (name, hex(address), str(value), current)
                record = {'function': name, 'seed': seed, 'choice': choice, 'linkPc': address,
                    'pc': address + bias, 'visit': visits[address], 'bytes': raw, 'value': str(value), 'logical': current}
                if not compiler:
                    prepared = json.loads((case / 'prepared.json').read_text())
                    saved, = [item for item in prepared[name + '_instructions'] if item['address'] == address]
                    assert saved['bytes'] == raw and saved['next'] == address + instruction['length']
                    assert any(low <= address < high for low, high in prepared[name + '_body'])
                    matches = [item for item in locations.get(name, []) if item['start'] <= address < item['end']]
                    available = not value.is_optimized_out
                    record['available'] = available
                    if variant == 'forge':
                        assert len(matches) == int(available), (name, hex(address), matches, str(value))
                        if available:
                            assert defined and not retired and int(value) == current, (name, hex(address), str(value), current)
                            item = matches[0]
                            physical = int(gdb.parse_and_eval('$' + register(item['register'])))
                            if item['kind'] == 'stack':
                                physical += item['offset']
                                assert physical == entry_stack + storage[name]['offset']
                                actual = int.from_bytes(gdb.selected_inferior().read_memory(physical, width), 'little', signed=True)
                            else:
                                actual = signed(physical)
                            assert actual == current
                            record['locationValue'] = actual
                        if address == row['live']:
                            assert available
                            if name == 'flow_redefine':
                                assert matches[0]['kind'] == 'stack'
                                old = signed(gdb.parse_and_eval('$r10' if target == 'x86_64' else '$x9'))
                                assert old == (seed + definitions - 2 if definitions > 1 else -23456)
                                assert old != current
                                record['staleBackup'] = old
                        if address == row['join']:
                            assert available == (name in ('flow_diamond', 'flow_loop', 'flow_redefine', 'flow_split')), (name, str(value))
                        if address == row.get('loop'):
                            assert available == (name == 'flow_loop'), (name, str(value))
                        if address == row.get('changed'):
                            assert not available
                        for parameter, expected in [('seed', seed), ('choice', choice)]:
                            observed = gdb.parse_and_eval(parameter)
                            if not observed.is_optimized_out:
                                assert int(observed) == expected, (name, parameter, hex(address), str(observed), expected)
                            record[parameter + 'Observed'] = str(observed)
                    else:
                        assert not available, (name, hex(address), str(value))
                points.append(record)
                if instruction['asm'].startswith('ret'):
                    assert int(gdb.parse_and_eval('effect_sink')) == current
                    assert visits.get(row.get('loop'), 0) == (choice + 2 if 'loop' in row else 0)
                    assert definitions == (choice + 2 if name == 'flow_redefine' else choice if name == 'flow_bypass' else 1)
                    returns.append({'function': name, 'seed': seed, 'choice': choice, 'value': current})
                    break
                gdb.execute('stepi')
            else:
                raise AssertionError('instruction budget exceeded')

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
print('stack-control-flow-gdb=' + variant + ' PASS')

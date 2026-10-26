"""Instruction-boundary oracle for the freestanding Linux i386 fixture."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ['I386_CASE'])
variant = os.environ['I386_VARIANT']
model = json.loads((case / 'symbols.json').read_text())
compiler = variant == 'compiler'
gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('set debuginfod enabled off')
gdb.execute('set auto-solib-add off')
gdb.execute('file ' + json.dumps(str(case / ('profile.reference' if compiler else 'profile.input'))))
if not compiler:
    gdb.execute('symbol-file ' + json.dumps(str(case / 'profile.dbg')))
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
rounds = [(-19, 42, 0x123456789abcdef, 7), (19, -42, -0x123456789abcdef, -7),
    (0x12345678, -1, -0x23456789abcdef0, 17)]
points = []
returns = []
bindings = {}
started = False
for first, second, large, tail in rounds:
    specs = [
        ('scalar', {'first': first, 'second': second}, first + second),
        ('wide', {'first': first, 'second': large, 'third': tail}, large + first - tail),
        ('aggregate', {'value.first': first, 'value.second': second, 'tail': tail}, first - second + tail),
    ]
    for name, expected, returned in specs:
        labels = model['functions'][name]
        stop = gdb.Breakpoint('*' + name)
        gdb.execute('continue' if started else 'run')
        started = True
        assert gdb.selected_frame().name() == name
        entry_sp = int(gdb.parse_and_eval('$esp'))
        bias = int(gdb.parse_and_eval('$pc')) - labels['entry']
        if model['role'] not in ('exec', 'sectionless'):
            assert bias != 0
        stop.delete()
        instructions = gdb.selected_frame().architecture().disassemble(
            labels['entry'] + bias, labels['end'] - 1 + bias)
        cursor = labels['entry']
        for instruction in instructions:
            assert instruction['addr'] - bias == cursor and instruction['length'] > 0
            cursor += instruction['length']
        assert cursor == labels['end'] and instructions[-1]['addr'] - bias == labels['end'] - 1
        for instruction in instructions:
            link_pc = instruction['addr'] - bias
            point = 'entry' if link_pc == labels['entry'] else 'ready' if link_pc == labels['ready'] else (
                'return' if link_pc == labels['end'] - 1 else 'instruction')
            if point != 'entry':
                stop = gdb.Breakpoint('*' + hex(link_pc + bias), temporary=True)
                gdb.execute('continue')
            assert int(gdb.parse_and_eval('$pc')) == link_pc + bias
            assert gdb.selected_frame().name() == name
            assert int(gdb.parse_and_eval('sizeof(void *)')) == 4
            # The compiler describes the wide argument in its copied stack slot,
            # which is not initialized at entry. Its entry oracle is the actual
            # incoming stack bytes, not that premature compiler location.
            slots = [('int', 4, first), ('int', 8, second)] if name == 'scalar' else (
                [('int', 4, first), ('long long', 8, large), ('int', 16, tail)] if name == 'wide' else
                [('int', 4, first), ('int', 8, second), ('int', 12, tail)])
            raw = [int(gdb.parse_and_eval('*(' + dtype + '*)' + hex(entry_sp + offset)))
                for dtype, offset, unused in slots]
            assert raw == [value for unused, offset, value in slots], (name, point, raw)
            actual = None
            if not compiler or link_pc >= labels['ready']:
                actual = {key: int(gdb.parse_and_eval(key)) for key in expected}
                assert actual == expected, (name, point, actual, expected)
            if compiler and point == 'ready':
                held = gdb.parse_and_eval('held')
                assert int(held) == returned
                binding = {'stackOffset': int(held.address) - entry_sp,
                    'bytes': held.type.sizeof, 'firstUse': labels['ready'] - labels['entry']}
                assert name not in bindings or bindings[name] == binding
                bindings[name] = binding
            elif not compiler:
                held = gdb.parse_and_eval('curated_held')
                assert held.is_optimized_out and held.type.sizeof == (8 if name == 'wide' else 4)
            if point == 'ready':
                assert name in gdb.execute('list ' + name, to_string=True)
                assert 'type =' in gdb.execute('ptype ' + name, to_string=True)
            points.append({'function': name, 'point': point, 'linkPc': link_pc,
                'bias': bias, 'entrySp': entry_sp, 'sp': int(gdb.parse_and_eval('$esp')),
                'expected': expected, 'named': actual, 'rawStack': raw,
                'instructionBytes': bytes(gdb.selected_inferior().read_memory(link_pc + bias, instruction['length'])).hex()})
        assert bytes(gdb.selected_inferior().read_memory(labels['end'] - 1 + bias, 1)) == b'\xc3'
        # Capture the return before source navigation can execute a caller test
        # that overwrites EAX/EDX. Navigation has its own fresh invocation below.
        gdb.execute('finish')
        assert gdb.selected_frame().name() == '_start'
        low = int(gdb.parse_and_eval('$eax')) & 0xffffffff
        value = ((int(gdb.parse_and_eval('$edx')) & 0xffffffff) << 32) | low if name == 'wide' else low
        bits = 64 if name == 'wide' else 32
        if value & (1 << (bits - 1)):
            value -= 1 << bits
        assert value == returned, (name, value, returned)
        returns.append({'function': name, 'value': value})
gdb.execute('continue')
assert exits == [0], exits
stop = gdb.Breakpoint('*scalar')
gdb.execute('run')
assert gdb.selected_frame().name() == 'scalar'
nav_bias = int(gdb.parse_and_eval('$pc')) - model['functions']['scalar']['entry']
stop.delete()
stop = gdb.Breakpoint('*' + hex(model['functions']['scalar']['ready'] + nav_bias), temporary=True)
gdb.execute('continue')
assert gdb.selected_frame().name() == 'scalar'
gdb.execute('next')
gdb.execute('step')
assert gdb.selected_frame().name() in ('scalar', '_start')
gdb.execute('continue')
assert exits == [0, 0], exits
assert len(returns) == 9
for name in model['functions']:
    for point in ('entry', 'ready', 'return'):
        assert sum(p['function'] == name and p['point'] == point for p in points) == 3
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant,
    'points': points, 'returns': returns, 'bindings': bindings, 'exitCodes': exits,
    'navigation': ['next', 'step']}, indent=4) + '\n')
print('i386-profile-gdb=' + variant + ' PASS')

"""Instruction-boundary oracle for the freestanding Linux i386 fixture."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ['I386_CASE'])
variant = os.environ['I386_VARIANT']
model = json.loads((case / 'symbols.json').read_text())
compiler = variant == 'compiler'
shared = 'driver' in model
gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('set debuginfod enabled off')
gdb.execute('set auto-solib-add off')
gdb.execute('file ' + json.dumps(str(case / (model['driver'] if shared else (
    'profile.reference' if compiler else 'profile.input')))))
if not compiler and not shared:
    gdb.execute('symbol-file ' + json.dumps(str(case / 'profile.dbg')))
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
rounds = [(-19, 42, 0x123456789abcdef, 7), (19, -42, -0x123456789abcdef, -7),
    (0x12345678, -1, -0x23456789abcdef0, 17)]
points = []
returns = []
bindings = {}
started = False
loaded_shared = False
shared_bindings = []


def shared_start():
    global loaded_shared
    artifact = case / ('profile.reference' if compiler else 'profile.dbg')
    if loaded_shared:
        gdb.execute('remove-symbol-file ' + json.dumps(str(artifact)))
    runtime = case / (variant + '-runtime')
    gdb.execute('set environment LD_LIBRARY_PATH = ' + str(runtime))
    stop = gdb.Breakpoint('*_start')
    gdb.execute('run')
    assert gdb.selected_frame().name() == '_start'
    stop.delete()
    library = (runtime / 'libprofile.so').resolve()
    mappings = []
    for line in Path('/proc/' + str(gdb.selected_inferior().pid) + '/maps').read_text().splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) == 6 and Path(fields[5]).resolve() == library and int(fields[2], 16) == 0:
            mappings.append(int(fields[0].split('-')[0], 16))
    assert len(mappings) == 1
    bias = mappings[0] - model['loadBase']
    assert bias != 0
    if not compiler:
        for display_name in model['curatedNames'].values():
            try:
                gdb.parse_and_eval('&' + display_name)
            except gdb.error as error:
                assert 'No symbol' in str(error)
            else:
                raise AssertionError('curated name exists before the Forge sidecar is loaded')
    gdb.execute('add-symbol-file ' + json.dumps(str(artifact)) + ' -o ' + hex(bias))
    loaded_shared = True
    for name, label in model['functions'].items():
        original_address = int(gdb.parse_and_eval('&' + name))
        assert original_address == label['entry'] + bias
        curated_address = None
        if not compiler:
            display_name = model['curatedNames'][name]
            curated_address = int(gdb.parse_and_eval('&' + display_name))
            assert curated_address == label['entry'] + bias
        shared_bindings.append({'function': name, 'bias': bias, 'original': original_address,
            'curated': curated_address, 'artifact': str(artifact), 'runtimeLibrary': str(library),
            'curatedAbsentBeforeLoad': not compiler})


if shared:
    shared_start()
    started = True
for first, second, large, tail in rounds:
    specs = [
        ('scalar', {'first': first, 'second': second}, first + second),
        ('wide', {'first': first, 'second': large, 'third': tail}, large + first - tail),
        ('aggregate', {'value.first': first, 'value.second': second, 'tail': tail}, first - second + tail),
    ]
    for name, expected, returned in specs:
        display_name = model['curatedNames'][name] if shared and not compiler else name
        labels = model['functions'][name]
        stop = gdb.Breakpoint('*' + display_name)
        gdb.execute('continue' if started else 'run')
        started = True
        assert gdb.selected_frame().name() == display_name
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
            assert gdb.selected_frame().name() == display_name
            if shared:
                expected_artifact = case / ('profile.reference' if compiler else 'profile.dbg')
                assert Path(gdb.selected_frame().find_sal().symtab.objfile.filename).resolve() == expected_artifact.resolve()
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
                assert display_name in gdb.execute('list ' + display_name, to_string=True)
                assert 'type =' in gdb.execute('ptype ' + display_name, to_string=True)
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
if shared:
    shared_start()
scalar_name = model['curatedNames']['scalar'] if shared and not compiler else 'scalar'
stop = gdb.Breakpoint('*' + scalar_name)
gdb.execute('continue' if shared else 'run')
assert gdb.selected_frame().name() == scalar_name
nav_bias = int(gdb.parse_and_eval('$pc')) - model['functions']['scalar']['entry']
stop.delete()
stop = gdb.Breakpoint('*' + hex(model['functions']['scalar']['ready'] + nav_bias), temporary=True)
gdb.execute('continue')
assert gdb.selected_frame().name() == scalar_name
gdb.execute('next')
navigation_stops = []
sal = gdb.selected_frame().find_sal()
navigation_stops.append({'operation': 'next', 'function': gdb.selected_frame().name(),
    'pc': int(gdb.parse_and_eval('$pc')), 'source': sal.symtab.fullname(), 'line': sal.line})
gdb.execute('step')
allowed = [scalar_name, '_start']
if shared:
    wide_name = model['curatedNames']['wide'] if not compiler else 'wide'
    allowed.append(wide_name)
    if gdb.selected_frame().name() == wide_name:
        # The caller's single ROUND source line contains all three calls.
        # Returning from scalar and stepping can therefore enter wide directly.
        assert int(gdb.parse_and_eval('first')) == -19
        assert int(gdb.parse_and_eval('second')) == 0x123456789abcdef
        assert int(gdb.parse_and_eval('third')) == 7
assert gdb.selected_frame().name() in allowed
sal = gdb.selected_frame().find_sal()
navigation_stops.append({'operation': 'step', 'function': gdb.selected_frame().name(),
    'pc': int(gdb.parse_and_eval('$pc')), 'source': sal.symtab.fullname(), 'line': sal.line})
assert all(point['line'] > 0 and Path(point['source']).is_file() for point in navigation_stops)
gdb.execute('continue')
assert exits == [0, 0], exits
assert len(returns) == 9
for name in model['functions']:
    for point in ('entry', 'ready', 'return'):
        assert sum(p['function'] == name and p['point'] == point for p in points) == 3
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant,
    'points': points, 'returns': returns, 'bindings': bindings, 'exitCodes': exits,
    'navigation': ['next', 'step'], 'navigationStops': navigation_stops,
    'sharedBindings': shared_bindings}, indent=4) + '\n')
print('i386-profile-gdb=' + variant + ' PASS')

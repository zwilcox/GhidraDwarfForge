"""Observe each machine boundary, compiler physical locals and the saved incoming value."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['LOCAL_CASE'])
target = os.environ['LOCAL_TARGET']
variant = os.environ['LOCAL_VARIANT']
model = json.loads((case / 'model.json').read_text())
labels = json.loads((case / 'boundaries.json').read_text())
layouts = {} if variant == 'compiler' else json.loads((case / 'stack-layouts.json').read_text())
binary = case / ('local.reference' if variant == 'compiler' else 'local.input')
sidecar = case / {'compiler': 'local.reference', 'forge': 'local.dbg', 'previous': 'previous.dbg'}[variant]
gdb.execute('file ' + str(binary))
gdb.execute('symbol-file ' + str(sidecar))
remote = os.environ.get('LOCAL_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
rows, biases, returned, navigation, exits = [], [], [], [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for iteration, (small, large) in enumerate(((19, 19), (-19, -19), (-1985229329, -81985529216486895))):
    for shape in ('keep', 'respill', 'loss', 'badload', 'alias', 'chainloss'):
        for width, argument in ((4, small), (8, large)):
            name = 'transfer_' + shape + str(width * 8)
            label = labels[name]
            stop = gdb.Breakpoint('*' + name, internal=True)
            gdb.execute('run' if not started and not remote else 'continue')
            started = True
            entry = int(gdb.parse_and_eval('&' + name))
            bias = entry - label['entry']
            biases.append(bias)
            assert int(gdb.parse_and_eval('$pc')) == entry
            assert model['role'] == 'exec' or bias != 0
            stop.delete()
            physical = None
            stack_addresses = None
            instructions = {i['address']: i for i in label['instructions']}
            for step in range(200):
                pc = int(gdb.parse_and_eval('$pc'))
                link = pc - bias
                assert link in instructions and gdb.newest_frame().name() == name
                dtype = 'int' if width == 4 else 'long long'
                if link == label['before']:
                    physical = {'first': -12345, 'second': -23456, 'slot': argument, 'slot2': -3456}
                    sp = int(gdb.parse_and_eval('$rsp' if target == 'x86_64' else '$sp'))
                    if variant == 'compiler':
                        observed_layout = [int(gdb.parse_and_eval('&' + variable)) - sp for variable in ('slot', 'slot2')]
                        assert observed_layout[0] != observed_layout[1]
                        if name in layouts:
                            assert layouts[name] == observed_layout
                        layouts[name] = observed_layout
                    stack_addresses = [sp + offset for offset in layouts[name]]
                expected = any(low <= link < high for low, high, kind, carrier in label['locations'])
                observed = {}
                if variant != 'compiler':
                    symbol, _ = gdb.lookup_symbol('input')
                    assert symbol is not None and symbol.is_argument
                    value = symbol.value(gdb.newest_frame())
                    assert value.type.sizeof == width
                    available = not value.is_optimized_out
                    assert available == (expected if variant == 'forge' else link < label['previous_end']), (name, hex(link), variant, str(value), expected)
                    if available:
                        assert int(value) == argument, (name, hex(link), str(value), argument)
                    observed.update(available=available, value=str(value))
                if physical is not None:
                    if variant == 'compiler' and link <= label['finish']:
                        for variable, physical_value in physical.items():
                            value = gdb.parse_and_eval(variable)
                            assert not value.is_optimized_out and value.type.sizeof == width
                            assert int(value) == physical_value, (name, hex(link), variable, str(value), physical_value)
                        observed['compilerLocals'] = dict(physical)
                    registers = ('r10', 'r11') if target == 'x86_64' else ('x9', 'x10')
                    raw = [int(gdb.parse_and_eval('(' + dtype + ')$' + register)) for register in registers]
                    memory = [int(gdb.parse_and_eval('*(' + dtype + '*)' + hex(address))) for address in stack_addresses]
                    assert raw == [physical['first'], physical['second']], (name, hex(link), raw, physical)
                    assert memory == [physical['slot'], physical['slot2']], (name, hex(link), memory, physical)
                    observed.update(rawRegisters=raw, stackValues=memory, stackAddresses=stack_addresses)
                rows.append({'function': name, 'input': argument, 'linkPc': link, 'pc': pc, 'expectedAvailable': expected, **observed})
                if link == label['before']:
                    listing = gdb.execute('list ' + name, to_string=True)
                    assert name in listing and 'No such file' not in listing
                    rendered = gdb.execute('ptype input', to_string=True)
                    assert rendered.startswith('type = ')
                if link == label['return']:
                    break
                if link == label['reload']:
                    physical['first'] = physical['slot']
                if link == label.get('save_again'):
                    physical['slot2'] = physical['first']
                if link == label.get('reuse'):
                    physical['slot'] = 0
                if link == label.get('kill_first'):
                    physical['first'] = 0
                if link == label.get('reload_again'):
                    physical['second'] = physical['slot2']
                if link == label.get('reuse_again'):
                    physical['slot2'] = 0
                if link == label.get('kill_second'):
                    physical['second'] = 0
                if iteration == 0 and name == 'transfer_keep32' and link in (label['reload'], label['ready']):
                    following = instructions[link]['next'] + bias
                    guard = gdb.Breakpoint('*' + hex(following), internal=True)
                    command = 'next' if link == label['reload'] else 'step'
                    gdb.execute(command)
                    assert int(gdb.parse_and_eval('$pc')) == following
                    navigation.append({'command': command, 'pc': following})
                    guard.delete()
                else:
                    gdb.execute('stepi')
            else:
                raise AssertionError('fixture did not return within bounded instruction count')
            finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
            gdb.execute('continue')
            result = argument if shape in ('keep', 'respill', 'alias') else 0
            assert int(finish.return_value) == result
            returned.append({'function': name, 'input': argument, 'value': result})
gdb.execute('continue')
assert exits == [0] and len(returned) == 36 and len(navigation) == 2
if variant == 'compiler':
    assert set(layouts) == set(labels)
    (case / 'stack-layouts.json').write_text(json.dumps(layouts, indent=4) + '\n')
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'runtimeBiases': biases, 'returned': returned, 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('stack-value-transitions-gdb=' + variant + ' PASS')

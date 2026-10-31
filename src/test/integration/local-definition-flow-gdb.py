"""Check each executed instruction, both paths and every loop iteration."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['LOCAL_CASE'])
target = os.environ['LOCAL_TARGET']
variant = os.environ['LOCAL_VARIANT']
model = json.loads((case / 'model.json').read_text())
labels = json.loads((case / 'boundaries.json').read_text())
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
    for choice in (0, 1):
        for shape in ('keep', 'kill', 'loop', 'loopkill', 'bypass', 'split'):
            for width, argument in ((4, small), (8, large)):
                name = 'flow_' + shape + str(width * 8)
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
                physical, visits = None, {}
                instructions = {i['address']: i for i in label['instructions']}
                for step in range(200):
                    pc = int(gdb.parse_and_eval('$pc'))
                    link = pc - bias
                    assert link in instructions and gdb.newest_frame().name() == name
                    assert any(low <= link < high for low, high in label['body'])
                    visits[link] = visits.get(link, 0) + 1
                    if link == label['before']:
                        physical = -12345
                    variable = 'held' if variant == 'compiler' else 'curated_held'
                    symbol, _ = gdb.lookup_symbol(variable)
                    value = None if symbol is None else symbol.value(gdb.newest_frame())
                    available = value is not None and not value.is_optimized_out
                    proven = any(low <= link < high for low, high in label['available'])
                    if variant == 'compiler':
                        if physical is not None:
                            assert available and int(value) == physical, (name, link, str(value), physical)
                    else:
                        assert symbol is not None and not symbol.is_argument
                        assert available == (variant == 'forge' and proven), (name, link, available, proven)
                        assert value.type.sizeof == width
                        if available:
                            assert int(value) == argument + 7
                    row = {'function': name, 'input': argument, 'choice': choice, 'visit': visits[link],
                        'linkPc': link, 'pc': pc, 'available': available,
                        'local': None if value is None else str(value)}
                    if physical is not None:
                        register = 'r10' if target == 'x86_64' else 'x9'
                        dtype = 'int' if width == 4 else 'long long'
                        raw = int(gdb.parse_and_eval('(' + dtype + ')$' + register))
                        assert raw == physical, (name, link, raw, physical)
                        row['rawRegister'] = raw
                    rows.append(row)
                    if link == label['ready']:
                        listing = gdb.execute('list ' + name, to_string=True)
                        assert name in listing and 'No such file' not in listing
                        rendered = gdb.execute('ptype ' + variable, to_string=True)
                        assert rendered.startswith('type = ') and value.type.sizeof == width
                    if link == label['return']:
                        break
                    if link == label['definition']:
                        physical = argument + 7
                    if link == label.get('kill'):
                        physical = 909
                    if iteration == 0 and choice == 0 and name == 'flow_keep32' and link in (label['definition'], label['ready']):
                        following = instructions[link]['next'] + bias
                        guard = gdb.Breakpoint('*' + hex(following), internal=True)
                        command = 'next' if link == label['definition'] else 'step'
                        gdb.execute(command)
                        assert int(gdb.parse_and_eval('$pc')) == following
                        navigation.append({'command': command, 'pc': following})
                        guard.delete()
                    else:
                        gdb.execute('stepi')
                else:
                    raise AssertionError('fixture did not return within bounded instruction count')
                expected = (909 if shape == 'loopkill' or (shape == 'kill' and choice) else
                    -12345 if shape == 'bypass' and not choice else argument + 7)
                finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
                gdb.execute('continue')
                assert int(finish.return_value) == expected
                returned.append({'function': name, 'input': argument, 'choice': choice, 'value': expected})
                assert visits.get(label.get('loop'), 0) == (choice + 2 if shape in ('loop', 'loopkill') else 0)
                if shape in ('keep', 'kill', 'bypass'):
                    assert (label['skipped'] in visits) == (choice == 0)
                if shape == 'bypass':
                    assert (label['definition'] in visits) == (choice == 1)
gdb.execute('continue')
assert exits == [0] and len(returned) == 72 and len(navigation) == 2
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'runtimeBiases': biases, 'returned': returned, 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('local-definition-flow-gdb=' + variant + ' PASS')

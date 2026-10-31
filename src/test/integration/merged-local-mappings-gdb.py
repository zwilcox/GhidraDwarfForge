"""Compare physical compiler locals and the current canonical saved local at each instruction."""
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
rows, biases, returned, navigation, exits, regressions = [], [], [], [], [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for iteration, (small, large) in enumerate(((19, 19), (-19, -19), (-1985229329, -81985529216486895))):
    for choice in (0, 1):
        for shape in ('straight', 'stale', 'branch', 'loop'):
            for width, argument in ((4, small), (8, large)):
                name = 'merged_' + shape + str(width * 8)
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
                first, second, logical, visits = None, None, None, {}
                instructions = {i['address']: i for i in label['instructions']}
                for step in range(200):
                    pc = int(gdb.parse_and_eval('$pc'))
                    link = pc - bias
                    assert link in instructions and gdb.newest_frame().name() == name
                    visits[link] = visits.get(link, 0) + 1
                    if link == label['before']:
                        first, second = -12345, -23456
                    proven = any(low <= link < high for low, high, register in label['intervals'])
                    observed = {}
                    if variant == 'compiler':
                        for variable, physical in [('first', first), ('second', second)]:
                            symbol, _ = gdb.lookup_symbol(variable)
                            value = None if symbol is None else symbol.value(gdb.newest_frame())
                            if physical is not None:
                                assert value is not None and not value.is_optimized_out
                                assert value.type.sizeof == width and int(value) == physical, (name, link, variable, str(value), physical)
                            observed[variable] = None if value is None else str(value)
                    else:
                        symbol, _ = gdb.lookup_symbol('curated_value')
                        assert symbol is not None and not symbol.is_argument
                        value = symbol.value(gdb.newest_frame())
                        assert value.type.sizeof == width and str(value.type) == 'analyst_count' + str(width * 8)
                        available = not value.is_optimized_out
                        observed['available'] = available
                        observed['curated_value'] = str(value)
                        if variant == 'forge':
                            assert available == proven, (name, hex(link), available, proven)
                            if available:
                                assert logical is not None and int(value) == logical, (name, hex(link), str(value), logical)
                            for index in range(1, len(label['mappings'])):
                                assert gdb.lookup_symbol('curated_value$' + str(index))[0] is None
                        elif link == label['updated'] and (not available or int(value) != logical):
                            regressions.append({'function': name, 'pc': link, 'old': str(value), 'expected': logical})
                    row = {'function': name, 'input': argument, 'choice': choice, 'visit': visits[link],
                        'linkPc': link, 'pc': pc, 'logical': logical, 'proven': proven, **observed}
                    if first is not None:
                        registers = ('r10', 'r11') if target == 'x86_64' else ('x9', 'x10')
                        dtype = 'int' if width == 4 else 'long long'
                        raw = [int(gdb.parse_and_eval('(' + dtype + ')$' + register)) for register in registers]
                        assert raw == [first, second], (name, hex(link), raw, first, second)
                        row['rawRegisters'] = raw
                    rows.append(row)
                    if link == label['ready']:
                        listing = gdb.execute('list ' + name, to_string=True)
                        assert name in listing and 'No such file' not in listing
                        rendered = gdb.execute('ptype ' + ('first' if variant == 'compiler' else 'curated_value'), to_string=True)
                        assert rendered.startswith('type = ')
                    if link == label['return']:
                        break
                    if link == label['definition']:
                        first = logical = argument + 7
                    if link == label['copy']:
                        second = logical = first
                    if link == label.get('oldkill'):
                        first = 0
                    if link == label.get('reset'):
                        second = logical = 42
                    if link == label['update']:
                        second += 5
                        logical = second
                    if link == label['kill']:
                        second = 909
                    if iteration == 0 and choice == 0 and name == 'merged_straight32' and link in (label['definition'], label['ready']):
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
                finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
                gdb.execute('continue')
                assert int(finish.return_value) == 909
                returned.append({'function': name, 'input': argument, 'choice': choice, 'value': 909})
                assert visits.get(label.get('loop'), 0) == (choice + 2 if shape == 'loop' else 0)
                if shape == 'branch':
                    assert (label['skipped'] in visits) == (choice == 0)
                    assert (label['copy'] in visits) == (choice == 1)
gdb.execute('continue')
assert exits == [0] and len(returned) == 48 and len(navigation) == 2
if variant == 'previous':
    assert len(regressions) >= 36, regressions
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'runtimeBiases': biases, 'returned': returned, 'navigation': navigation, 'exitCodes': exits,
    'previousIncorrectOrUnavailable': regressions}, indent=4) + '\n')
print('merged-local-mappings-gdb=' + variant + ' PASS')

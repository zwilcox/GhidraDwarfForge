"""Observe both incoming-value handoffs and the unavailable tail at exact PCs."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['SECOND_COPY_CASE'])
target = os.environ['SECOND_COPY_TARGET']
variant = os.environ['SECOND_COPY_VARIANT']
labels = json.loads((case / 'labels.json').read_text())
metadata = json.loads((case / 'metadata.json').read_text())
binary = case / ('chain.reference' if variant == 'compiler' else 'chain.input')
sidecar = case / {'compiler': 'chain.reference', 'forge': 'chain.dbg', 'previous': 'previous.dbg'}[variant]
gdb.execute('file ' + str(binary))
gdb.execute('symbol-file ' + str(sidecar))
remote = os.environ.get('SECOND_COPY_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
rows, biases, navigation, returned, exits = [], [], [], [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for iteration, (small, large) in enumerate(((19, 19), (-19, -19), (-1985229329, -81985529216486895))):
    for name, argument in (('chain32', small), ('chain64', large)):
        label = labels[name]
        stop = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        entry = int(gdb.parse_and_eval('&' + name))
        bias = entry - label['entry']
        biases.append(bias)
        assert int(gdb.parse_and_eval('$pc')) == entry
        if metadata['role'] != 'exec':
            assert bias != 0
        stop.delete()
        points = ['entry', 'saved', 'write', 'after', 'copy', 'second', 'kill', 'tail', 'erase', 'unavailable', 'return']
        if metadata.get('handoffs', 2) == 4:
            points[8:8] = ['copy3', 'third', 'kill2', 'tail3', 'copy4', 'fourth', 'kill3', 'tail4']
        points.sort(key=lambda point: label[point])
        assert len({label[p] for p in points}) == len(points)
        for point in points:
            pc = label[point] + bias
            stop = gdb.Breakpoint('*' + hex(pc), internal=True)
            if int(gdb.parse_and_eval('$pc')) != pc:
                gdb.execute('continue')
            assert int(gdb.parse_and_eval('$pc')) == pc and gdb.newest_frame().name() == name
            value = gdb.parse_and_eval('value')
            available = not value.is_optimized_out
            stop_point = ('tail3' if metadata.get('handoffs', 2) == 4 else 'tail') if variant == 'previous' else 'unavailable'
            expected = variant == 'compiler' or label[point] < label[stop_point]
            assert available == expected, (variant, name, point, str(value))
            assert value.type.sizeof == label['width']
            if available:
                assert int(value) == argument, (variant, name, point, str(value), argument)
            row = {'function': name, 'point': point, 'input': argument, 'linkPc': label[point],
                'pc': pc, 'available': available, 'value': str(value)}
            dtype = 'int' if label['width'] == 4 else 'long long'
            registers = ('rdi', 'r10', 'r11') if target == 'x86_64' else ('x0', 'x9', 'x10')
            if point in ('saved', 'write', 'after', 'copy', 'second', 'kill'):
                raw = int(gdb.parse_and_eval('(' + dtype + ')$' + registers[1]))
                assert raw == argument
                row['firstBackup'] = raw
            if point in ('second', 'kill', 'tail', 'erase', 'unavailable'):
                raw = int(gdb.parse_and_eval('(' + dtype + ')$' + registers[2]))
                assert raw == (0 if point == 'unavailable' else argument)
                row['secondBackup'] = raw
            if point in ('third', 'kill2', 'tail3', 'copy4', 'fourth', 'kill3'):
                raw = int(gdb.parse_and_eval('(' + dtype + ')$' + registers[1]))
                assert raw == argument
                row['thirdBackup'] = raw
            if point in ('fourth', 'kill3', 'tail4'):
                raw = int(gdb.parse_and_eval('(' + dtype + ')$' + registers[2]))
                assert raw == argument
                row['fourthBackup'] = raw
            if point in ('tail', 'tail4'):
                assert int(gdb.parse_and_eval('$' + registers[1])) == 0
            if point == 'tail3':
                assert int(gdb.parse_and_eval('$' + registers[2])) == 0
            if point in ('erase', 'unavailable', 'return'):
                assert int(gdb.parse_and_eval(name + '_sink')) == argument
            if point == 'entry':
                assert name in gdb.execute('list ' + name, to_string=True)
                assert 'type = ' in gdb.execute('ptype ' + name, to_string=True)
            rows.append(row)
            stop.delete()
            if iteration == 0 and name == 'chain32' and point in ('copy', 'kill'):
                following = label['second' if point == 'copy' else 'tail'] + bias
                guard = gdb.Breakpoint('*' + hex(following), internal=True)
                command = 'next' if point == 'copy' else 'step'
                gdb.execute(command)
                stepped = int(gdb.parse_and_eval('$pc'))
                assert pc < stepped <= following
                navigation.append({'command': command, 'pc': stepped})
                guard.delete()
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        assert int(finish.return_value) == 0
        returned.append(0)
gdb.execute('continue')
assert exits == [0] and len(returned) == 6 and len(navigation) == 2
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'runtimeBiases': biases, 'returned': returned, 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('second-register-copy-gdb=' + variant + ' PASS')

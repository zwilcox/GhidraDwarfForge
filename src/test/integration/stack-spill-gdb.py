"""Compare signed argument values, exact spill memory and honest unavailable tails."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['SPILL_CASE'])
variant = os.environ['SPILL_VARIANT']
target = os.environ['SPILL_TARGET']
model = json.loads((case / 'model.json').read_text())
labels = json.loads((case / 'boundaries.json').read_text())
binary = case / ('spill.reference' if variant == 'compiler' else 'spill.input')
sidecar = case / {'compiler': 'spill.reference', 'forge': 'spill.dbg', 'previous': 'previous.dbg'}[variant]
gdb.execute('file ' + str(binary))
gdb.execute('symbol-file ' + str(sidecar))
remote = os.environ.get('SPILL_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
rows, navigation, biases, returned, exits = [], [], [], [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for iteration, (small, large) in enumerate(((19, 19), (-19, -19), (-1985229329, -81985529216486895))):
    for name in ('spill32_keep', 'spill32_kill', 'spill64_keep', 'spill64_kill'):
        label = labels[name]
        argument = small if label['width'] == 4 else large
        entry_breakpoint = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        entry = int(gdb.parse_and_eval('&' + name))
        bias = entry - label['entry']
        biases.append(bias)
        assert int(gdb.parse_and_eval('$pc')) == entry
        if model['role'] != 'exec':
            assert bias != 0, 'PIE must have an observed runtime bias'
        entry_breakpoint.delete()
        keys = ['entry', 'saved', 'write', 'after']
        keys += ['kill', 'unavailable'] if name.endswith('kill') else (['restore'] if target == 'aarch64' else [])
        keys += ['return']
        # A keep case's AArch64 unavailable boundary is its return PC.
        assert len({label[key] for key in keys}) == len(keys)
        for index, point in enumerate(keys):
            pc = label[point] + bias
            stop = gdb.Breakpoint('*' + hex(pc), internal=True)
            if int(gdb.parse_and_eval('$pc')) != pc:
                gdb.execute('continue')
            assert int(gdb.parse_and_eval('$pc')) == pc and gdb.newest_frame().name() == name
            symbol, _ = gdb.lookup_symbol('value')
            assert symbol is not None and symbol.is_argument
            value = symbol.value(gdb.newest_frame())
            assert value.type.sizeof == label['width']
            unavailable = (variant == 'previous' and label[point] >= label['after']) or (
                variant == 'forge' and label[point] >= label.get('unavailable', label['end']))
            assert bool(value.is_optimized_out) == unavailable, (name, point, str(value))
            if not unavailable:
                assert int(value) == argument, (name, point, str(value), argument)
            row = {'function': name, 'point': point, 'input': argument, 'linkPc': label[point],
                'pc': pc, 'argument': str(value), 'unavailable': bool(value.is_optimized_out)}
            if point != 'entry':
                # Memory is observed independently even when Forge must stop
                # claiming it after an unproved aliasing store or SP change.
                offset = -label['width'] if target == 'x86_64' or point == 'return' else 16 - label['width']
                pointer = '$rsp' if target == 'x86_64' else '$sp'
                dtype = 'int' if label['width'] == 4 else 'long long'
                raw = int(gdb.parse_and_eval('*(' + dtype + '*)(' + pointer + ' + ' + str(offset) + ')'))
                assert raw == argument, (name, point, raw, argument)
                row['stackValue'] = raw
            if point == 'entry':
                listing = gdb.execute('list ' + name, to_string=True)
                assert name in listing and 'No such file' not in listing
                rendered = gdb.execute('ptype value', to_string=True)
                expected_types = {'type = int\n'} if label['width'] == 4 else (
                    {'type = long long\n', 'type = long long int\n'} if variant == 'compiler' else {'type = longlong\n'})
                assert rendered in expected_types, rendered
            rows.append(row)
            stop.delete()
            if iteration == 0 and name == 'spill32_keep' and index in (0, 1):
                following = label[keys[index + 1]] + bias
                guard = gdb.Breakpoint('*' + hex(following), internal=True)
                command = 'next' if index == 0 else 'step'
                gdb.execute(command)
                stepped = int(gdb.parse_and_eval('$pc'))
                assert pc < stepped <= following and gdb.newest_frame().name() == name
                navigation.append({'command': command, 'pc': stepped})
                guard.delete()
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        assert int(finish.return_value) == argument
        returned.append(argument)
gdb.execute('continue')
assert exits == [0] and len(returned) == 12 and len(navigation) == 2
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'runtimeBiases': biases, 'returned': returned, 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('stack-spill-gdb=' + variant + ' PASS')

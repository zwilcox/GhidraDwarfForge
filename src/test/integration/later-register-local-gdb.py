"""Compare curated physical lifetimes; do not substitute compiler lexical scopes."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['LOCAL_CASE'])
target = os.environ['LOCAL_TARGET']
variant = os.environ['LOCAL_VARIANT']
model = json.loads((case / 'model.json').read_text())
defined = model.get('firstUseKind', 'read') == 'definition'
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
    for name, argument in (('local32', small), ('local64', large)):
        label = labels[name]
        stop = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        entry = int(gdb.parse_and_eval('&' + name))
        bias = entry - label['entry']
        biases.append(bias)
        assert int(gdb.parse_and_eval('$pc')) == entry
        if model['role'] != 'exec':
            assert bias != 0
        stop.delete()
        keys = (['entry', 'before', 'definition'] if defined else
            ['entry'] + (['definition'] if label['definition'] != label['entry'] else []))
        keys += ['read', 'kill', 'after', 'return']
        assert len({label[key] for key in keys}) == len(keys)
        for point in keys:
            pc = label[point] + bias
            stop = gdb.Breakpoint('*' + hex(pc), internal=True)
            if int(gdb.parse_and_eval('$pc')) != pc:
                gdb.execute('continue')
            assert int(gdb.parse_and_eval('$pc')) == pc and gdb.newest_frame().name() == name
            variable = 'held' if variant == 'compiler' else 'curated_held'
            symbol, _ = gdb.lookup_symbol(variable)
            value = None if symbol is None else symbol.value(gdb.newest_frame())
            available = value is not None and not value.is_optimized_out
            if variant == 'compiler':
                if point == 'read':
                    assert available and int(value) == argument + 7
                if point in ('kill', 'after', 'return'):
                    assert symbol is None, 'compiler lexical block has ended'
            else:
                assert symbol is not None and not symbol.is_argument
                assert available == (variant == 'forge' and point in ('read', 'kill'))
                if available:
                    assert int(value) == argument + 7
                assert value.type.sizeof == label['width']
            row = {'function': name, 'point': point, 'input': argument, 'linkPc': label[point],
                'pc': pc, 'available': available, 'local': None if value is None else str(value)}
            if point in ('read', 'kill', 'after', 'return') or (defined and point in ('before', 'definition')):
                register = 'r10' if target == 'x86_64' else 'x9'
                dtype = 'int' if label['width'] == 4 else 'long long'
                raw = int(gdb.parse_and_eval('(' + dtype + ')$' + register))
                expected = -12345 if point in ('before', 'definition') else (
                    argument + 7 if point in ('read', 'kill') else 0)
                assert raw == expected, (name, point, raw, expected)
                row['rawRegister'] = raw
            if point == 'read':
                listing = gdb.execute('list ' + name, to_string=True)
                assert name in listing and 'No such file' not in listing
                rendered = gdb.execute('ptype ' + variable, to_string=True)
                assert rendered.startswith('type = ') and value.type.sizeof == label['width']
            rows.append(row)
            stop.delete()
            if iteration == 0 and name == 'local32' and point in ('read', 'kill'):
                following = label['kill' if point == 'read' else 'after'] + bias
                guard = gdb.Breakpoint('*' + hex(following), internal=True)
                command = 'next' if point == 'read' else 'step'
                gdb.execute(command)
                stepped = int(gdb.parse_and_eval('$pc'))
                assert pc < stepped <= following and gdb.newest_frame().name() == name
                navigation.append({'command': command, 'pc': stepped})
                guard.delete()
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        assert int(finish.return_value) == argument + 7
        returned.append(argument + 7)
gdb.execute('continue')
assert exits == [0] and len(returned) == 6 and len(navigation) == 2
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'runtimeBiases': biases, 'returned': returned, 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('later-register-local-gdb=' + variant + ' PASS')

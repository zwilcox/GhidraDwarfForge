"""Compare original parameter values after the complete inline-assembly statement."""
import gdb
import json
import os
from pathlib import Path

case = Path(os.environ['FLOW_CASE'])
variant = os.environ['FLOW_VARIANT']
target = os.environ['FLOW_TARGET']
remote = os.environ.get('FLOW_REMOTE', '')
labels = json.loads((case / 'symbols.json').read_text())
model = json.loads((case / 'model.json').read_text())
compiler = variant == 'compiler'
gdb.execute('file ' + str(case / ('control.reference' if compiler else 'control.input')))
if not compiler:
    gdb.execute('symbol-file ' + str(case / (variant + '.dbg')))
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
points = []
started = bool(remote)
for expected in (19, -19):
    stop = gdb.Breakpoint('*boundary', internal=True)
    gdb.execute('continue' if started else 'run')
    started = True
    stop.delete()
    entry = int(gdb.parse_and_eval('&boundary'))
    bias = entry - labels['boundary']
    assert int(gdb.parse_and_eval('$pc')) == entry
    if model['role'] != 'exec':
        assert bias != 0
    for point in ('entry', 'after'):
        if point == 'after':
            stop = gdb.Breakpoint('*' + hex(labels['probe_after'] + bias), temporary=True, internal=True)
            gdb.execute('continue')
        variable = gdb.parse_and_eval('value')
        assert variable.type.sizeof == 4
        available = not variable.is_optimized_out
        value = int(variable) if available else None
        raw = int(gdb.parse_and_eval('(int)$' + ('esi' if target == 'x86_64' else 'w1')))
        assert raw == (expected if point == 'entry' else 0)
        if compiler:
            assert available and value == expected, (target, point, value, expected)
        elif variant == 'previous':
            assert available and value == raw, (target, point, value, raw)
        else:
            assert not available, (target, point, value)
        rendered = gdb.execute('ptype value', to_string=True)
        assert rendered.startswith('type = int')
        listing = gdb.execute('list boundary', to_string=True)
        assert 'boundary' in listing and 'No such file' not in listing
        points.append({'point': point, 'expectedOriginalParameter': expected, 'available': available,
            'value': value, 'rawRegister': raw, 'pc': int(gdb.parse_and_eval('$pc')), 'runtimeBias': bias})
    gdb.execute('finish')
    returned = int(gdb.parse_and_eval('(int)$' + ('eax' if target == 'x86_64' else 'w0')))
    assert returned == expected + 7
    points[-1]['returned'] = returned
gdb.execute('continue')
assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS',
    'previousBugReproduced': variant == 'previous', 'points': points, 'exitCodes': exits}, indent=4) + '\n')
print('outside-body-flow-gdb=' + variant + ' PASS')

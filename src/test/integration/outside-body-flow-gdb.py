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
    instructions = {row['address']: row for row in model['cases']['complete']['model']['instructions']}
    retained = {row['address'] for row in model['cases']['excluded']['model']['instructions'] if row['inBody']}
    arithmetic = instructions[labels['probe_after']]
    lost = arithmetic['next']
    raw_expected = expected
    visited = []
    while True:
        pc = int(gdb.parse_and_eval('$pc'))
        link = pc - bias
        assert link in instructions and len(visited) < 32, (variant, hex(link), visited)
        instruction = instructions[link]
        assert bytes(gdb.selected_inferior().read_memory(pc, len(bytes.fromhex(instruction['bytes'])))).hex() == instruction['bytes']
        visited.append(link)
        in_scope = compiler or variant == 'complete' or link in retained
        if in_scope:
            variable = gdb.parse_and_eval('value')
            assert variable.type.sizeof == 4
            available = not variable.is_optimized_out
            value = int(variable) if available else None
        else:
            # The excluded machine block still executes, but has no owning DIE.
            try:
                gdb.parse_and_eval('value')
            except gdb.error:
                pass
            else:
                raise AssertionError('excluded instruction acquired a scoped parameter')
            available = False
            value = None
        raw = int(gdb.parse_and_eval('(int)$' + ('esi' if target == 'x86_64' else 'w1')))
        backup = int(gdb.parse_and_eval('(int)$' + ('eax' if target == 'x86_64' else 'w0')))
        assert raw == raw_expected
        if compiler:
            # GCC does not describe each instruction inside one inline-asm statement.
            # Check its source boundaries; physical carrier checks below cover the interior.
            if link in (labels['boundary'], labels['probe_copy_done'], labels['probe_after']):
                assert available and value == expected, (target, link, value, expected)
            elif link == lost and available:
                assert value == expected
        elif variant == 'previous' and in_scope:
            assert available and value == raw, (target, link, value, raw)
        elif variant == 'complete':
            assert available == (link != lost), (target, link, value)
            if available:
                assert value == expected
        else:
            assert not available, (target, link, value)
        if link != labels['boundary'] and link >= labels['probe_copy_done']:
            assert backup == (expected + 7 if link == lost else expected)
        if link == labels['boundary']:
            rendered = gdb.execute('ptype value', to_string=True)
            assert rendered.startswith('type = int')
            listing = gdb.execute('list boundary', to_string=True)
            assert 'boundary' in listing and 'No such file' not in listing
        points.append({'linkPc': link, 'expectedOriginalParameter': expected, 'available': available,
            'value': value, 'rawRegister': raw, 'backupRegister': backup,
            'pc': pc, 'runtimeBias': bias, 'inScope': in_scope})
        if link == lost:
            break
        if link == labels['probe_hidden']:
            raw_expected = 0
        gdb.execute('stepi')
    assert set(visited) == set(instructions) and len(visited) == len(instructions)
    gdb.execute('finish')
    returned = int(gdb.parse_and_eval('(int)$' + ('eax' if target == 'x86_64' else 'w0')))
    assert returned == expected + 7
    points[-1]['returned'] = returned
gdb.execute('continue')
assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS',
    'previousBugReproduced': variant == 'previous', 'points': points, 'exitCodes': exits}, indent=4) + '\n')
print('outside-body-flow-gdb=' + variant + ' PASS')

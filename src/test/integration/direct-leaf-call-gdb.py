"""Compare actual argument values before/after a direct leaf call and its restore."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['CALL_CASE'])
variant = os.environ['CALL_VARIANT']
target = os.environ['CALL_TARGET']
model = json.loads((case / 'model.json').read_text())
function = next(f for f in model['functions'] if f['name'] == 'carry_across_call')
call, = [i for i in function['instructions'] if i['flow'] == 'UNCONDITIONAL_CALL']
restore, = [i for i in function['instructions'] if
    (target == 'x86_64' and i['text'].startswith('MOV RBX,')) or
    (target == 'aarch64' and i['text'].startswith('ldp x19,'))]
points = [('entry', function['entry']), ('call', call['address']),
    ('after-call', call['fallThrough']), ('before-restore', restore['address']),
    ('after-restore', restore['next'])]
binary = case / ('call.reference' if variant == 'compiler' else 'call.input')
sidecar = case / {'compiler': 'call.reference', 'forge': 'call.dbg', 'previous': 'previous.dbg'}[variant]
gdb.execute('file ' + str(binary))
gdb.execute('symbol-file ' + str(sidecar))
remote = os.environ.get('CALL_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
delta = model['rebaseDelta']
link_entry = int(function['entry'], 16) - delta
biases = []
rows = []
navigation = []
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
for iteration, argument in enumerate((17, -17, 0x1234567)):
    # Symbolic instruction breakpoints relocate at PIE startup; numeric link
    # addresses would incorrectly remain absolute runtime addresses.
    entry_breakpoint = gdb.Breakpoint('*carry_across_call', internal=True)
    gdb.execute('run' if iteration == 0 and not remote else 'continue')
    entry = int(gdb.parse_and_eval('&carry_across_call'))
    bias = entry - link_entry
    biases.append(bias)
    assert int(gdb.parse_and_eval('$pc')) == entry
    assert int(gdb.parse_and_eval('&perturb')) - bias == int(next(f for f in model['functions'] if f['name'] == 'perturb')['entry'], 16) - delta
    if model['role'] != 'exec':
        assert bias != 0, 'PIE test must observe a real runtime load bias'
    entry_breakpoint.delete()
    for index, (name, address) in enumerate(points):
        runtime_address = int(address, 16) - delta + bias
        breakpoint = gdb.Breakpoint('*' + hex(runtime_address), internal=True)
        if int(gdb.parse_and_eval('$pc')) != runtime_address:
            gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == runtime_address
        assert gdb.newest_frame().name() == 'carry_across_call'
        symbol, _ = gdb.lookup_symbol('value')
        assert symbol is not None and symbol.is_argument
        value = symbol.value(gdb.newest_frame())
        assert str(value.type) == 'int'
        if variant == 'previous' or (variant == 'forge' and name == 'after-restore'):
            assert value.is_optimized_out
        elif name != 'after-restore':
            assert not value.is_optimized_out and int(value) == argument
        elif not value.is_optimized_out:
            assert int(value) == argument
        row = {'iteration': iteration, 'input': argument, 'point': name, 'pc': hex(runtime_address), 'linkPc': hex(int(address, 16) - delta),
            'argument': str(value), 'unavailable': bool(value.is_optimized_out)}
        if 0 < index < 4:
            backup = int(gdb.parse_and_eval('$rbx' if target == 'x86_64' else '$x19')) & 0xffffffff
            assert backup == argument & 0xffffffff
            row['backupLow32'] = backup
        if index == 0:
            listing = gdb.execute('list carry_across_call', to_string=True)
            assert 'carry_across_call' in listing and 'No such file' not in listing
            assert 'int' in gdb.execute('ptype value', to_string=True)
        rows.append(row)
        breakpoint.delete()
        if iteration == 0 and index in (0, 1):
            # Guard instruction boundaries while exercising source commands.
            # A command may arrive at the next oracle PC; do not skip that PC.
            stop = int(call['address'] if index == 0 else call['fallThrough'], 16) - delta + bias
            guard = gdb.Breakpoint('*' + hex(stop), internal=True)
            command = 'next' if index == 0 else 'step'
            gdb.execute(command)
            frame = gdb.newest_frame().name()
            pc = int(gdb.parse_and_eval('$pc'))
            if index == 0:
                assert frame == 'carry_across_call' and entry < pc <= stop
            else:
                assert frame == 'perturb' or (frame == 'carry_across_call' and pc == stop)
            navigation.append({'command': command, 'function': frame, 'pc': pc})
            guard.delete()
    finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
    gdb.execute('continue')
    assert int(finish.return_value) == argument * 3 + 6
gdb.execute('continue')
assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'runtimeBiases': biases, 'returned': [57, -45, 0x1234567 * 3 + 6], 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('direct-leaf-call-gdb=' + variant + ' PASS')

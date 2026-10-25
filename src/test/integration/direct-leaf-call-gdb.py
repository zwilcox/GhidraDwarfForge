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
rows = []
navigation = []
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
for iteration, argument in enumerate((17, -17, 0x1234567)):
    for index, (name, address) in enumerate(points):
        breakpoint = gdb.Breakpoint('*0x' + address, internal=True)
        if iteration == index == 0:
            gdb.execute('run' if not remote else 'continue')
        elif int(gdb.parse_and_eval('$pc')) != int(address, 16):
            gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == int(address, 16)
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
        row = {'iteration': iteration, 'input': argument, 'point': name, 'pc': address,
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
            stop = call['address'] if index == 0 else call['fallThrough']
            guard = gdb.Breakpoint('*0x' + stop, internal=True)
            command = 'next' if index == 0 else 'step'
            gdb.execute(command)
            frame = gdb.newest_frame().name()
            pc = int(gdb.parse_and_eval('$pc'))
            if index == 0:
                assert frame == 'carry_across_call' and int(function['entry'], 16) < pc <= int(stop, 16)
            else:
                assert frame == 'perturb' or (frame == 'carry_across_call' and pc == int(stop, 16))
            navigation.append({'command': command, 'function': frame, 'pc': pc})
            guard.delete()
    finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
    gdb.execute('continue')
    assert int(finish.return_value) == argument * 3 + 6
gdb.execute('continue')
assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'returned': [57, -45, 0x1234567 * 3 + 6], 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('direct-leaf-call-gdb=' + variant + ' PASS')

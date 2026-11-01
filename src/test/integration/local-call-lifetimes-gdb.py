"""Observe compiler and exported later locals before, through and after real calls."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['LOCAL_CASE'])
target = os.environ['LOCAL_TARGET']
variant = os.environ['LOCAL_VARIANT']
baseline = os.environ.get('LOCAL_BASELINE') == '1'
labels = json.loads((case / 'boundaries.json').read_text())
model = json.loads((case / 'model.json').read_text())
binary = case / ('local.reference' if variant == 'compiler' else 'local.input')
gdb.execute('file ' + str(binary))
gdb.execute('symbol-file ' + str(case / ('local.reference' if variant == 'compiler' else 'local.dbg')))
remote = os.environ.get('LOCAL_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
register = 'r12' if target == 'x86_64' else 'x19'
rows, calls, returns, exits = [], [], [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for argument in (19, -19, -81985529216486895):
    for name, count in (('local_call_once', 1), ('local_call_twice', 2)):
        label = labels[name]
        stop = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        bias = int(gdb.parse_and_eval('&' + name)) - label['entry']
        assert model['role'] == 'exec' or bias != 0
        assert int(gdb.parse_and_eval('$pc')) - bias == label['entry']
        stop.delete()
        instructions = {i['address']: i for i in label['instructions']}
        callee = {i['address']: i for i in labels['inspected_leaf']['instructions']}
        call_count = 0
        for step in range(100):
            pc = int(gdb.parse_and_eval('$pc')) - bias
            if pc in callee:
                assert int(gdb.parse_and_eval('(long long)$' + register)) == argument + 7
                calls.append({'function': name, 'input': argument, 'pc': pc, 'held': argument + 7})
                gdb.execute('stepi')
                continue
            assert pc in instructions, (name, hex(pc))
            symbol, _ = gdb.lookup_symbol('held' if variant == 'compiler' else 'curated_held')
            assert symbol is not None and not symbol.is_argument
            value = symbol.value(gdb.newest_frame())
            available = not value.is_optimized_out
            proven = label['ready'] <= pc < label['lost']
            if variant == 'compiler':
                if label['before'] <= pc < label['lost']:
                    assert available and int(value) == (argument + 7 if proven else -12345), (name, pc, str(value))
            else:
                assert available == (proven and not baseline), (name, pc, available, proven, baseline)
                if available:
                    assert value.type.sizeof == 8 and int(value) == argument + 7
            if proven:
                assert int(gdb.parse_and_eval('(long long)$' + register)) == argument + 7
            if pc == label['after']:
                listing = gdb.execute('list ' + name, to_string=True)
                assert name in listing and 'No such file' not in listing
                assert gdb.execute('ptype ' + symbol.name, to_string=True).startswith('type = ')
            rows.append({'function': name, 'input': argument, 'pc': pc,
                'available': available, 'value': str(value), 'proven': proven})
            if pc == label['return']:
                break
            call_count += int(instructions[pc]['call'])
            gdb.execute('stepi')
        else:
            raise AssertionError('fixture did not return')
        assert call_count == count
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        expected = argument * 2 + 7 + count
        assert int(finish.return_value) == expected
        returns.append({'function': name, 'input': argument, 'value': expected, 'calls': count})
gdb.execute('continue')
assert exits == [0] and len(returns) == 6 and len(calls) > 0
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'calleePoints': calls, 'returned': returns, 'exitCodes': exits}, indent=4) + '\n')
print('local-call-lifetimes-gdb=' + variant + ' PASS')

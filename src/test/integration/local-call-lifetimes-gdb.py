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
outgoing = model['storage'] == 'outgoing'
stack = model['storage'] != 'register'
offsets = json.loads((case / 'stack-offsets.json').read_text())['functions'] if stack else {}
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
    for shape in (('overlap', 'adjacent', 'released', 'unknown') if outgoing else ('once', 'twice', 'alias') if stack else ('once', 'twice', 'branch', 'loop', 'split', 'clobber')):
        name = 'local_call_' + shape
        count = (2 if shape == 'twice' else 1 if shape == 'branch' and argument > 0 else
            2 if shape == 'branch' else (2 if argument > 0 else 3) if shape == 'loop' else 1)
        label = labels[name]
        stop = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        bias = int(gdb.parse_and_eval('&' + name)) - label['entry']
        assert model['role'] == 'exec' or bias != 0
        assert int(gdb.parse_and_eval('$pc')) - bias == label['entry']
        value_expression = ('*(long long*)' + hex(int(gdb.parse_and_eval('$sp')) + offsets[name])
            if stack else '(long long)$' + register)
        stop.delete()
        instructions = {i['address']: i for i in label['instructions']}
        callee = {i['address']: i for leaf in labels if leaf.startswith('inspected_') for i in labels[leaf]['instructions']}
        call_count = 0
        clobbers = 0
        callee_entry_sp = None
        visits = {}
        for step in range(100):
            pc = int(gdb.parse_and_eval('$pc')) - bias
            if pc in callee:
                raw = int(gdb.parse_and_eval(value_expression))
                changed = 909 if shape == 'alias' else 0
                if shape == 'overlap':
                    data = bytearray((argument + 7).to_bytes(8, 'little', signed=True))
                    data[2] = 0
                    changed = int.from_bytes(data, 'little', signed=True)
                if outgoing:
                    helper = labels['inspected_' + shape]
                    if pc == helper['entry']:
                        callee_entry_sp = int(gdb.parse_and_eval('$sp'))
                    if shape == 'released' and pc == helper['released']:
                        slot = int(gdb.parse_and_eval('&' + value_expression))
                        assert callee_entry_sp <= slot and int(gdb.parse_and_eval('$sp')) >= slot + 8
                    if pc == helper['written']:
                        assert int(gdb.parse_and_eval('$sp')) == callee_entry_sp
                    assert raw == (changed if shape == 'overlap' and pc >= helper['written'] else argument + 7)
                assert raw in ({argument + 7, changed} if shape in ('clobber', 'alias', 'overlap') else {argument + 7})
                clobbers += int(raw == changed and raw != argument + 7)
                calls.append({'function': name, 'input': argument, 'pc': pc, 'held': raw})
                gdb.execute('stepi')
                continue
            assert pc in instructions, (name, hex(pc))
            visits[pc] = visits.get(pc, 0) + 1
            symbol, _ = gdb.lookup_symbol('held' if variant == 'compiler' else 'curated_held')
            assert symbol is not None and not symbol.is_argument
            value = symbol.value(gdb.newest_frame())
            available = not value.is_optimized_out
            initialized = label['ready'] <= pc < label['lost']
            proven = any(low <= pc < high for low, high in label['available'])
            expected_value = 909 if shape == 'alias' and pc >= label['after'] else argument + 7
            if variant == 'compiler':
                if label.get('before', label['ready']) <= pc < label['lost']:
                    assert available and int(value) == (expected_value if initialized else -12345), (name, pc, str(value))
            else:
                assert available == (proven and not baseline), (name, pc, available, proven, baseline)
                if available:
                    assert value.type.sizeof == 8 and int(value) == expected_value
            if initialized:
                memory_value = expected_value
                if shape == 'overlap' and pc >= label['after']:
                    data = bytearray((argument + 7).to_bytes(8, 'little', signed=True))
                    data[2] = 0
                    memory_value = int.from_bytes(data, 'little', signed=True)
                assert int(gdb.parse_and_eval(value_expression)) == memory_value
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
        assert call_count == (1 if stack else count)
        assert (clobbers > 0) == (shape in ('clobber', 'alias') or shape == 'overlap' and argument < 0)
        if shape == 'loop':
            assert max(visits.values()) == count
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        expected = 909 + argument + 1 if shape == 'alias' else argument * 2 + 7 + count
        assert int(finish.return_value) == expected
        returns.append({'function': name, 'input': argument, 'value': expected, 'calls': count,
            'clobbers': clobbers, 'visits': visits})
gdb.execute('continue')
assert exits == [0] and len(returns) == (12 if outgoing else 9 if stack else 18) and len(calls) > 0
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': rows,
    'calleePoints': calls, 'returned': returns, 'exitCodes': exits}, indent=4) + '\n')
print('local-call-lifetimes-gdb=' + variant + ' PASS')

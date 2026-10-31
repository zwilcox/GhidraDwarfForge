"""Check formal prototypes, real calls and rejection without target-state changes."""
import gdb
import json
import os
from pathlib import Path

case = Path(os.environ['AGGREGATE_CASE'])
variant = os.environ['AGGREGATE_VARIANT']
metadata = json.loads((case / 'metadata.json').read_text())
mips = metadata['target'].startswith('mips')
compiler = variant == 'compiler'
gdb.execute('file ' + str(case / 'calls.input'))
gdb.execute('symbol-file ' + str(case / ('calls.reference' if compiler else 'calls.dbg')))
remote = os.environ.get('AGGREGATE_REMOTE', '')
if remote:
    gdb.execute('set sysroot ' + os.environ['AGGREGATE_SYSROOT'])
    gdb.execute('target remote ' + remote)
breakpoint = gdb.Breakpoint('marker', internal=True)
gdb.execute('continue' if remote else 'run')
breakpoint.delete()
counts = ['triple64_calls', 'triple32_calls', 'pair64_calls', 'scalar64_calls', 'words_calls']


def state():
    result = {name: int(gdb.parse_and_eval(name)) for name in counts + ['sink', 'pointer_data']}
    result.update({name: int(gdb.parse_and_eval('$' + name)) for name in ['pc', 'sp']})
    return result


initial = state()
assert [initial[name] for name in counts] == [1] * 5 and initial['sink'] == 127 and initial['pointer_data'] == 100
rows = []
for name, expression, fields, expected, count in [
        ('triple64', 'triple64(0x1122334455667788ULL,-19)', ('first', 'second', 'third'),
            [0x1122334455667788, 0x1122334455667775, 0x1122334455667788 ^ 0xffffffed], 'triple64_calls'),
        ('triple32', 'triple32(23U,7)', ('first', 'second', 'third'), [23, 30, 16], 'triple32_calls'),
        ('pair64', 'pair64(0x1122334455667788ULL,-19)', ('first', 'second'), [0x55667788, 0x11223331], 'pair64_calls'),
        ('scalar64', 'scalar64(0x1122334455667788ULL,-19)', (), [0x1122334455667775], 'scalar64_calls'),
        ('word_mix', 'word_mix(-3,23,FIRST,&pointer_data,19U)', ('first', 'second', 'third'), [97, 25, 19], 'words_calls')]:
    signature = gdb.parse_and_eval(name).type
    assert len(signature.fields()) == (5 if name == 'word_mix' else 2), str(signature)
    prototype = gdb.execute('ptype ' + name, to_string=True)
    listing = gdb.execute('list ' + name, to_string=True)
    assert name in listing and 'No such file' not in listing
    entry = int(gdb.parse_and_eval("&'" + name + "'"))
    bias = entry - metadata['symbols'][name]
    if metadata['role'] != 'exec':
        assert bias != 0
    before = state()
    row = {'name': name, 'entry': entry, 'bias': bias, 'prototype': prototype, 'before': before, 'expected': expected}
    blocked = mips and not compiler and name in ('triple64', 'pair64')
    if blocked:
        registers = ['a0', 'a1', 'a2', 'a3', 'v0', 'v1', 'ra', 'gp', 'sr', 'hi', 'lo']
        row['registersBefore'] = {register: int(gdb.parse_and_eval('$' + register)) for register in registers}
        row['stackBefore'] = bytes(gdb.selected_inferior().read_memory(before['sp'], 128)).hex()
    try:
        value = gdb.parse_and_eval(expression)
        row['returned'] = [int(value[field]) for field in fields] if fields else [int(value)]
    except gdb.error as error:
        row['error'] = str(error)
    after = state()
    row['after'] = after
    if blocked:
        assert 'does not follow the target calling convention' in row.get('error', '')
        assert after == before and 'returned' not in row
        row['registersAfter'] = {register: int(gdb.parse_and_eval('$' + register)) for register in registers}
        row['stackAfter'] = bytes(gdb.selected_inferior().read_memory(after['sp'], 128)).hex()
        assert row['registersBefore'] == row['registersAfter'] and row['stackBefore'] == row['stackAfter']
        row['status'] = 'REJECTED_WITHOUT_EXECUTION'
    else:
        assert 'error' not in row, row
        assert after == {**before, count: before[count] + 1}, (before, after)
        if mips and compiler and name in ('triple64', 'pair64'):
            assert row['returned'] != expected
            row['status'] = 'EXPECTED_COMPILER_TRANSFER_FAILURE'
        else:
            assert row['returned'] == expected, row
            row['status'] = 'PASS'
    rows.append(row)
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0], exits
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'calls': rows, 'exitCodes': exits,
    'scope': 'MIPS compiler wide-argument aggregate calls are negative controls' if mips else 'all calls pass'}, indent=4) + '\n')
print('AGGREGATE_RETURN_CALLS_PASS ' + variant)

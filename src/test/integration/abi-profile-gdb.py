"""Observe ordinary calls, then prove typed injected calls or rejection before execution."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ['ABI_PROFILE_CASE'])
variant = os.environ['ABI_PROFILE_VARIANT']
metadata = json.loads((case / 'metadata.json').read_text())
blocked = variant == 'fixed' and metadata['blocked']
gdb.execute('set pagination off')
gdb.execute('set confirm off')
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
ordinary = []
for name, values in [('fp_call', {'a': 21.5, 'b': -9.25}), ('integer_call', {'value': 5})]:
    stop = gdb.Breakpoint('*' + name, internal=True)
    gdb.execute('continue')
    stop.delete()
    assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&' + name))
    observed = {key: float(gdb.parse_and_eval(key)) if name == 'fp_call' else int(gdb.parse_and_eval(key))
        for key in values}
    assert observed == values, (name, observed)
    signature = gdb.parse_and_eval(name).type
    width = 8 if name == 'fp_call' else 4
    assert signature.target().sizeof == width and all(field.type.sizeof == width for field in signature.fields())
    prototype = gdb.execute('ptype ' + name, to_string=True)
    listing = gdb.execute('list ' + name, to_string=True)
    assert name in listing and 'No such file' not in listing
    ordinary.append({'function': name, 'values': observed, 'prototype': prototype, 'listing': listing})
stop = gdb.Breakpoint('*marker', internal=True)
gdb.execute('continue')
stop.delete()


def state():
    return {'a': float(gdb.parse_and_eval('seen_a')), 'b': float(gdb.parse_and_eval('seen_b')),
        'floatingCalls': int(gdb.parse_and_eval('floating_calls')), 'integerCalls': int(gdb.parse_and_eval('integer_calls')),
        'integer': int(gdb.parse_and_eval('seen_integer')), 'pc': int(gdb.parse_and_eval('$pc'))}


def machine():
    registers = {item.name: str(gdb.selected_frame().read_register(item.name))
        for item in gdb.selected_frame().architecture().registers()}
    stack = bytes(gdb.selected_inferior().read_memory(int(gdb.parse_and_eval('$sp')), 256)).hex()
    return {'registers': registers, 'stack': stack}


for name in ('seen_integer', 'floating_calls', 'integer_calls'):
    assert gdb.parse_and_eval(name).type.sizeof == 4
initial = state()
assert initial['a'] == 21.5 and initial['b'] == -9.25 and initial['integer'] == 5
assert initial['floatingCalls'] == initial['integerCalls'] == 1
calls = []
for expression, floating, expected in [('integer_call(19)', False, 26), ('fp_call(19.5,-3.25)', True, 16.25),
        ('integer_pointer(19)', False, 26), ('fp_pointer(19.5,-3.25)', True, 16.25)]:
    before, machine_before = state(), machine()
    record = {'expression': expression, 'before': before}
    try:
        value = gdb.parse_and_eval(expression)
        record['returned'] = float(value) if floating else int(value)
    except gdb.error as error:
        record['error'] = str(error)
    after = state()
    record['after'] = after
    (case / (variant + '-call-attempt.json')).write_text(json.dumps(record, indent=4) + '\n')
    if blocked:
        assert 'does not follow the target calling convention' in record.get('error', ''), record
        assert 'returned' not in record and before == after
        assert machine_before == machine(), 'rejected call changed registers or stack'
        record['unchangedRegistersAndStack'] = True
    else:
        assert 'error' not in record and record['returned'] == expected, record
        assert after == ({**before, 'a': 19.5, 'b': -3.25, 'floatingCalls': before['floatingCalls'] + 1} if floating else
            {**before, 'integer': 19, 'integerCalls': before['integerCalls'] + 1}), (before, after)
    record['after'] = after
    calls.append(record)
gdb.execute('continue')
assert exits == [0], exits
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant,
    'blocked': blocked, 'ordinary': ordinary, 'calls': calls, 'exitCodes': exits}, indent=4) + '\n')
print('abi-profile-gdb=' + variant + ' PASS')

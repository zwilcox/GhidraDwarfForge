"""Require no execution of an unsupported injected call, plus correct ordinary execution."""
import gdb
import json
import os
from pathlib import Path

case = Path(os.environ['POINTER_CASE'])
variant = os.environ['POINTER_VARIANT']
compiler = variant == 'compiler'
windows = json.loads((case / 'model.json').read_text())['compiler'] == 'windows'
gdb.execute('file ' + str(case / ('control.reference' if compiler else 'control.input')))
if not compiler:
    gdb.execute('symbol-file ' + str(case / (variant + '.dbg')))
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('start')
# Access counters through their executable symbols; they do not depend on recovered types.
counter = lambda name: int(gdb.parse_and_eval('*(int *)&' + name))
assert counter('sysv_calls') == counter('microsoft_calls') == 0


def snapshot():
    frame = gdb.selected_frame()
    # Include every readable architectural register and the complete writable
    # stack mapping; a refused call must not change either or either counter.
    registers = {item.name: str(frame.read_register(item.name))
        for item in frame.architecture().registers()}
    inferior = gdb.selected_inferior()
    stack_line, = [line for line in Path('/proc/' + str(inferior.pid) + '/maps').read_text().splitlines()
        if line.endswith('[stack]')]
    begin, end = [int(value, 16) for value in stack_line.split()[0].split('-')]
    import hashlib
    stack = hashlib.sha256(bytes(inferior.read_memory(begin, end - begin))).hexdigest()
    return {'registers': registers, 'stackBegin': begin, 'stackEnd': end, 'stackSha256': stack,
        'counters': {name: counter(name) for name in ('sysv_calls', 'microsoft_calls')}}


calls = []
for expression in ('sysv_function(1,2,3,4)', 'sysv_pointer(1,2,3,4)',
        'microsoft_function(1,2,3,4)', 'microsoft_pointer(1,2,3,4)'):
    gdb.execute('set $r8 = 8')
    gdb.execute('set $r9 = 9')
    before = snapshot()
    error = None
    injected = None
    try:
        injected = int(gdb.parse_and_eval(expression))
    except gdb.error as failure:
        error = str(failure)
    after = snapshot()
    # The previous exporter already guards direct functions, but loses the
    # same convention on the pointer type. GCC's DWARF loses it on both.
    microsoft = expression.startswith('microsoft')
    direct = '_function(' in expression
    rejected = not compiler and (microsoft or windows) and (variant == 'fixed' or direct)
    if rejected:
        assert error is not None and "does not follow the target calling convention" in error, error
        assert before == after, 'rejected call changed inferior state'
    else:
        assert error is None and injected == (4389 if microsoft else 1234), (error, injected)
        changed = 'microsoft_calls' if microsoft else 'sysv_calls'
        assert after['counters'] == {**before['counters'], changed: before['counters'][changed] + 1}
    calls.append({'expression': expression, 'returned': injected, 'error': error,
        'rejected': rejected, 'before': before, 'after': after})
observations = []
for name in ('sysv_function', 'microsoft_function'):
    stop = gdb.Breakpoint('*' + name, internal=True)
    gdb.execute('continue')
    stop.delete()
    assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&' + name))
    prototype = gdb.execute('ptype ' + name, to_string=True)
    assert 'int (int, int, int, int)' in prototype, prototype
    listing = gdb.execute('list ' + name, to_string=True)
    assert name in listing and 'No such file' not in listing
    values = [int(gdb.parse_and_eval('arg' + str(i))) for i in range(4)]
    assert values == [1, 2, 3, 4], (name, values)
    gdb.execute('finish')
    returned = int(gdb.parse_and_eval('(int)$eax'))
    assert returned == 1234
    observations.append({'name': name, 'entryValues': values, 'returnedRegisterValue': returned,
        'gdbReturnUnavailable': not compiler and (windows or name == 'microsoft_function'), 'prototype': prototype})
for prefix in ('sysv', 'microsoft'):
    assert counter(prefix + '_calls') == 1 + sum(
        not call['rejected'] for call in calls if call['expression'].startswith(prefix))
gdb.execute('continue')
assert exits == [0], exits
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant,
    'injectedCalls': calls,
    'ordinaryCalls': observations, 'exitCodes': exits}, indent=4) + '\n')
print('function-pointer-conventions-gdb=' + variant + ' PASS')

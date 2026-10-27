"""Require no execution of an unsupported injected call, plus correct ordinary execution."""
import gdb
import json
import os
from pathlib import Path

case = Path(os.environ['CONVENTION_CASE'])
variant = os.environ['CONVENTION_VARIANT']
compiler = variant == 'compiler'
gdb.execute('file ' + str(case / ('control.reference' if compiler else 'control.input')))
if not compiler:
    gdb.execute('symbol-file ' + str(case / (variant + '.dbg')))
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('start')
# Access counters through their executable symbols; they do not depend on recovered types.
counter = lambda name: int(gdb.parse_and_eval('*(int *)&' + name))
assert counter('sysv_calls') == counter('microsoft_calls') == 0
assert int(gdb.parse_and_eval('sysv_function(1,2,3,4)')) == 1234
assert counter('sysv_calls') == 1
# Deterministic unused-register sentinels make the old SysV-injected MS ABI call wrong.
gdb.execute('set $r8 = 8')
gdb.execute('set $r9 = 9')
error = None
injected = None
try:
    injected = int(gdb.parse_and_eval('microsoft_function(1,2,3,4)'))
except gdb.error as failure:
    error = str(failure)
if variant == 'fixed':
    assert error is not None and "does not follow the target calling convention" in error, error
    assert counter('microsoft_calls') == 0, 'rejected call executed target code'
else:
    # GCC's original DWARF also lacks the MS ABI classification: retain this limitation.
    assert error is None and injected == 4389, (error, injected)
    assert counter('microsoft_calls') == 1
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
        'gdbReturnUnavailable': variant == 'fixed' and name == 'microsoft_function', 'prototype': prototype})
assert counter('sysv_calls') == 2
assert counter('microsoft_calls') == (1 if variant == 'fixed' else 2)
gdb.execute('continue')
assert exits == [0], exits
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant,
    'injectedMicrosoftValue': injected, 'injectedMicrosoftError': error,
    'ordinaryCalls': observations, 'exitCodes': exits}, indent=4) + '\n')
print('calling-convention-gdb=' + variant + ' PASS')

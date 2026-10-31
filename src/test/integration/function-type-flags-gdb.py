"""Exercise variadic prototypes and ordinary non-returning pointer execution."""
import gdb
import json
import os
from pathlib import Path

case = Path(os.environ['TYPE_FLAGS_CASE'])
variant = os.environ['TYPE_FLAGS_VARIANT']
gdb.execute('file ' + str(case / 'flags.input'))
gdb.execute('symbol-file ' + str(case / ('flags.reference' if variant == 'compiler' else 'flags.dbg')))
gdb.execute('start')
rows = []
for name in ('known_variadic', 'variadic_pointer'):
    signature = gdb.parse_and_eval(name).type
    if name.endswith('_pointer'):
        signature = signature.target()
    assert signature.target().sizeof == 4
    prototype = gdb.execute('ptype ' + name, to_string=True)
    assert '...' in prototype and 'int' in prototype
    for arguments, expected in (('3,10,20,30', 60), ('1,29', 29)):
        value = int(gdb.parse_and_eval(name + '(' + arguments + ')'))
        assert value == expected
        rows.append({'name': name, 'arguments': arguments, 'returned': value, 'prototype': prototype})
assert int(gdb.parse_and_eval('*(int *)&variadic_calls')) == 4
stop = gdb.Breakpoint('*known_noreturn', internal=True)
gdb.execute('continue')
stop.delete()
assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&known_noreturn'))
# The existing lifetime policy omits this register-modified parameter. The
# entry register is an independent ABI oracle, not an invented DWARF location.
assert int(gdb.parse_and_eval('$edi')) == 0
parameter = gdb.parse_and_eval('code')
if variant == 'compiler':
    assert int(parameter) == 0
else:
    assert parameter.is_optimized_out
    report = json.loads((case / 'first-report.json').read_text())
    omission, = [row for row in report['omittedLocations']
        if row['function'] == 'known_noreturn' and row['variable'] == 'code']
    assert omission['reason'] == 'REGISTER_MODIFIED'

assert int(gdb.parse_and_eval('*(int *)&variadic_calls')) == 5
prototype = gdb.execute('ptype noreturn_pointer', to_string=True)
assert 'void (*)(int)' in prototype
assert int(gdb.parse_and_eval('(void *)noreturn_pointer')) == int(gdb.parse_and_eval('&known_noreturn'))
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'calls': rows,
    'noreturnPointerPrototype': prototype, 'ordinaryNoreturnArgumentRegister': 0, 'parameterUnavailable': variant != 'compiler', 'exitCodes': exits}, indent=4) + '\n')
print('function-type-flags-gdb=' + variant + ' PASS')

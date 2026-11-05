"""Instruction-correlated values and honest omissions in the producer fixture."""
import gdb

exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('info functions')
gdb.execute('list observed')
gdb.execute('ptype struct Node')
gdb.Breakpoint('*observed', temporary=True)
gdb.execute('run')
for name, expected in [('x', 41), ('moving', 41), ('counter', 23)]:
    gdb.execute('print ' + name)
    assert int(gdb.parse_and_eval(name)) == expected
for name in ['late', 'partial', 'mixed', 'no_storage', 'opaque_pointer', 'recursive']:
    assert gdb.parse_and_eval(name).is_optimized_out, name
gdb.execute('ptype opaque_pointer')
gdb.execute('stepi')
assert int(gdb.parse_and_eval('moving')) == 41
assert int(gdb.parse_and_eval('late')) == 41
assert int(gdb.parse_and_eval('$rax')) == 41
gdb.Breakpoint('*failed', temporary=True)
gdb.execute('next')
gdb.execute('step')
if int(gdb.parse_and_eval('$pc')) != int(gdb.parse_and_eval('&failed')):
    gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&failed'))
try:
    gdb.parse_and_eval('hidden')
except gdb.error as error:
    assert 'No symbol "hidden"' in str(error)
else:
    raise AssertionError('symbol-only failed function retained a parameter')
gdb.execute('continue')
assert exits == [0], exits
print('emission-evidence-gdb=PASS')

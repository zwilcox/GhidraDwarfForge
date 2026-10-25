"""GDB checks recovered scalar signatures and returns from ordinary fixture calls."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['RETURN_CASE'])
variant = os.environ['RETURN_VARIANT']
expected = {'recovered_signed': (gdb.TYPE_CODE_INT, 4, -41),
    'recovered_unsigned': (gdb.TYPE_CODE_INT, 4, 41),
    'recovered_double': (gdb.TYPE_CODE_FLT, 8, 1.75)}
rows = {}


def function_symbol(name):
    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
    assert symbol is not None and symbol.type.code == gdb.TYPE_CODE_FUNC, name
    return symbol


for name, (code, size, value) in expected.items():
    symbol = function_symbol(name)
    returned = symbol.type.target().strip_typedefs()
    rows[name] = {'returnType': str(returned), 'returnCode': returned.code, 'returnBytes': returned.sizeof}
    if variant == 'previous':
        assert returned.code == gdb.TYPE_CODE_VOID, (name, str(returned))
    else:
        # The optimized division is recovered as ulong, while compiler DWARF
        # records uint. Preserve that observed inference, never label it original.
        recovered_size = 8 if variant == 'forge' and name == 'recovered_unsigned' else size
        assert returned.code == code and returned.sizeof == recovered_size, (name, str(returned))
        if code == gdb.TYPE_CODE_INT:
            assert bool(gdb.Value(-1).cast(returned) < 0) == (name == 'recovered_signed')
        assert symbol.symtab is not None
        gdb.execute('list ' + name)
assert function_symbol('curated_pointer').type.target().strip_typedefs().code == gdb.TYPE_CODE_PTR
assert function_symbol('curated_void').type.target().strip_typedefs().code == gdb.TYPE_CODE_VOID
if variant != 'previous':
    exits = []
    gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
    started = False
    for name, (_, _, expected_value) in expected.items():
        breakpoint = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('continue' if started else 'run')
        started = True
        assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&' + name))
        breakpoint.delete()
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        returned = finish.return_value
        assert returned is not None
        actual = float(returned) if name == 'recovered_double' else int(returned)
        assert actual == expected_value, (name, actual)
        rows[name]['returnedValue'] = actual
    gdb.execute('next')
    if not exits:
        gdb.execute('step')
    if not exits:
        gdb.execute('continue')
    assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'variant': variant, 'status': 'PASS', 'functions': rows}, indent=4) + '\n')
print('recovered-return-gdb=' + variant + ' PASS')

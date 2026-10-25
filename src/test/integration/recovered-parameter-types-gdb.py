"""Inferred parameter types remain useful without asserting a storage lifetime."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['PARAMETER_CASE'])
variant = os.environ['PARAMETER_VARIANT']
expected = {'inferred_scalar': ('seed', gdb.TYPE_CODE_INT, 4, -123, -41),
    'inferred_pointer': ('cursor', gdb.TYPE_CODE_PTR, 8, 123, 41),
    'inferred_floating': ('scale', gdb.TYPE_CODE_FLT, 8, 1.5, 1.75)}
rows = {}


def function_symbol(name):
    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
    assert symbol is not None and symbol.type.code == gdb.TYPE_CODE_FUNC, name
    return symbol


for name, (_, code, size, _, _) in expected.items():
    symbol = function_symbol(name)
    rows[name] = {'prototype': gdb.execute('ptype ' + name, to_string=True)}
    fields = symbol.type.fields()
    if variant == 'previous':
        assert not fields, 'previous exporter unexpectedly recovered parameter types'
    else:
        field, = fields
        dtype = field.type.strip_typedefs()
        assert dtype.code == code and dtype.sizeof == size, (name, str(dtype))
        if code == gdb.TYPE_CODE_PTR:
            assert dtype.target().strip_typedefs().code == gdb.TYPE_CODE_INT
            assert dtype.target().sizeof == 4
        if code == gdb.TYPE_CODE_INT:
            assert gdb.Value(-1).cast(dtype) < 0
        rows[name]['type'] = str(dtype)
        gdb.execute('list ' + name)
if variant != 'previous':
    assert len(function_symbol('curated_scalar').type.fields()) == 1
    assert len(function_symbol('unresolved_pair').type.fields()) == (2 if variant == 'compiler' else 0)
    exits = []
    gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
    started = False
    for name, (original_name, code, _, argument, returned_value) in expected.items():
        breakpoint = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('continue' if started else 'run')
        started = True
        assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&' + name))
        breakpoint.delete()
        parameter_name = original_name if variant == 'compiler' else 'param_1'
        symbol, _ = gdb.lookup_symbol(parameter_name)
        assert symbol is not None and symbol.is_argument
        value = symbol.value(gdb.newest_frame())
        if variant == 'forge':
            assert value.is_optimized_out, (name, str(value))
            rows[name]['valueStatus'] = 'unavailable'
        else:
            assert not value.is_optimized_out
            actual = int(value.dereference()) if code == gdb.TYPE_CODE_PTR else float(value) if code == gdb.TYPE_CODE_FLT else int(value)
            assert actual == argument, (name, actual)
            rows[name]['argument'] = actual
        rows[name]['infoArgs'] = gdb.execute('info args', to_string=True)
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        result = finish.return_value
        assert result is not None
        actual = float(result) if code == gdb.TYPE_CODE_FLT else int(result)
        assert actual == returned_value, (name, actual)
        rows[name]['returnedValue'] = actual
    gdb.execute('next')
    if not exits:
        gdb.execute('step')
    if not exits:
        gdb.execute('continue')
    assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'variant': variant, 'status': 'PASS', 'functions': rows}, indent=4) + '\n')
print('recovered-parameter-gdb=' + variant + ' PASS')

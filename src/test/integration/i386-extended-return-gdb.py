"""Natural function entries and typed x87 returns; no injected calls or lifetime claim."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['I386_CASE'])
variant = os.environ['I386_VARIANT']
wide = os.environ.get('I386_TARGET', 'i386') == 'x86_64'
expected = [('scalar_float', 1.25, 2.5, 4.25), ('scalar_double', 8.5, 2.25, 6.5),
    ('scalar_extended', 1.25, 2.5, 3.875)]
if wide:
    # Cross-target check covers padded global types, not extended-return allocation.
    expected = expected[:2]
result = {'status': 'RUNNING', 'variant': variant, 'rows': []}
try:
    for command in ('set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set auto-solib-add off'):
        gdb.execute(command)
    gdb.execute('file ' + str(case / ('profile.reference' if variant == 'compiler' else 'profile.input')))
    if variant == 'forge':
        gdb.execute('symbol-file ' + str(case / 'profile.dbg'))
    # Resolve PIE addresses after the loader has selected the runtime load bias.
    gdb.execute('starti')
    for name, a, b, returned in expected:
        gdb.Breakpoint('*' + name, temporary=True)
        gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&' + name))
        actual = [float(gdb.parse_and_eval('a')), float(gdb.parse_and_eval('b'))]
        row = {'function': name, 'arguments': actual, 'expectedArguments': [a, b]}
        result['rows'].append(row)
        assert actual == [a, b], row
        expected_size = {'scalar_float': 4, 'scalar_double': 8, 'scalar_extended': 12}[name]
        row['argumentSize'] = int(gdb.parse_and_eval('sizeof(a)'))
        assert row['argumentSize'] == expected_size, row
        layout = {
            'sizeof(extended_global)': 16 if wide else 12,
            'sizeof(extended_array)': 48 if wide else 36,
            '(char *)&extended_array[1] - (char *)&extended_array[0]': 16 if wide else 12,
            'sizeof(extended_record)': 48 if wide else 20,
            '(char *)&extended_record.value - (char *)&extended_record': 16 if wide else 4,
            '(char *)&extended_record.tail - (char *)&extended_record': 32 if wide else 16,
            'extended_record.tag': 17, 'extended_record.tail': -23,
        }
        row['layout'] = {expr: int(gdb.parse_and_eval(expr)) for expr in layout}
        assert row['layout'] == layout, row
        values = {'extended_global': 6.25, 'extended_array[0]': 1.25,
            'extended_array[1]': 2.5, 'extended_array[2]': -4.0, 'extended_record.value': 8.75}
        row['floatingObjects'] = {expr: float(gdb.parse_and_eval(expr)) for expr in values}
        assert row['floatingObjects'] == values, row
        if name == 'scalar_extended' and not wide:
            # Require source-level stepping into the real helper using the emitted line table.
            for _ in range(24):
                gdb.execute('step')
                if gdb.newest_frame().name() == 'source_helper':
                    break
            else:
                raise AssertionError('source stepping did not enter the helper')
            row['helperValue'] = float(gdb.parse_and_eval('value'))
            assert row['helperValue'] == 3.75, row
            row['helperListing'] = gdb.execute('list source_helper', to_string=True)
            assert '__return_storage_ptr__' not in row['helperListing']
            helper_finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
            gdb.execute('continue')
            row['helperReturn'] = float(helper_finish.return_value)
            assert row['helperReturn'] == returned
            assert gdb.newest_frame().name() == 'scalar_extended'
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        row['returned'] = float(finish.return_value)
        row['expectedReturn'] = returned
        assert row['returned'] == returned, row
    gdb.execute('continue')
    result['exitCode'] = int(gdb.parse_and_eval('$_exitcode'))
    assert result['exitCode'] == 0
    result['status'] = 'PASS'
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

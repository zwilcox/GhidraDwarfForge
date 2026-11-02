"""Natural function entries and typed x87 returns; no injected calls or lifetime claim."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['I386_CASE'])
variant = os.environ['I386_VARIANT']
expected = [('scalar_float', 1.25, 2.5, 4.25), ('scalar_double', 8.5, 2.25, 6.5),
    ('scalar_extended', 1.25, 2.5, 3.875)]
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

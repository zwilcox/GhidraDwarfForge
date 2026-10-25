"""Complete ARM pair before overwrite; no surviving-piece claim afterward."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ['FORGE_TERMINAL_CASE'])
compiler = os.environ['FORGE_TERMINAL_MODE'] == 'compiler'
labels = dict((name, int(address, 16)) for name, address in
    (line.split() for line in (case / 'labels.txt').read_text().splitlines()))
gdb.Breakpoint('*terminal_pair', temporary=True)
gdb.execute('target remote ' + os.environ['FORGE_TERMINAL_REMOTE'])
gdb.execute('continue')
entry = int(gdb.parse_and_eval('&terminal_pair'))
assert int(gdb.parse_and_eval('$pc')) == entry
bias = entry - labels['terminal_pair']
rows = []
for marker in ('terminal_pair', 'terminal_pair_before', 'terminal_pair_write', 'terminal_pair_after'):
    pc = labels[marker] + bias
    if int(gdb.parse_and_eval('$pc')) != pc:
        gdb.Breakpoint('*' + hex(pc), temporary=True)
        gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == pc
    value = gdb.parse_and_eval('pair')
    assert value.type.sizeof == 8 and value.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT
    row = {'marker': marker, 'pc': pc, 'r0': int(gdb.parse_and_eval('$r0')) & 0xffffffff,
        'r1': int(gdb.parse_and_eval('$r1')) & 0xffffffff}
    if compiler and marker == 'terminal_pair':
        # GCC describes the aggregate's stack home even before its prologue
        # stores execute. This is a machine-argument observation, not a passing
        # compiler location oracle. Compare compiler fields after that prologue.
        assert [row['r0'], row['r1']] == [(-19 & 0xffffffff), 37], row
        row['compilerEntryObservation'] = str(value)
        row['compilerLocationValidated'] = False
    elif marker == 'terminal_pair_after':
        assert row['r0'] == 0
        if not compiler:
            assert value.is_optimized_out, str(value)
        row['available'] = not value.is_optimized_out
    else:
        assert not value.is_optimized_out
        row['fields'] = {name: int(value[name]) for name in ('low', 'high')}
        assert row['fields'] == {'low': -19, 'high': 37}, row
    if not compiler:
        assert gdb.selected_frame().find_sal().symtab.filename.endswith('terminal.dbg.c')
    rows.append(row)
assert int(gdb.parse_and_eval('terminal_pair_low')) == -19
assert int(gdb.parse_and_eval('terminal_pair_high')) == 37
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
result = {'status': 'PASS', 'compiler': compiler, 'bias': bias, 'points': rows}
Path(os.environ['FORGE_TERMINAL_RESULT']).write_text(json.dumps(result, indent=4) + '\n')

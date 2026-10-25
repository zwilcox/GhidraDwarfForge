"""Check actual mixed arguments, SP adjustment, and the conservative write boundary."""
import json
import os
from pathlib import Path
import re

import gdb

case = Path(os.environ['FORGE_MIXED_CASE'])
compiler = os.environ['FORGE_MIXED_MODE'] == 'compiler'
model = json.loads(Path(os.environ['FORGE_MIXED_MODEL']).read_text())
labels = dict((name, int(address, 16)) for name, address in
    (line.split() for line in (case / 'labels.txt').read_text().splitlines()))
store = next(instruction for instruction in model['instructions']
    if any('STORE' in operation for operation in instruction['pcode']))
store_pc = int(store['address'], 16) - model['rebaseDelta']
boundary = store_pc + store['length']
assert store['depth'] == -8 and store_pc == labels['mixed'] + 4
assert boundary == labels['mixed_before']
gdb.execute('ptype mixed')
listing = gdb.execute('list mixed', to_string=True)
assert 'mixed(' in listing
for line in listing.splitlines():
    if re.search(r'warning:|error:', line, re.IGNORECASE):
        # Preserve this exact synthetic decompiler comment as source content;
        # it is not a diagnostic emitted by GDB or the DWARF reader.
        assert re.fullmatch(r'\d+\s+/\* WARNING: Unknown calling convention(?: -- yet parameter storage is locked)? \*/', line), line
gdb.Breakpoint('*mixed', temporary=True)
gdb.execute('target remote ' + os.environ['FORGE_MIXED_REMOTE'])
gdb.execute('continue')
entry = int(gdb.parse_and_eval('&mixed'))
assert int(gdb.parse_and_eval('$pc')) == entry
bias = entry - labels['mixed']
expected = {'low': 0x12345678, 'high': -1234567}
rows = []
for index, address in enumerate((labels['mixed'], store_pc, boundary, labels['mixed_after'])):
    pc = address + bias
    if int(gdb.parse_and_eval('$pc')) != pc:
        gdb.Breakpoint('*' + hex(pc), temporary=True)
        gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == pc
    value = gdb.parse_and_eval('pair')
    assert value.type.sizeof == 8 and value.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT
    row = {'pc': pc, 'sp': int(gdb.parse_and_eval('$sp')), 'available': not value.is_optimized_out}
    if index < 2:
        offset = 0 if index == 0 else 8
        row['machine'] = {'low': int(gdb.parse_and_eval('$r3')),
            'high': int(gdb.parse_and_eval('*(int*)($sp+' + str(offset) + ')'))}
        assert row['machine'] == expected, row
        if compiler:
            # GCC names a stack home before storing the register half into it.
            # This is retained as an observation, never a compiler-value pass.
            row['compilerObservation'] = str(value)
            row['compilerLocationValidated'] = False
        else:
            assert not value.is_optimized_out, row
            row['fields'] = {name: int(value[name]) for name in expected}
            assert row['fields'] == expected, row
    elif compiler:
        assert not value.is_optimized_out, row
        row['fields'] = {name: int(value[name]) for name in expected}
        assert row['fields'] == expected, row
    else:
        assert value.is_optimized_out, row
    if not compiler:
        assert gdb.selected_frame().find_sal().symtab.filename.endswith('mixed.dbg.c')
    rows.append(row)
assert rows[1]['sp'] == rows[0]['sp'] - 8
assert {name: int(gdb.parse_and_eval('mixed_' + name)) for name in expected} == expected
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
Path(os.environ['FORGE_MIXED_RESULT']).write_text(json.dumps({'status': 'PASS', 'compiler': compiler,
    'bias': bias, 'points': rows, 'boundary': boundary, 'sourceListing': listing}, indent=4) + '\n')

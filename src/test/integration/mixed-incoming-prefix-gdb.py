"""Check every instruction through register/stack copies and the unknown-store gap."""
import importlib.util
import json
import os
from pathlib import Path
import re

import gdb

spec = importlib.util.spec_from_file_location('mixed_contract', Path(__file__).with_name('mixed_incoming_contract.py'))
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)

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
pie = case.name == 'pie'
code = bytes(gdb.selected_inferior().read_memory(entry, 44 if pie else 40))
contract.validate_code(code, pie, labels['mixed'], labels['mixed_low'])
assert labels['mixed_after'] == labels['mixed'] + 32
assert labels['mixed_high'] == labels['mixed_low'] + 4
rows = []
for offset in range(0, 40, 4):
    pc = entry + offset
    if int(gdb.parse_and_eval('$pc')) != pc:
        gdb.Breakpoint('*' + hex(pc), temporary=True)
        gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == pc
    value = gdb.parse_and_eval('pair')
    assert value.type.sizeof == 8 and value.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT
    row = {'pc': pc, 'offset': offset, 'sp': int(gdb.parse_and_eval('$sp')), 'available': not value.is_optimized_out}
    def stack(displacement):
        return int.from_bytes(gdb.selected_inferior().read_memory(row['sp'] + displacement, 4), 'little', signed=True)
    low = int(gdb.parse_and_eval('$r3')) if offset < 12 else (
        int(gdb.parse_and_eval('$r2')) if offset == 20 else stack(-4 if offset == 36 else 4))
    row['machine'] = {'low': low, 'high': stack(0 if offset in (0, 36) else 8)}
    assert row['machine'] == expected, row
    if offset >= 16:
        assert int(gdb.parse_and_eval('$r3')) == labels['mixed_low'] + bias
    if compiler and offset < 8:
        # GCC names a stack home before storing the register half into it.
        # This is retained as an observation, never a compiler-value pass.
        row['compilerObservation'] = str(value)
        row['compilerLocationValidated'] = False
    elif compiler or offset < 24:
        assert not value.is_optimized_out, row
        row['fields'] = {name: int(value[name]) for name in expected}
        assert row['fields'] == expected, row
    else:
        assert value.is_optimized_out and all(value[name].is_optimized_out for name in expected), row
    if not compiler:
        assert gdb.selected_frame().find_sal().symtab.filename.endswith('mixed.dbg.c')
    rows.append(row)
assert rows[1]['sp'] == rows[0]['sp'] - 8
assert rows[-1]['sp'] == rows[0]['sp']
assert {name: int(gdb.parse_and_eval('mixed_' + name)) for name in expected} == expected
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
Path(os.environ['FORGE_MIXED_RESULT']).write_text(json.dumps({'status': 'PASS', 'compiler': compiler,
    'bias': bias, 'points': rows, 'boundary': labels['mixed'] + 24, 'codeHex': code.hex(),
    'sourceListing': listing}, indent=4) + '\n')

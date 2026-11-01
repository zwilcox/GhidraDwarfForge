"""Exact entry/body argument checks; compiler entry displays remain observations."""
import gdb
import json
import math
import os
from pathlib import Path
case = Path(os.environ['MIPS_LAYOUT_CASE'])
mode = os.environ['MIPS_LAYOUT_MODE']
meta = json.loads((case / 'metadata.json').read_text())
expected = {'layout_array': {'value.elements[0]': 1.25, 'value.elements[1]': -2.5, 'tail': 11}, 'layout_union': {'value.first.value': 3.75, 'value.second': -4.5, 'tail': 13}, 'layout_nested': {'value.first.value': 5.25, 'value.second': -6.5, 'tail': 17}, 'layout_float_box': {'value.value': 7.75, 'tail': 19}, 'layout_small': {'value.elements[0]': 21, 'value.elements[1]': 23, 'value.elements[2]': 29, 'tail': 31}, 'layout_padded': {'value.first': 8.25, 'value.second': -9.5, 'tail': 37}, 'layout_aligned': {'lead': 41, 'value': 43 << 64 | 47, 'tail': 53}, 'layout_aligned_stack': dict(zip('abcdefgh', range(1, 9))) | {'lead': 59, 'value': 61 << 64 | 67, 'tail': 71}}
for command in ['set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set auto-solib-add off', 'set sysroot ' + meta['sysroot'], 'file ' + str(case / 'input'), 'symbol-file ' + str(case / ('reference' if mode == 'compiler' else 'input.dbg')), 'target remote ' + os.environ['MIPS_LAYOUT_REMOTE']]:
    gdb.execute(command)
rows = []
for name, values in expected.items():
    for point in ('entry', 'body'):
        address = meta['labels'][name + ('_body' if point == 'body' else '')]
        if point == 'entry' or address != meta['labels'][name]:
            gdb.Breakpoint('*' + hex(address), temporary=True, internal=True)
            gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == address
        observed = {}
        for expression, wanted in values.items():
            row = {'expected': wanted}
            try:
                value = gdb.parse_and_eval(expression)
                row['display'] = str(value)
                if value.is_optimized_out:
                    row['unavailable'] = True
                elif isinstance(wanted, float):
                    row['actual'] = float(value)
                    if not math.isfinite(row['actual']):
                        row['actual'] = row['display']
                elif value.type.sizeof > 8:
                    row['actual'] = int.from_bytes(value.bytes,
                        'big' if meta['endian'] == 'be' else 'little', signed=True)
                else:
                    row['actual'] = int(value)
                row['correct'] = row.get('actual') == wanted
            except gdb.error as error:
                row.update(error=str(error), correct=False)
            observed[expression] = row
        raw = {r: gdb.selected_frame().read_register(r).bytes.hex() for r in ['a' + str(i) for i in range(8)] + ['f' + str(i) for i in range(12, 20)] + ['sp']}
        pointer = int(gdb.parse_and_eval('$sp')) & (1 << (32 if meta['abi'] == 'n32' else 64)) - 1
        row = {'name': name, 'point': point, 'address': address, 'observed': observed, 'registers': raw, 'stack': bytes(gdb.selected_inferior().read_memory(pointer, 128)).hex()}
        rows.append(row)
        print('LAYOUT', mode, name, point, sum((v['correct'] for v in observed.values())), '/', len(observed))
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
assert len(rows) == 16
checks = 0
for row in rows:
    if mode == 'compiler' and row['point'] == 'entry':
        continue
    for expression, value in row['observed'].items():
        assert value['correct'], (row['name'], row['point'], expression, value)
        checks += 1
(case / (mode + '-observations.json')).write_text(json.dumps(rows, indent=4, allow_nan=False) + '\n')
print('MIPS_LAYOUT_' + mode.upper() + '_PASS checks=' + str(checks))

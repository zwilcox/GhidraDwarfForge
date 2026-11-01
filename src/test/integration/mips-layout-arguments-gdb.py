"""Exact entry/body argument checks; compiler entry displays remain observations."""
import gdb
import json
import math
import os
import re
from pathlib import Path
case = Path(os.environ['MIPS_LAYOUT_CASE'])
mode = os.environ['MIPS_LAYOUT_MODE']
meta = json.loads((case / 'metadata.json').read_text())
assert mode in ('compiler', 'forge')
failed = os.environ.get('MIPS_LAYOUT_FAILED_FUNCTION')
assert failed is None or (failed == 'layout_array' and mode == 'forge')
expected = {
    'layout_array': {'value.elements[0]': 1.25, 'value.elements[1]': -2.5, 'tail': 11},
    'layout_union': {'value.first.value': 3.75, 'value.second': -4.5, 'tail': 13},
    'layout_nested': {'value.first.value': 5.25, 'value.second': -6.5, 'tail': 17},
    'layout_float_box': {'value.value': 7.75, 'tail': 19},
    'layout_small': {'value.elements[0]': 21, 'value.elements[1]': 23, 'value.elements[2]': 29, 'tail': 31},
    'layout_padded': {'value.first': 8.25, 'value.second': -9.5, 'tail': 37},
    'layout_aligned': {'lead': 41, 'value': (43 << 64) | 47, 'tail': 53},
    'layout_aligned_stack': dict(zip('abcdefgh', range(1, 9))) | {'lead': 59, 'value': (61 << 64) | 67, 'tail': 71},
}
artifact = case / ('reference' if mode == 'compiler' else 'input.dbg')
shared = meta['role'].startswith('shared')
for command in ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
        'set auto-solib-add off', 'set sysroot ' + meta['sysroot'],
        'set solib-search-path ' + str(case), 'file ' + str(case / meta['runtime'])]:
    gdb.execute(command)
bias = 0
if meta['role'] == 'exec':
    gdb.execute('symbol-file ' + str(artifact))
gdb.execute('target remote ' + os.environ['MIPS_LAYOUT_REMOTE'])
if not shared and meta['role'] != 'exec':
    auxiliary = gdb.execute('info auxv', to_string=True)
    entry, = [line.split()[-1] for line in auxiliary.splitlines() if 'AT_ENTRY' in line]
    bias = int(entry, 16) - meta['entryAddress']
    assert bias > 0
    gdb.execute('symbol-file -o ' + hex(bias) + ' ' + str(artifact))
    (case / (mode + '-loader.json')).write_text(json.dumps(dict(
        bias=bias, linkEntry=meta['entryAddress'], runtimeEntry=int(entry, 16),
        auxiliaryVector=auxiliary), indent=4) + '\n')
if shared:
    gdb.Breakpoint('*main', temporary=True, internal=True)
    gdb.execute('continue')
    assert gdb.selected_frame().name() == 'main'
    libraries = gdb.execute('info sharedlibrary', to_string=True)
    library, = [line for line in libraries.splitlines() if line.split()[-1:] == [str(case / 'input')]]
    # GDB 17 reports the full mapped image range here, whereas older releases
    # reported text bounds. Derive the bias from the original image's actual
    # relocated .text section, before loading either DWARF artifact.
    sections = gdb.execute('maintenance info target-sections', to_string=True)
    (case / (mode + '-target-sections.txt')).write_text(sections)
    _, owned = sections.split("From '" + str(case / 'input') + "',", 1)
    owned = owned.split("\nFrom '", 1)[0]
    text, = re.findall(r'\.text\b[^\n]*\n\s*Start:\s*(0x[0-9a-f]+)', owned)
    text_address = int(text, 16)
    assert int(library.split()[0], 16) <= text_address < int(library.split()[1], 16)
    bias = text_address - meta['textAddress']
    assert bias > 0
    gdb.execute('add-symbol-file ' + str(artifact) + ' -o ' + hex(bias))
    (case / (mode + '-loader.json')).write_text(json.dumps(dict(
        bias=bias, textAddress=meta['textAddress'], runtimeTextAddress=text_address,
        sharedLibraries=libraries), indent=4) + '\n')
rows = []
for name, values in expected.items():
    for point in ('entry', 'body'):
        address = meta['labels'][name + ('_body' if point == 'body' else '')] + bias
        if point == 'entry' or address != meta['labels'][name] + bias:
            gdb.Breakpoint('*' + hex(address), temporary=True, internal=True)
            gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == address
        observed = {}
        for expression, wanted in values.items():
            if name == failed:
                try:
                    value = gdb.parse_and_eval(expression)
                except gdb.error as error:
                    assert 'No symbol' in str(error), str(error)
                else:
                    assert value.is_optimized_out, 'failed function retained a location'
                observed[expression] = dict(unavailable=True, failedDecompilation=True, correct=True)
                continue
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

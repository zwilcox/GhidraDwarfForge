"""Execute the exact Thumb tail through its original or exported alias name."""
import json
import os
from pathlib import Path
import gdb

root = Path(os.environ['BOUNDARY_CASE'])
variant = os.environ['BOUNDARY_VARIANT']
assert variant in ('reference', 'fixed')
reference = variant == 'reference'
conflict = os.environ.get('BOUNDARY_CONFLICT', 'none')
input_path = root / ('reference.elf' if reference else
    'mode-conflict.elf' if conflict != 'none' else 'sectionless.elf')
case = Path(os.environ['BOUNDARY_CASE'])
gdb.execute('file ' + str(input_path))
if not reference:
    gdb.execute('symbol-file ' + str(case / 'boundary.dbg'))
gdb.execute('set architecture armv7')
names = ['boundary'] if reference else ['boundary', 'recovered_boundary'] + ([] if conflict != 'none' else ['alternate_boundary'])
for name in names:
    assert int(gdb.parse_and_eval('&' + name)) == 0x101c
if not reference:
    if conflict != 'none':
        try:
            gdb.parse_and_eval('&alternate_boundary')
        except gdb.error as error:
            assert 'No symbol' in str(error), str(error)
        else:
            raise AssertionError('contradictory alias was emitted')
    assert 'int (int)' in gdb.execute('ptype recovered_boundary', to_string=True)
    listing = gdb.execute('list recovered_boundary', to_string=True)
    assert 'return value + 5;' in listing and 'No such file' not in listing
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('target remote ' + os.environ['BOUNDARY_REMOTE'])
entry = int(gdb.parse_and_eval('&boundary'))
bias = entry - 0x101c
assert bias != 0
decoded = gdb.selected_inferior().architecture().disassemble(entry, entry + 3)
if not reference and conflict == 'mapping':
    # The preserved wrong original mapping must remain observable. No instructions
    # have executed since attach, and this is not a passing Forge runtime case.
    assert int(gdb.parse_and_eval('$pc')) == bias + 0x1000
    assert len(decoded) == 1 and decoded[0]['addr'] == entry and decoded[0]['length'] == 4, decoded
    (case / 'fixed-gdb.json').write_text(json.dumps({'status': 'EXPECTED_MAPPING_DECODE_REJECTION',
        'instructions': decoded, 'alias': 'omitted', 'execution': 'stopped-before-first-continue'}, indent=4) + '\n')
    print('ARM_BOUNDARY_MAPPING_REJECTED')
    gdb.execute('disconnect')
    gdb.execute('quit')
assert [(row['addr'], row['length']) for row in decoded] == [(entry, 2), (entry + 2, 2)], decoded
assert decoded[-1]['asm'].split() == ['bx', 'lr'], decoded
breakpoint = gdb.Breakpoint('*' + ('boundary' if reference else 'recovered_boundary' if conflict != 'none' else 'alternate_boundary'), internal=True)
gdb.execute('continue')
breakpoint.delete()
assert int(gdb.parse_and_eval('$pc')) == entry
assert int(gdb.parse_and_eval('$r0')) == 7
if not reference:
    assert int(gdb.parse_and_eval('value')) == 7
    assert gdb.newest_frame().find_sal().symtab.filename.endswith('boundary.dbg.c')
gdb.execute('stepi')
assert int(gdb.parse_and_eval('$r0')) == 12
assert int(gdb.parse_and_eval('$pc')) == entry + 2
gdb.execute('stepi')
assert int(gdb.parse_and_eval('$pc')) == bias + 0x1008
gdb.execute('continue')
assert exits == [0], exits
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant, 'bias': bias,
    'names': names, 'instructions': decoded, 'argument': 7, 'return': 12, 'exit': 0}, indent=4) + '\n')
print('ARM_BOUNDARY_RUNTIME_PASS ' + variant)

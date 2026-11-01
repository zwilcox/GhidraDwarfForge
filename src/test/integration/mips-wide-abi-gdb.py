"""Source-known scalar values at entry and every visited instruction, in both ABIs."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ['FORGE_MIPS_WIDE_CASE'])
mode = os.environ['FORGE_MIPS_WIDE_MODE']
assert mode in ('compiler', 'forge')
phase = os.environ.get('FORGE_MIPS_WIDE_PHASE', 'instructions')
assert phase in ('instructions', 'source')
failed = os.environ.get('FORGE_MIPS_WIDE_FAILED_FUNCTION')
assert failed is None or failed == 'fp_float' and mode == 'forge'
result_prefix = mode + ('-source' if phase == 'source' else '')
metadata = json.loads((case / 'metadata.json').read_text())
shared = metadata['role'].startswith('shared')
prefix = 'curated_' if mode == 'forge' else ''
artifact = case / ('abi.reference' if mode == 'compiler' else 'abi.dbg')
for command in ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
        'set auto-solib-add off', 'set sysroot ' + metadata['sysroot'],
        'set solib-search-path ' + str(case), 'file ' + str(case / metadata['runtime'])]:
    gdb.execute(command)
if metadata['role'] == 'exec':
    gdb.execute('symbol-file ' + str(artifact))
gdb.execute('target remote ' + os.environ['FORGE_MIPS_WIDE_REMOTE'])
if not shared and metadata['role'] != 'exec':
    # With MIPS PIE, GDB 15 can relocate the symbols but retain a wrong frame
    # lookup when a separate symbol-file is supplied before remote attach.
    # Apply the actual loader bias explicitly; never suppress that warning.
    auxiliary = gdb.execute('info auxv', to_string=True)
    entry, = [line.split()[-1] for line in auxiliary.splitlines() if 'AT_ENTRY' in line]
    bias = int(entry, 16) - metadata['entryAddress']
    assert bias > 0
    gdb.execute('symbol-file -o ' + hex(bias) + ' ' + str(artifact))
    (case / (mode + '-loader.json')).write_text(json.dumps({
        'runtimeEntry': int(entry, 16), 'linkEntry': metadata['entryAddress'],
        'bias': bias, 'auxiliaryVector': auxiliary}, indent=4) + '\n')
if shared:
    stop = gdb.Breakpoint('*main', temporary=True, internal=True)
    gdb.execute('continue')
    assert gdb.selected_frame().name() == 'main'
    libraries = gdb.execute('info sharedlibrary', to_string=True)
    library, = [line for line in libraries.splitlines()
        if line.split()[-1:] == [str(case / 'abi.input')]]
    bias = int(library.split()[0], 16) - metadata['textAddress']
    assert bias > 0
    gdb.execute('add-symbol-file ' + str(artifact) + ' -o ' + hex(bias))

rows, bindings = [], {}
for function, expected, width in [('fp_float', (19.25, -7.5), 4), ('fp_double', (21.5, -9.25), 8)]:
    name = prefix + function
    start = int(gdb.parse_and_eval('&' + name))
    link = metadata['symbols'][function]
    current_bias = start - link
    assert (current_bias == 0) == (metadata['role'] == 'exec'), (name, current_bias)
    bindings[function] = current_bias
    assert len(set(bindings.values())) == 1
    if metadata['abi'] == 'n64' and metadata['role'] == 'exec':
        assert start > 0xffffffff
    if metadata['role'] != 'exec':
        assert current_bias == bias
    # Resolve a named breakpoint too, but enter at the raw function address so
    # source-row/prologue skipping cannot hide a wrong incoming location.
    named = gdb.Breakpoint(name, internal=True)
    assert named.locations and all(start <= location.address < start + metadata['sizes'][function]
        for location in named.locations)
    named.delete()
    gdb.Breakpoint('*' + hex(start), temporary=True, internal=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == start
    if function != failed:
        listing = gdb.execute('list ' + name, to_string=True)
        assert name in listing and 'No such file' not in listing
        assert ('float' if width == 4 else 'double') in gdb.execute('ptype first', to_string=True)
    end = start + metadata['sizes'][function]
    observed = 0
    for step in range(100):
        pc = int(gdb.parse_and_eval('$pc'))
        if not start <= pc < end:
            break
        values = {}
        for parameter, wanted in zip(('first', 'second'), expected):
            if function == failed:
                try:
                    gdb.parse_and_eval(parameter)
                except gdb.error as error:
                    assert 'No symbol' in str(error), str(error)
                else:
                    raise AssertionError('failed function retained a variable location')
                continue
            value = gdb.parse_and_eval(parameter)
            assert value.type.sizeof == width and not value.is_optimized_out
            assert float(value) == wanted, (mode, name, hex(pc), parameter, str(value))
            values[parameter] = float(value)
        rows.append({'function': function, 'pc': pc, 'values': values})
        observed += 1
        command = 'next' if phase == 'source' and step == 1 and function != failed else (
            'step' if phase == 'source' and step == 2 and function != failed else 'stepi')
        rows[-1]['command'] = command
        gdb.execute(command)
    else:
        raise AssertionError('instruction bound exceeded')
    assert observed >= 3
    for suffix, wanted in zip(('first', 'second'), expected):
        value = gdb.parse_and_eval(prefix + function + '_' + suffix)
        assert value.type.sizeof == width and float(value) == wanted
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
if phase == 'source':
    assert {'next', 'step'} <= {row['command'] for row in rows}
(case / (result_prefix + '-values.json')).write_text(json.dumps(rows, indent=4) + '\n')
(case / (result_prefix + '-biases.json')).write_text(json.dumps(bindings, indent=4) + '\n')
print('MIPS_WIDE_ABI_' + mode.upper() + '_PASS observations=' + str(len(rows)))

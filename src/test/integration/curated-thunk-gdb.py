"""Real native/QEMU thunk identity, source omission, argument and return oracle."""
import gdb
import json
import os
from pathlib import Path

case = Path(os.environ['THUNK_CASE'])
target = os.environ['THUNK_TARGET']
variant = os.environ['THUNK_VARIANT']
compiler = variant == 'compiler'
fixed = variant == 'fixed'
gdb.execute('file ' + str(case / ('control.reference' if compiler else 'control.input')))
if not compiler:
    gdb.execute('symbol-file ' + str(case / (variant + '.dbg')))
remote = os.environ.get('THUNK_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
name = 'analyst_gateway' if fixed else 'gateway'
symbol = gdb.lookup_global_symbol('analyst_gateway') or gdb.lookup_static_symbol('analyst_gateway')
assert (symbol is not None) == fixed
if fixed:
    prototype = gdb.execute('ptype analyst_gateway', to_string=True)
    assert 'int (int)' in prototype, prototype
stop = gdb.Breakpoint(name, internal=True)
gdb.execute('continue' if remote else 'run')
stop.delete()
entry = int(gdb.parse_and_eval('$pc'))
target_entry = int(gdb.parse_and_eval('&implementation'))
assert entry != target_entry
symbols = json.loads((case / 'symbols.json').read_text())
bias = target_entry - symbols['implementation']
assert int(gdb.parse_and_eval('&' + name)) == symbols['gateway'] + bias
# Break by name must select the actual transfer body, not a destination-derived row.
start = int(gdb.parse_and_eval('&' + name))
assert entry >= start
if fixed:
    assert entry == start
    assert gdb.find_pc_line(start).line == 0
    try:
        value = gdb.parse_and_eval('value')
        assert value.is_optimized_out, 'thunk parameter has an unproven location'
    except gdb.error as error:
        assert any(message in str(error) for message in ('optimized out', 'not available', 'requires a frame')), str(error)
raw = int(gdb.parse_and_eval('(int)$' + ('edi' if target == 'x86_64' else 'w0')))
assert raw == 19
steps = 0
while int(gdb.parse_and_eval('$pc')) != target_entry:
    gdb.execute('stepi')
    steps += 1
    assert steps <= 4
assert int(gdb.parse_and_eval('(int)$' + ('edi' if target == 'x86_64' else 'w0'))) == 19
if fixed:
    assert int(gdb.parse_and_eval('value')) == 19
    assert 'implementation' in gdb.execute('list implementation', to_string=True)
gdb.execute('finish')
assert int(gdb.parse_and_eval('(int)$' + ('eax' if target == 'x86_64' else 'w0'))) == 39
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant,
    'curatedNamePresent': fixed, 'bias': bias, 'entry': entry, 'target': target_entry, 'steps': steps,
    'argument': raw, 'return': 39, 'exitCodes': exits}, indent=4) + '\n')
print('curated-thunk-gdb=' + variant + ' PASS')

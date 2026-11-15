"""Cold lookup and actual tail-transfer behavior for isolated relationship DIEs."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['RELATION_CASE'])
target = os.environ['RELATION_TARGET']
variant = os.environ['RELATION_VARIANT']
symbols = json.loads((case / 'symbols.json').read_text())
compiler = variant == 'compiler'
names = ['gateway', 'implementation'] if compiler else ['analyst_alias', 'analyst_gateway', 'implementation', 'gateway']
lookup = {}
for name in names:
    expected = symbols['gateway' if name in ['gateway', 'analyst_gateway'] else 'implementation']['entry']
    address = int(gdb.parse_and_eval('&' + name))
    assert address == expected, (name, address, expected)
    prototype = gdb.execute('ptype ' + name, to_string=True)
    assert 'int (int)' in prototype, (name, prototype)
    stop = gdb.Breakpoint(name, internal=True)
    assert len(stop.locations) == 1, (name, stop.locations)
    if compiler:
        extent = symbols['gateway' if name == 'gateway' else 'implementation']['size']
        assert expected <= stop.locations[0].address < expected + extent
    else:
        assert stop.locations[0].address == expected, (name, stop.locations)
    stop.delete()
    lookup[name] = {'address': address, 'type': prototype}
remote = os.environ.get('RELATION_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
name = 'gateway' if compiler else 'analyst_gateway'
stop = gdb.Breakpoint(('*' if compiler else '') + name, internal=True)
gdb.execute('continue' if remote else 'run')
stop.delete()
pc = int(gdb.parse_and_eval('$pc'))
bias = pc - symbols['gateway']['entry']
destination = int(gdb.parse_and_eval('&implementation'))
assert destination == symbols['implementation']['entry'] + bias and pc != destination
argument_register = {'x86_64': 'edi', 'aarch64': 'w0'}[target]
return_register = {'x86_64': 'eax', 'aarch64': 'w0'}[target]
assert int(gdb.parse_and_eval('(int)$' + argument_register)) == 19
if not compiler:
    assert gdb.find_pc_line(pc).line == 0
    assert gdb.parse_and_eval('value').is_optimized_out, 'thunk borrowed a destination parameter location'
steps = 0
while int(gdb.parse_and_eval('$pc')) != destination:
    gdb.execute('stepi')
    steps += 1
    assert steps <= 4
assert int(gdb.parse_and_eval('(int)$' + argument_register)) == 19
gdb.execute('finish')
assert int(gdb.parse_and_eval('(int)$' + return_register)) == 39
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0]
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'variant': variant,
    'lookup': lookup, 'entry': pc, 'target': destination, 'bias': bias, 'steps': steps,
    'argument': 19, 'return': 39, 'exits': exits}, indent=4) + '\n')
print('function-relationships-gdb=' + variant + ' PASS')

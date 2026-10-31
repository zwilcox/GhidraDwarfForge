"""Check actual global identities without ELF symbol-table fallback."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['GLOBAL_CASE'])
mode = os.environ['GLOBAL_MODE']
target = os.environ['GLOBAL_TARGET']
remote = os.environ.get('GLOBAL_REMOTE', '')
symbols = json.loads((case / 'symbols.json').read_text())
expected = {'left::item': 17, 'right::item': 29, 'left::unique_value': 41, 'item': 53}
addresses = {}
for name in expected:
    assert 'int' in gdb.execute("ptype '" + name + "'", to_string=True)
    addresses[name] = int(gdb.parse_and_eval("&'" + name + "'"))
    assert addresses[name] == symbols[name], (name, addresses[name], symbols[name])
if mode == 'selected':
    assert 'int' in gdb.execute("ptype 'left::missing'", to_string=True)
    try:
        gdb.parse_and_eval("&'left::missing'")
    except gdb.error:
        pass
    else:
        raise AssertionError('addressless declaration gained an executable address')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*marker', temporary=True)
gdb.execute('continue' if remote else 'run')
values = {name: int(gdb.parse_and_eval("'" + name + "'")) for name in expected}
assert values == expected
short_unique = None
if mode == 'selected':
    short_unique = int(gdb.parse_and_eval('unique_value'))
    assert short_unique == 41 and int(gdb.parse_and_eval('item')) == 53
# Finish via a machine return register: the research function DIE is symbol-only.
gdb.execute('finish')
returned = int(gdb.parse_and_eval('(int)$' + ('eax' if target == 'x86_64' else 'w0')))
assert returned == 140
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0]
(case / (mode + '-runtime.json')).write_text(json.dumps({'status': 'PASS', 'values': values,
    'addresses': addresses, 'shortUnique': short_unique, 'return': returned, 'exitCodes': exits}, indent=4) + '\n')
print('namespace-global-runtime=' + mode + ' PASS')

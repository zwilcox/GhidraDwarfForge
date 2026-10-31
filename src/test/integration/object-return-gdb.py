"""Keep automatic object and return transport separate from name-only ordinary arguments."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['OBJECT_RETURN_CASE'])
mode = os.environ['OBJECT_RETURN_MODE']
target = os.environ['OBJECT_RETURN_TARGET']
remote = os.environ.get('OBJECT_RETURN_REMOTE', '')
labels = json.loads((case / 'labels.json').read_text())
if remote:
    gdb.execute('target remote ' + remote)
method = "'recovered::Counter::inspect_result'"
gdb.Breakpoint('*' + method, temporary=True)
gdb.execute('continue' if remote else 'run')
bias = int(gdb.parse_and_eval('$pc')) - labels['method']
carrier = int(gdb.parse_and_eval('$rdi' if target == 'x86_64' else '$x8'))
receiver = int(gdb.parse_and_eval('$rsi' if target == 'x86_64' else '$x0'))
assert receiver == int(gdb.parse_and_eval("&'recovered::object'"))
if mode == 'forge':
    assert int(gdb.parse_and_eval('this')) == receiver
    assert int(gdb.parse_and_eval('__return_storage_ptr__')) == carrier
    assert int(gdb.parse_and_eval('sizeof(*__return_storage_ptr__)')) == 24
    assert int(gdb.parse_and_eval('sizeof(*this)')) == 8
# Compiler source variables may use their post-prologue stack locations at entry.
# The oracle validates them after the compiler's labeled prologue instead.
gdb.Breakpoint('*' + hex(labels['object_return_live'] + bias), temporary=True)
gdb.execute('continue')
assert int(gdb.parse_and_eval('this')) == receiver
assert int(gdb.parse_and_eval('this->value')) == 7
assert int(gdb.parse_and_eval('amount')) == 3
prototype = gdb.execute('ptype ' + method, to_string=True)
assert '__return_storage_ptr__' not in prototype
listing = gdb.execute('list ' + method, to_string=True)
assert listing.strip()
return_pc = gdb.newest_frame().older().pc()
gdb.Breakpoint('*' + hex(return_pc), temporary=True, internal=True)
gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == return_pc
raw = bytes(gdb.selected_inferior().read_memory(carrier, 24))
fields = [int.from_bytes(raw[i:i + 8], 'little', signed=True) for i in range(0, 24, 8)]
assert fields == [10, 4, 21]
gdb.Breakpoint('*ordinary_roles', temporary=True)
gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == labels['ordinary'] + bias
gdb.Breakpoint('*' + hex(labels['ordinary_roles_live'] + bias), temporary=True)
gdb.execute('continue')
object_name, result_name = ('receiver', 'carrier') if mode == 'compiler' else ('this', '__return_storage_ptr__')
assert int(gdb.parse_and_eval(object_name + '->value')) == 7
assert int(gdb.parse_and_eval(result_name + '->first')) == 10
assert int(gdb.parse_and_eval('amount')) == 25
ordinary_prototype = gdb.execute('ptype ordinary_roles', to_string=True)
assert ordinary_prototype.count('*') == 2
return_pc = gdb.newest_frame().older().pc()
gdb.Breakpoint('*' + hex(return_pc), temporary=True, internal=True)
gdb.execute('continue')
returned = int(gdb.parse_and_eval('$rax' if target == 'x86_64' else '$x0'))
assert returned == 42
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0]
(case / (mode + '-observations.json')).write_text(json.dumps({'status': 'PASS', 'bias': bias,
    'receiver': receiver, 'carrier': carrier, 'aggregate': fields, 'ordinaryReturn': returned,
    'prototype': prototype, 'ordinaryPrototype': ordinary_prototype, 'exitCodes': exits}, indent=4) + '\n')
print('object-return-gdb=' + mode + ' PASS')

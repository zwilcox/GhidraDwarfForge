"""Distinguish same-named types through their actual objects and owning classes."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['SAME_TYPE_CASE'])
mode = os.environ['SAME_TYPE_MODE']
target = os.environ['SAME_TYPE_TARGET']
remote = os.environ.get('SAME_TYPE_REMOTE', '')
labels = json.loads((case / 'labels.json').read_text())
observations = []
if remote:
    gdb.execute('target remote ' + remote)
for index, (namespace, value, amount, returned, size) in enumerate([
        ('alpha', 7, 3, 10, 16), ('beta', 101, 5, 119, 24)]):
    method = "'" + namespace + "::Node::inspect'"
    gdb.Breakpoint('*' + method, temporary=True)
    gdb.execute('run' if index == 0 and not remote else 'continue')
    bias = int(gdb.parse_and_eval('$pc')) - labels[namespace + '.method']
    assert int(gdb.parse_and_eval('&' + method)) == labels[namespace + '.method'] + bias
    gdb.Breakpoint('*' + hex(labels[namespace + '_live'] + bias), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('this->value')) == value
    assert int(gdb.parse_and_eval('amount')) == amount
    assert int(gdb.parse_and_eval('sizeof(*this)')) == size
    assert int(gdb.parse_and_eval('this->next')) == int(gdb.parse_and_eval('this'))
    assert int(gdb.parse_and_eval('this->next->value')) == value
    assert int(gdb.parse_and_eval('this')) == int(gdb.parse_and_eval("&'" + namespace + "::object'"))
    for owner, expected, extent in [('alpha', 7, 16), ('beta', 101, 24)]:
        assert int(gdb.parse_and_eval("'" + owner + "::object'.value")) == expected
        assert int(gdb.parse_and_eval("sizeof('" + owner + "::object')")) == extent
    assert int(gdb.parse_and_eval("'beta::object'.extra")) == 13
    states = {}
    for owner, expected, spelling in [('alpha', 5, 'ALPHA_READY'), ('beta', 17, 'BETA_READY')]:
        state = gdb.parse_and_eval("'" + owner + "::state'")
        assert int(state) == expected and str(state).rsplit('::', 1)[-1] == spelling, (owner, int(state), str(state))
        states[owner] = {'value': int(state), 'spelling': str(state)}
    assert int(gdb.parse_and_eval('category_small.code')) == 23
    assert int(gdb.parse_and_eval('sizeof(category_small)')) == 4
    assert int(gdb.parse_and_eval('category_large.code')) == 0x112233445566
    assert int(gdb.parse_and_eval('category_large.extra')) == 31
    assert int(gdb.parse_and_eval('sizeof(category_large)')) == 16
    assert int(gdb.parse_and_eval('sizeof(category_small.code)')) == 4
    assert int(gdb.parse_and_eval('sizeof(category_large.code)')) == 8
    gdb.execute('list ' + method)
    # Preserve the exporter's existing no-injected-call policy for __thiscall.
    # Use the independently known fixture ABI to observe the executed return.
    return_pc = gdb.newest_frame().older().pc()
    gdb.Breakpoint('*' + hex(return_pc), temporary=True, internal=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == return_pc
    assert int(gdb.parse_and_eval('(int)$' + ('eax' if target == 'x86_64' else 'w0'))) == returned
    observations.append({'namespace': namespace, 'thisValue': value, 'amount': amount, 'return': returned,
        'size': size, 'recursiveValue': value, 'bias': bias, 'states': states,
        'smallCode': 23, 'largeCode': 0x112233445566, 'largeExtra': 31})
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0]
(case / (mode + '-observations.json')).write_text(json.dumps({'status': 'PASS', 'observations': observations,
    'exitCodes': exits}, indent=4) + '\n')
print('same-name-types-gdb=' + mode + ' PASS')

"""Read actual object/ordinary parameter values using compiler and Forge symbols."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_OBJECT_CASE'])
mode = os.environ['FORGE_OBJECT_MODE']
remote = os.environ.get('FORGE_OBJECT_REMOTE', '')
labels = json.loads((case / 'labels.json').read_text())
method = "'recovered::Counter::inspect_object'"
# Independent first queries are checked by check-class-first-lookup.py.
if mode == 'forge':
    class_text = gdb.execute("ptype 'recovered::Counter'", to_string=True)
    assert 'int value;' in class_text and 'inspect_object' in class_text
    assert 'int value;' in gdb.execute('ptype struct Counter', to_string=True)
if mode == 'unbound':
    class_text = gdb.execute("ptype 'recovered::Counter'", to_string=True)
    assert 'int value;' not in class_text and 'int first;' not in class_text
    assert 'int value;' in gdb.execute('ptype struct Counter', to_string=True)
if mode != 'failed':
    gdb.execute('ptype ' + method)
    gdb.execute('list ' + method)
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*' + method, temporary=True)
gdb.execute('continue' if remote else 'run')
bias = int(gdb.parse_and_eval('$pc')) - labels['method']
gdb.Breakpoint('*' + hex(labels['object_live'] + bias), temporary=True)
gdb.execute('continue')
if mode == 'failed':
    for name in ['this', 'amount']:
        try:
            gdb.parse_and_eval(name)
        except gdb.error as error:
            assert 'No symbol' in str(error), str(error)
        else:
            raise AssertionError('failed method acquired a parameter through its specification')
    class_text = gdb.execute("ptype 'recovered::Counter'", to_string=True)
    assert 'int value;' in class_text and 'inspect_object' not in class_text
    observations = [{'failedMethod': True, 'parametersAbsent': ['this', 'amount']}]
else:
    assert int(gdb.parse_and_eval('this->value')) == 7
    assert int(gdb.parse_and_eval('amount')) == 3
    assert 'Counter' in gdb.execute('ptype *this', to_string=True)
    observations = [{'objectValue': 7, 'amount': 3, 'objectPointer': str(gdb.parse_and_eval('this'))}]
assert 'inspect_object' in gdb.execute('bt 1', to_string=True)
gdb.Breakpoint('*' + hex(labels['ordinary_live'] + bias), temporary=True)
gdb.execute('continue')
name = 'value' if mode == 'compiler' else 'this'
assert int(gdb.parse_and_eval(name)) == 41
assert gdb.parse_and_eval(name).type.strip_typedefs().code == gdb.TYPE_CODE_INT
observations.append({'ordinaryName': name, 'ordinaryValue': 41})
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
(case / (mode + '-observations.json')).write_text(json.dumps(observations, indent=4) + '\n')
print('object-parameter-gdb=' + mode + ' PASS')

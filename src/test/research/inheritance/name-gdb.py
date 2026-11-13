"""Observe recovered class names through explicit human-readable vtable symbols."""
import json
import os
from pathlib import Path
import traceback
import gdb

result = {'status': 'FAIL'}
try:
    names = json.loads(Path(os.environ['INHERITANCE_NAMES']).read_text())
    remote = os.environ.get('INHERITANCE_REMOTE', '')
    if remote:
        gdb.execute('target remote ' + remote)
    gdb.Breakpoint('inheritance_checkpoint', temporary=True)
    gdb.execute('continue' if remote else 'run')
    expect_static = os.environ.get('INHERITANCE_EXPECT_STATIC') == '1'
    expected = names['static' if expect_static else 'dynamic']
    result['dynamicTypes'] = {variable: str(gdb.parse_and_eval(variable).dynamic_type).removeprefix('struct ')
        for variable in expected}
    assert result['dynamicTypes'] == {variable: item['name'] + ' *' for variable, item in expected.items()}, result
    result['layouts'] = {}
    for variable, item in expected.items():
        kind = gdb.parse_and_eval(variable).dynamic_type.target().strip_typedefs()
        members = [field.name for field in kind.fields() if not field.is_base_class]
        result['layouts'][variable] = {'size': kind.sizeof, 'members': members}
        assert kind.sizeof == item['size'] and members == item['members'], (variable, result['layouts'][variable], item)
    gdb.execute('set print object on')
    result['printed'] = {name: gdb.execute('print *' + name, to_string=True) for name in expected}
    if not expect_static:
        result['vtables'] = {name: gdb.execute('info vtbl *' + name, to_string=True) for name in expected}
        assert all('[0]:' in value for value in result['vtables'].values()), result
    values = {'single_object->base': 11, 'multiple_object->right': 17, 'diamond_object->root': 19,
        'virtual_left_object->root': 19, 'virtual_right_object->root': 19}
    assert {name: int(gdb.parse_and_eval(name)) for name in values} == values
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$_exitcode')) == 0
    result['status'] = 'PASS_STATIC_NAME_CONTROL' if expect_static else 'PASS_RECOVERED_VTABLE_NAMES'
except Exception:
    result['error'] = traceback.format_exc()
    raise
finally:
    Path(os.environ['INHERITANCE_RESULT']).write_text(json.dumps(result, indent=4) + '\n')

"""Observe runtime inheritance before broad type expansion can mask lookup gaps."""
import json
import os
from pathlib import Path
import traceback
import gdb

result = {'status': 'FAIL', 'queries': {}}
try:
    remote = os.environ.get('INHERITANCE_REMOTE', '')
    if remote:
        gdb.execute('target remote ' + remote)
    gdb.Breakpoint('inheritance_checkpoint', temporary=True)
    gdb.execute('continue' if remote else 'run')
    result['language'] = gdb.execute('show language', to_string=True)
    result['dynamicTypes'] = {name: str(gdb.parse_and_eval(name).dynamic_type)
        for name in ('single_base', 'multiple_right', 'diamond_base', 'diamond_right')}
    gdb.execute('set print object on')
    for query in ('print *single_base', 'print *multiple_right', 'print *diamond_base',
            'ptype Single', 'ptype Multiple', 'ptype Diamond', 'ptype struct Diamond',
            'info vtbl *single_base', 'info vtbl *multiple_right', 'info vtbl *diamond_base',
            'print single_base->base', 'print multiple_right->right', 'print diamond_object->root',
            'print diamond_right->root'):
        try:
            result['queries'][query] = {'result': gdb.execute(query, to_string=True)}
        except gdb.error as error:
            result['queries'][query] = {'error': str(error)}
    result['baseValues'] = {expression: int(gdb.parse_and_eval(expression)) for expression in (
        'single_base->base', 'multiple_right->right', 'diamond_base->root')}
    assert list(result['baseValues'].values()) == [11, 17, 19]
    result['offsets'] = {
        'multipleRight': int(gdb.parse_and_eval('(char*)multiple_right - (char*)multiple_object')),
        'diamondBase': int(gdb.parse_and_eval('(char*)diamond_base - (char*)diamond_object')),
        'diamondRight': int(gdb.parse_and_eval('(char*)diamond_right - (char*)diamond_object'))}
    assert all(value > 0 for value in result['offsets'].values())
    if os.environ['INHERITANCE_VARIANT'] == 'cpp':
        assert result['dynamicTypes'] == {'single_base': 'Single *', 'multiple_right': 'Multiple *',
            'diamond_base': 'Diamond *', 'diamond_right': 'Diamond *'}, result['dynamicTypes']
        assert all('error' not in value for value in result['queries'].values())
        assert int(gdb.parse_and_eval('diamond_right->root')) == 19
    if os.environ['INHERITANCE_VARIANT'].endswith('vtables'):
        assert {name: value.removeprefix('struct ') for name, value in result['dynamicTypes'].items()} == {
            'single_base': 'Single *', 'multiple_right': 'Multiple *',
            'diamond_base': 'Diamond *', 'diamond_right': 'Diamond *'}, result['dynamicTypes']
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$_exitcode')) == 0
    result['status'] = 'PASS_REFERENCE_OBSERVATION'
except Exception:
    result['error'] = traceback.format_exc()
    raise
finally:
    Path(os.environ['INHERITANCE_RESULT']).write_text(json.dumps(result, indent=4) + '\n')

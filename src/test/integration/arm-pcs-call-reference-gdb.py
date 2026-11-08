"""Independent compiler reference observations, including known consumer failures."""
import gdb
import json
import os
from pathlib import Path
import re

case = Path(os.environ['FORGE_CALL_CASE'])
mode = os.environ['FORGE_CALL_MODE']
operation = os.environ['FORGE_CALL_OPERATION']
result = {'status': 'STARTED', 'mode': mode, 'operation': operation, 'observations': []}

def value(expression):
    return float(gdb.parse_and_eval(expression))

try:
    gdb.execute('set arm fpu ' + mode)
    result['fpu'] = gdb.execute('show arm fpu', to_string=True)
    gdb.execute('target remote ' + os.environ['FORGE_CALL_REMOTE'])
    result['auxv'] = gdb.execute('info auxv', to_string=True)
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', result['auxv'])
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = gdb.selected_inferior().read_memory(result['vdsoAddress'], 4096).tobytes().hex()
    if operation == 'write':
        stop = gdb.Breakpoint('main')
        gdb.execute('continue')
        stop.delete()
        gdb.execute('set debug remote 1')
        gdb.execute('set $d0 = 1.25')
        gdb.execute('maintenance flush register-cache')
        result['registerBytes'] = gdb.parse_and_eval('$d0').bytes.hex()
        result['registerValue'] = value('$d0.f64')
        gdb.execute('set debug remote 0')
    elif operation == 'inject':
        stop = gdb.Breakpoint('main')
        gdb.execute('continue')
        stop.delete()
        for name, first, second in [('base_sum', 1.25, 2.5), ('vfp_sum', 3.25, 4.5)]:
            returned = value('%s(%sf, %sf)' % (name, first, second))
            result['observations'].append({'function': name, 'returned': returned,
                'seenFirst': value('seen_first'), 'seenSecond': value('seen_second'),
                'expected': [first, second, first + second]})
    else:
        for name, first, second in [('base_sum', 1.25, 2.5), ('vfp_sum', 3.25, 4.5)]:
            stop = gdb.Breakpoint(name)
            gdb.execute('continue')
            stop.delete()
            arguments = [value('first'), value('second')]
            assert arguments == [first, second]
            text = gdb.execute('finish', to_string=True)
            result['observations'].append({'function': name, 'arguments': arguments,
                'returned': value('$'), 'finish': text, 'expected': first + second,
                'r0': int(gdb.parse_and_eval('$r0')), 's0': value('$s0')})
    gdb.execute('continue')
    result['exitCode'] = int(gdb.parse_and_eval('$_exitcode'))
    assert result['exitCode'] == 0
    result['status'] = 'OBSERVED'
except Exception as error:
    result['status'] = 'ERROR'
    result['error'] = repr(error)
finally:
    (case / (operation + '-' + mode + '.json')).write_text(json.dumps(result, indent=4) + '\n')
if result['status'] == 'ERROR':
    raise gdb.GdbError(result['error'])

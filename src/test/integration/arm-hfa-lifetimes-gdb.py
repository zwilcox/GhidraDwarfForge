"""Immutable source-known HFA values through register copies and frame release."""
import gdb
import json
import os
from pathlib import Path
import struct
import re

case = Path(os.environ['FORGE_PCS_CASE'])
variant = os.environ['FORGE_PCS_VARIANT']
profile = json.loads((case / 'profile.json').read_text())
labels = json.loads((case / 'labels.json').read_text())
result = {'status': 'STARTED', 'variant': variant, 'observations': []}
order = '>' if profile['order'] == 'big' else '<'


def number(expression):
    return int(gdb.parse_and_eval(expression))


def floating(name, width):
    return struct.unpack(order + ('f' if width == 4 else 'd'), gdb.parse_and_eval('$' + name).bytes)[0]


try:
    gdb.execute('target remote ' + os.environ['FORGE_PCS_REMOTE'])
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', gdb.execute('info auxv', to_string=True))
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = gdb.selected_inferior().read_memory(result['vdsoAddress'], 4096).tobytes().hex()
    for name, width, expected in [('sum_floats', 4, [6.25, 7.5]), ('sum_doubles', 8, [1.25, 2.5])]:
        entry = labels[name]
        stop = gdb.Breakpoint('*' + hex(entry))
        gdb.execute('continue')
        stop.delete()
        for offset in range(0, 56, 4):
            assert number('$pc') == entry + offset
            prefix = 's' if width == 4 else 'd'
            first = prefix + '0' if offset <= 40 else ('s14' if width == 4 else 'd6')
            raw = [floating(first, width), floating(prefix + '1', width)]
            assert raw == expected, (name, offset, raw)
            row = {'name': name, 'offset': offset, 'raw': raw}
            # Compiler stack locations are initialized at offset 28. They cease
            # to be a reliable reference after frame release, so use the actual
            # source-known surviving register values at those boundaries.
            if variant == 'forge' or 28 <= offset <= 44:
                value = gdb.parse_and_eval('value')
                assert not value.is_optimized_out, (name, offset)
                typed = [float(value[field]) for field in ('first', 'second')]
                assert typed == expected, (name, offset, typed)
                row['typed'] = typed
            result['observations'].append(row)
            gdb.execute('stepi', to_string=True)
        assert not entry <= number('$pc') < entry + 56
        assert floating('s0' if width == 4 else 'd0', width) == sum(expected)
    gdb.execute('continue')
    assert number('$_exitcode') == 0
    result['status'] = 'PASS_HFA_LIFETIMES'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

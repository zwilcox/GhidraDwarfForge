"""Observe D/Q alias read/write round trips without depending on a recovered sidecar."""
import gdb
import json
import os
from pathlib import Path
import re
import struct

case = Path(os.environ['FORGE_PCS_CASE'])
profile = json.loads((case / 'profile.json').read_text())
big = profile['order'] == 'big'
result = {'status': 'STARTED', 'order': profile['order'], 'readAliases': [], 'writeAliases': []}
try:
    gdb.execute('target remote ' + os.environ['FORGE_PCS_REMOTE'])
    result['auxv'] = gdb.execute('info auxv', to_string=True)
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', result['auxv'])
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = gdb.selected_inferior().read_memory(result['vdsoAddress'], 4096).tobytes().hex()
    stop = gdb.Breakpoint('marker')
    gdb.execute('continue')
    stop.delete()
    result['registerDescriptions'] = gdb.execute('maintenance print raw-registers', to_string=True)
    gdb.execute('set debug remote 1')
    for index in range(32):
        gdb.execute('set $d%d = %s' % (index, index + 1.25))
    gdb.execute('maintenance flush register-cache')
    for index in range(16):
        pair = [index * 2 + 1.25, index * 2 + 2.25]
        expected = struct.pack('>dd' if big else '<dd', *(pair[::-1] if big else pair)).hex()
        actual = gdb.parse_and_eval('$q' + str(index)).bytes.hex()
        result['readAliases'].append({'q': index, 'expected': expected, 'actual': actual})
    for index in range(16):
        pair = [index * 2 + 101.5, index * 2 + 102.5]
        for lane, value in enumerate(pair):
            bits = struct.unpack('>Q', struct.pack('>d', value))[0]
            gdb.execute('set $q%d.u64[%d] = 0x%x' % (index, 1 - lane if big else lane, bits))
        gdb.execute('maintenance flush register-cache')
        actual = [float(gdb.parse_and_eval('$d%d.f64' % (index * 2 + lane))) for lane in range(2)]
        result['writeAliases'].append({'q': index, 'expected': pair, 'actual': actual})
    gdb.execute('set debug remote 0')
    gdb.execute('continue')
    result['exitCode'] = int(gdb.parse_and_eval('$_exitcode'))
    assert result['exitCode'] == 0
    result['status'] = 'OBSERVED'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / 'alias-observations.json').write_text(json.dumps(result, indent=4) + '\n')

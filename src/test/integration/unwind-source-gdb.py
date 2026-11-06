"""Exercise synthetic source lookup and stepping alongside recovered frame data."""
import json
import os
from pathlib import Path

import gdb

remote = os.environ.get('FORGE_FRAME_REMOTE', '')
shared = os.environ.get('FORGE_FRAME_SHARED') == '1'
artifact = Path(os.environ['FORGE_FRAME_SYMBOLS'])
source = Path(str(artifact) + '.c')
if remote:
    gdb.execute('target remote ' + remote)
if shared:
    gdb.Breakpoint('cfi_ready', temporary=True)
    gdb.execute('continue' if remote else 'run')
    bias = int(gdb.parse_and_eval('cfi_module_bias'))
    gdb.execute('add-symbol-file "' + str(artifact) + '" -o ' + hex(bias))
functions = gdb.execute('info functions cf_recurse', to_string=True)
assert 'cf_recurse' in functions
listing = gdb.execute('list cf_recurse', to_string=True)
assert 'cf_recurse' in listing and 'No such file' not in listing
signature = gdb.execute('ptype cf_recurse', to_string=True)
assert 'type = ' in signature
gdb.Breakpoint('cf_recurse', temporary=True)
gdb.execute('continue' if remote or shared else 'run')


def position():
    frame = gdb.newest_frame()
    sal = frame.find_sal()
    assert sal.symtab is not None and Path(sal.symtab.fullname()).resolve() == source.resolve()
    assert 0 < sal.line <= len(source.read_text().splitlines())
    return {'function': frame.name(), 'pc': int(frame.pc()), 'line': sal.line}


positions = [position()]
for command in ('next', 'step'):
    gdb.execute(command)
    positions.append(position())
assert all(left['pc'] != right['pc'] for left, right in zip(positions, positions[1:])), positions
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
Path(os.environ['FORGE_FRAME_RESULT']).write_text(json.dumps({
    'status': 'PASS_SOURCE_WITH_FRAMES', 'positions': positions, 'signature': signature,
    'source': str(source), 'exitcode': 0}, indent=4) + '\n')
print('native-frame-source=PASS')

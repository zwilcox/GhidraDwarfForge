"""Observe an inherited unavailable register without fabricating an outer frame."""
import json
import os
from pathlib import Path

import gdb

assert os.environ['FORGE_FRAME_TARGET'] == 'aarch64'
remote = os.environ.get('FORGE_FRAME_REMOTE', '')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*cf_checkpoint', temporary=True)
gdb.execute('continue' if remote else 'run')
rows = []
failure = None
frame = gdb.newest_frame()
while frame is not None and len(rows) < 8:
    try:
        rows.append({'name': frame.name(), 'pc': int(frame.pc()), 'witness': int(frame.read_register('x19'))})
        if rows[-1]['name'] == '_start':
            break
        frame = frame.older()
    except gdb.error as error:
        failure = str(error)
        break
assert failure == 'Register 29 was not saved', (rows, failure)
assert [row['name'] for row in rows] == ['cf_checkpoint'] + ['cf_recurse'] * 3
assert [row['witness'] for row in rows] == [0x5100, 0x5100, 0x5101, 0x5102]
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
Path(os.environ['FORGE_FRAME_RESULT']).write_text(json.dumps({
    'status': 'PASS_INHERITED_UNAVAILABLE_CONTROL', 'frames': rows, 'error': failure, 'exitcode': 0}, indent=4) + '\n')
print('inherited-unavailable-control=PASS')

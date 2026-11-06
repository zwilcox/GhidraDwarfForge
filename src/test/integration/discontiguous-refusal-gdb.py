"""Observe fallback selection at a deliberately unproved function's real PC."""
import json
import os
from pathlib import Path
import gdb

remote = os.environ.get('FORGE_FRAME_REMOTE', '')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*cf_gap_after', temporary=True)
gdb.execute('continue' if remote else 'run')
assert gdb.newest_frame().name() == 'cf_recurse'
gdb.execute('set debug frame 1')
gdb.execute('maintenance flush register-cache')
# Ask for a caller so GDB must actually select an unwinder. Whether fallback
# recovers the entire chain is outside this intentionally omitted frame's claim.
gdb.newest_frame().older()
gdb.execute('set debug frame 0')
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
Path(os.environ['FORGE_FRAME_RESULT']).write_text(json.dumps({'status': 'PASS_REFUSED_FRAME_RUNTIME', 'exitcode': 0}) + '\n')

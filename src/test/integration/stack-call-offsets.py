"""Derive saved stack offsets from the compiler's real DWARF and process memory."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['LOCAL_CASE'])
target = os.environ['LOCAL_TARGET']
labels = json.loads((case / 'boundaries.json').read_text())
gdb.execute('file ' + str(case / 'local.reference'))
remote = os.environ.get('LOCAL_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
offsets, observations, exits = {}, [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for argument in (19, -19, -81985529216486895):
    for name in ('local_call_once', 'local_call_twice', 'local_call_alias'):
        stop = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        entry_sp = int(gdb.parse_and_eval('$sp'))
        bias = int(gdb.parse_and_eval('&' + name)) - labels[name]['entry']
        stop.delete()
        stop = gdb.Breakpoint('*' + hex(labels[name]['ready'] + bias), internal=True)
        gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == labels[name]['ready'] + bias
        assert int(gdb.parse_and_eval('held')) == argument + 7
        address = int(gdb.parse_and_eval('&held'))
        offset = address - entry_sp
        assert -4096 < offset < 0
        assert name not in offsets or offsets[name] == offset
        offsets[name] = offset
        observations.append({'function': name, 'input': argument, 'entrySp': entry_sp,
            'address': address, 'offset': offset, 'value': argument + 7})
        stop.delete()
gdb.execute('continue')
assert exits == [0] and len(observations) == 9
(case / 'stack-offsets.json').write_text(json.dumps({'status': 'PASS', 'functions': offsets,
    'observations': observations, 'exitCodes': exits}, indent=4) + '\n')
print('stack-call-offsets=PASS')

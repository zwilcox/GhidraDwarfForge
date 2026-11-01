"""Compiler and Forge must select distinct static storage as lexical visibility changes."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_STATIC_CASE'])
mode = os.environ['FORGE_STATIC_MODE']
labels = json.loads((case / 'labels.json').read_text())
remote = os.environ.get('FORGE_STATIC_REMOTE', '')
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute('ptype scoped_statics')
if mode not in ['isolated', 'failed', 'memory-failed']:
    gdb.execute('list scoped_statics')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*scoped_statics', temporary=True)
gdb.execute('continue' if remote else 'run')
bias = int(gdb.parse_and_eval('$pc')) - labels['scoped_statics']
observations = []
objects = {}
sequence = [('root_live', 'root', 11), ('outer_begin', 'outer', 21), ('inner_begin', 'inner', 31),
    ('inner_end', 'outer', 21), ('outer_end', 'root', 11), ('sibling_begin', 'sibling', 41),
    ('sibling_end', 'root', 11), ('other_live', 'other', 51), ('global_live', 'global', 101)]
expected = None if mode == 'compiler' else json.loads((case / 'compiler-objects.json').read_text())
for marker, scope, value in sequence:
    if mode == 'stale' and scope == 'inner':
        scope, value = 'outer', 21
    if mode == 'conflict' and scope in ['inner', 'sibling']:
        scope, value = ('outer', 21) if scope == 'inner' else ('root', 11)
    if mode == 'coalesced' and scope in ['outer', 'inner', 'sibling']:
        scope, value = 'root', 11
    if mode in ['failed', 'memory-stale', 'memory-failed'] and scope in ['root', 'outer', 'inner', 'sibling']:
        scope, value = 'global', 101
    if mode in ['inferred-stale', 'inferred-namespace', 'inferred-overlap'] and scope == 'other':
        scope, value = 'global', 101
    pc = labels[marker] + bias
    gdb.Breakpoint('*' + hex(pc), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == pc
    current = gdb.parse_and_eval('shadow')
    assert int(current) == value and current.type.sizeof == 4, (marker, str(current), value)
    address = int(current.address) - bias
    if scope in objects:
        assert objects[scope] == address
    objects[scope] = address
    if expected is not None:
        assert expected[scope] == address, (scope, address, expected)
    assert 'int' in gdb.execute('ptype shadow', to_string=True)
    observations.append({'marker': marker, 'scope': scope, 'value': int(current), 'address': address, 'runtimePc': pc, 'bias': bias})
    # Execute the actual marker instruction before selecting the next lexical boundary.
    gdb.execute('stepi')
assert len(set(objects.values())) == {'stale': 5, 'conflict': 4, 'coalesced': 3, 'failed': 2,
    'memory-stale': 2, 'memory-failed': 2, 'inferred-stale': 5, 'inferred-namespace': 5, 'inferred-overlap': 5}.get(mode, 6)
if mode == 'compiler':
    (case / 'compiler-objects.json').write_text(json.dumps(objects, indent=4) + '\n')
gdb.execute('continue')
assert exits == [0], exits
(case / (mode + '-observations.json')).write_text(json.dumps(observations, indent=4) + '\n')
print('lexical-statics-gdb=' + mode + ' PASS')

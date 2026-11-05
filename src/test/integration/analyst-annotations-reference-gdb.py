"""Compiler-reference oracle; no claim about Forge annotation export."""
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ['FORGE_ANNOTATION_CASE'])
remote = os.environ.get('FORGE_ANNOTATION_REMOTE', '')
observations = {}
exits = []


def exited(event):
    exits.append(getattr(event, 'exit_code', None))


gdb.events.exited.connect(exited)
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*annotation_live')
gdb.execute('continue' if remote else 'run')
assert gdb.selected_frame().name() == 'annotation_probe'
labels = json.loads((case / 'labels.json').read_text())
runtime = int(gdb.parse_and_eval('&annotation_probe'))
elf_type = int.from_bytes((case / 'reference').read_bytes()[16:18],
    'little' if (case / 'reference').read_bytes()[5] == 1 else 'big')
assert (runtime == labels['annotation_probe']['address']) == (elf_type == 2)
(case / 'runtime-address.json').write_text(json.dumps({
    'linkTime': labels['annotation_probe']['address'], 'runtime': runtime,
    'loadBias': runtime - labels['annotation_probe']['address']}, indent=4) + '\n')
expected = {
    'input': (7, 4),
    'sum': (49, 4),
    'ANNOTATION_LOCAL': (11, 4),
    'ANNOTATION_COLLISION': (101, 4),
    'annotation_s8': (-7, 1),
    'annotation_u8': (255, 1),
    'annotation_s16': (-(1 << 15), 2),
    'annotation_u16': ((1 << 16) - 1, 2),
    'annotation_s32': (-(1 << 31), 4),
    'annotation_u32': ((1 << 32) - 1, 4),
    'annotation_s64': (-(1 << 63), 8),
    'annotation_u64': ((1 << 64) - 1, 8),
    'ANNOTATION_ENUM_COLLISION': (3, 4),
    'annotation_object.member': (5, 4),
}
for expression, (number, size) in expected.items():
    value = gdb.parse_and_eval(expression)
    assert int(value) == number and value.type.sizeof == size, (expression, str(value), str(value.type))
    observations[expression] = {'value': str(int(value)), 'bytes': value.type.sizeof, 'type': str(value.type)}
listing = gdb.execute('list annotation_probe', to_string=True)
assert 'annotation_probe' in listing and 'ANNOTATION_LOCAL' in listing
assert 'member' in gdb.execute('ptype ANNOTATION_TYPE', to_string=True)
gdb.execute('continue')
assert exits == [0], exits
(case / 'compiler-observations.json').write_text(json.dumps(observations, indent=4, sort_keys=True) + '\n')
print('analyst-annotations-compiler=PASS values=' + str(len(observations)))

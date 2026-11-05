"""Independent runtime observation of location loss after actual Ghidra curation."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_LEXICAL_CASE'])
phase = os.environ['FORGE_LEXICAL_MODE']
labels = json.loads((case / 'labels.json').read_text())
storage = json.loads((case / 'compiler-storage.json').read_text())
remote = os.environ.get('FORGE_LEXICAL_REMOTE', '')
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute('list scoped')
gdb.execute('ptype scoped')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*scoped', temporary=True)
gdb.execute('continue' if remote else 'run')
bias = int(gdb.parse_and_eval('$pc')) - labels['scoped']
stack = int(gdb.parse_and_eval('$sp'))
observations = []
for marker, expected in [('outer_live', 11), ('inner_live', 23), ('inner_end', 11)]:
    gdb.Breakpoint('*' + hex(labels[marker] + bias), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == labels[marker] + bias
    value = gdb.parse_and_eval('shadow')
    gdb.execute('print shadow')
    assert value.type.sizeof == 4
    inner = marker == 'inner_live'
    raw = int.from_bytes(gdb.selected_inferior().read_memory(stack + storage['inner' if inner else 'outer'], 4),
                         'little', signed=True)
    assert raw == expected
    omitted = inner and phase in ('curated', 'renamed')
    assert value.is_optimized_out == omitted, (phase, marker, str(value))
    if not omitted:
        assert int(value) == expected
    observations.append({'marker': marker, 'linkTimePc': hex(labels[marker]), 'value': str(value), 'rawValue': raw})
gdb.execute('continue')
assert exits == [0] and gdb.selected_inferior().pid == 0
(case / (phase + '-curation-observations.json')).write_text(json.dumps(observations, indent=4) + '\n')
print('coverage-curation-gdb=' + phase + ' PASS')

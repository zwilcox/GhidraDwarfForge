"""Runtime branch/slot and ARM/Thumb transitions with honest failed-function source."""
import json
import os
from pathlib import Path
import gdb

root = Path(os.environ['FORGE_BOUNDARY_CASE'])
target = os.environ['FORGE_BOUNDARY_TARGET']
mode = os.environ['FORGE_BOUNDARY_MODE']
data = json.loads((root / 'observations.json').read_text())
entry = data['entry']
source = root / (mode + '.dbg.c')
name = ('mixed_body' if mode == 'compiler' else 'recovered_mixed_body') if target == 'arm32' else 'delay_context'
assert int(gdb.parse_and_eval('&' + name)) == entry
(root / 'unrelated-cwd').mkdir(exist_ok=True)
gdb.execute('cd ' + str(root / 'unrelated-cwd'))
line = None
if mode != 'compiler':
    line = next(i for i, text in enumerate(source.read_text().splitlines(), 1) if 'DECOMPILATION_FAILURE_ENTRY_SAMPLE' in text)
    gdb.execute('set listsize 3')
    assert 'DECOMPILATION_FAILURE_ENTRY_SAMPLE' in gdb.execute('list ' + str(source) + ':' + str(line), to_string=True)
    assert gdb.find_pc_line(entry).line == 0
else:
    assert name in gdb.execute('list ' + name, to_string=True)
gdb.Breakpoint('*' + hex(entry))
gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == entry
if target == 'arm32':
    assert int(gdb.parse_and_eval('$cpsr')) & 0x20 == 0
    gdb.Breakpoint('*' + hex(entry + 24), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == entry + 24
    assert int(gdb.parse_and_eval('$cpsr')) & 0x20
    gdb.execute('stepi')
    assert int(gdb.parse_and_eval('$r0')) == 19
    gdb.Breakpoint('*' + hex(entry + 32), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == entry + 32
    assert int(gdb.parse_and_eval('$cpsr')) & 0x20 == 0
    gdb.execute('stepi')
    assert int(gdb.parse_and_eval('$r0')) == 26
else:
    assert int(gdb.parse_and_eval('$a0')) == 0
    gdb.execute('stepi')
    assert int(gdb.parse_and_eval('$v0')) == 9
    assert int(gdb.parse_and_eval('$pc')) == entry + 12
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == entry and int(gdb.parse_and_eval('$a0')) == 5
    gdb.execute('stepi')
    assert int(gdb.parse_and_eval('$v0')) == 14 and int(gdb.parse_and_eval('$pc')) == entry + 8
    gdb.execute('stepi')
    assert int(gdb.parse_and_eval('$v0')) == 17
if mode != 'compiler': assert gdb.find_pc_line(int(gdb.parse_and_eval('$pc'))).line == 0
gdb.execute('disable breakpoints')
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute('continue')
assert exits == [0], exits
(root / (mode + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'target': target, 'mode': mode,
    'entry': entry, 'diagnosticLine': line, 'exit': 0}, indent=4) + '\n')
print('context-boundaries-gdb=PASS')

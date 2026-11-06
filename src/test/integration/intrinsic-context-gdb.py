"""Live source lookup and stepping with intrinsic context in each output mode."""
import json
import os
from pathlib import Path
import gdb

root = Path(os.environ['FORGE_INTRINSIC_CASE'])
mode = os.environ['FORGE_INTRINSIC_MODE']
source = root / (mode + '.dbg.c')
lines = source.read_text().splitlines()
comments = json.loads((root / (mode + '-context-lines.json')).read_text())
(root / 'unrelated-cwd').mkdir(exist_ok=True)
gdb.execute('cd ' + str(root / 'unrelated-cwd'))
assert not any(Path(obj.filename) == root / 'reference' for obj in gdb.objfiles())
gdb.Breakpoint('*ordinary_context', temporary=True)
gdb.Breakpoint('*halt_baddata', temporary=True)
gdb.Breakpoint('*cpuid_basic_info', temporary=True)
gdb.Breakpoint('*intrinsic_context', temporary=True)
gdb.execute('run')
hits = []
for name in ('ordinary_context', 'halt_baddata', 'cpuid_basic_info', 'intrinsic_context'):
    assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&' + name))
    assert name in gdb.execute('list ' + name, to_string=True)
    hits.append(name)
    if name != 'intrinsic_context':
        gdb.execute('continue')
if comments:
    gdb.execute('set listsize 3')
    assert 'INTRINSIC_CALLOTHER' in gdb.execute('list ' + str(source) + ':' + str(comments[0]), to_string=True)
steps = []
for command in ('next', 'step'):
    gdb.execute(command)
    row = gdb.find_pc_line(int(gdb.parse_and_eval('$pc')))
    assert row.line and Path(row.symtab.fullname()) == source
    assert row.line not in comments
    steps.append({'command': command, 'line': row.line, 'text': lines[row.line - 1]})
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute('continue')
assert exits == [0]
(root / (mode + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'mode': mode,
    'breakpoints': hits, 'steps': steps, 'exit': 0}, indent=4) + '\n')
print('intrinsic-context-gdb=PASS')

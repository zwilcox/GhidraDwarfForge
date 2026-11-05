"""Observe actual default exporter comments, source, types and original variable identity."""
import json
import os
from pathlib import Path
import gdb

root = Path(os.environ['FORGE_ANNOTATION_CASE'])
reference = Path(os.environ['FORGE_ANNOTATION_REFERENCE'])
remote = os.environ.get('FORGE_ANNOTATION_REMOTE', '')
labels = json.loads((reference / 'labels.json').read_text())
inserted = set(json.loads((root / 'comment-lines.json').read_text()))
source = root / 'forge.dbg.c'
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
quote = lambda value: json.dumps(str(value))
(root / 'unrelated-cwd').mkdir(exist_ok=True)
gdb.execute('cd ' + str(root / 'unrelated-cwd'))
gdb.execute('file ' + quote(reference / 'reference'))
gdb.execute('exec-file ' + quote(reference / 'stripped'))
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*annotation_probe', temporary=True)
gdb.execute('continue' if remote else 'run')
runtime = int(gdb.parse_and_eval('&annotation_probe'))
bias = runtime - labels['annotation_probe']['address']
gdb.execute('symbol-file -o ' + hex(bias) + ' ' + quote(root / 'forge.dbg'))
assert not any(Path(obj.filename) == reference / 'reference' for obj in gdb.objfiles())
assert int(gdb.parse_and_eval('&annotation_probe')) == runtime
assert 'annotation_probe' in gdb.execute('info functions annotation_', to_string=True)
assert 'annotation_probe' in gdb.execute('list annotation_probe', to_string=True)
assert 'member' in gdb.execute('ptype struct ANNOTATION_TYPE', to_string=True)
for expression, number in [('ANNOTATION_COLLISION', 101), ('annotation_object.member', 5)]:
    value = gdb.parse_and_eval(expression)
    assert int(value) == number and value.type.sizeof == 4, (expression, str(value))
steps = []
for command in ('stepi', 'next', 'step'):
    gdb.execute(command)
    sal = gdb.find_pc_line(int(gdb.parse_and_eval('$pc')))
    if sal.line:
        assert Path(sal.symtab.fullname()) == source and sal.line not in inserted
    steps.append({'command': command, 'line': sal.line})
marker = 'FORGE_ANNOTATION:failed-function:EOL'
catalog_line = next(i for i, line in enumerate(source.read_text().splitlines(), 1) if marker in line)
gdb.execute('set listsize 5')
assert marker in gdb.execute('list ' + str(source) + ':' + str(catalog_line), to_string=True)
gdb.execute('continue')
assert exits == [0], exits
(root / 'gdb-observation.json').write_text(json.dumps({'status': 'PASS', 'bias': bias,
    'steps': steps, 'catalogLine': catalog_line, 'exit': 0}, indent=4) + '\n')
print('annotation-default-gdb=PASS')

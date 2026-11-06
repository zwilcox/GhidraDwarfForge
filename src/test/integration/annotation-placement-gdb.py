"""Exercise the generated annotation source after replacing compiler bootstrap symbols."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_PLACEMENT_CASE'])
reference = Path(os.environ['FORGE_PLACEMENT_REFERENCE'])
remote = os.environ.get('FORGE_PLACEMENT_REMOTE', '')
mode = os.environ.get('FORGE_PLACEMENT_MODE', 'annotated')
assert mode in ('annotated', 'baseline')
sidecar = case / ('forge.dbg' if mode == 'annotated' else 'baseline.dbg')
observed = json.loads((case / 'forge.dbg.placement.json').read_text())
labels = json.loads((reference / 'labels.json').read_text())
source = Path(str(sidecar) + '.c')
source_lines = source.read_text().splitlines()
quote = lambda value: json.dumps(str(value), ensure_ascii=False)
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
(case / 'unrelated-cwd').mkdir(exist_ok=True)
gdb.execute('cd ' + str(case / 'unrelated-cwd'))
gdb.execute('file ' + quote(reference / 'reference'))
gdb.execute('exec-file ' + quote(reference / 'stripped'))
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*annotation_probe', temporary=True)
gdb.execute('continue' if remote else 'run')
runtime = int(gdb.parse_and_eval('&annotation_probe'))
bias = runtime - labels['annotation_probe']['address']
gdb.execute('symbol-file -o ' + hex(bias) + ' ' + quote(sidecar))
assert int(gdb.parse_and_eval('&annotation_probe')) == runtime
assert len(gdb.objfiles()) >= 1
assert not any(Path(obj.filename) == reference / 'reference' for obj in gdb.objfiles())
gdb.execute('info functions annotation_')
assert 'annotation_probe' in gdb.execute('list annotation_probe', to_string=True)


def check_line():
    sal = gdb.find_pc_line(int(gdb.parse_and_eval('$pc')))
    if sal.line:
        assert sal.symtab is not None and Path(sal.symtab.fullname()) == source
        if mode == 'annotated':
            assert sal.line not in observed['annotationLines']
    return sal.line


assert check_line() > 0
gdb.Breakpoint('*annotation_failure', temporary=True)
steps = []
for command in ('stepi', 'next', 'step'):
    if int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&annotation_failure')):
        break
    gdb.execute(command)
    steps.append({'command': command, 'line': check_line()})
if int(gdb.parse_and_eval('$pc')) != int(gdb.parse_and_eval('&annotation_failure')):
    gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&annotation_failure'))
assert check_line() == 0, 'failed native source acquired an executable source row'
gdb.execute('set listsize 5')
marker = 'FORGE_ANNOTATION:failed-function:EOL' if mode == 'annotated' else 'Decompilation unavailable for annotation_failure'
catalog_line = next(number for number, line in enumerate(source_lines, 1) if marker in line)
catalog = gdb.execute('list ' + str(source) + ':' + str(catalog_line), to_string=True)
assert marker in catalog
print(catalog)
gdb.execute('continue')
assert exits == [0], exits
(case / ('gdb-observation.json' if mode == 'annotated' else 'baseline-gdb-observation.json')).write_text(json.dumps({'status': 'PASS', 'runtimeBias': bias,
    'steps': steps, 'failedSourceLine': 0, 'catalogLine': catalog_line, 'exit': 0}, indent=4) + '\n')
print('annotation-placement-gdb=PASS')

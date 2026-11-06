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
equates_file = root / 'equate-expected.json'
equates = json.loads(equates_file.read_text()) if equates_file.exists() else []
equate_checks = []


def check_equates(frame):
    for constant in equates:
        value = constant['value']
        expected = value['value'] if value['signed'] else value['value'] & ((1 << value['bits']) - 1)
        for expression in (constant['name'], "'forge.dbg.c'::" + constant['name']):
            observed = gdb.parse_and_eval(expression)
            assert int(observed) == expected, (frame, expression, str(observed), expected)
            assert observed.type.sizeof == (value['bits'] + 7) // 8
            assert observed.address is None and 'const forge_equate_type_' in str(observed.type)
            equate_checks.append({'frame': frame, 'expression': expression, 'value': int(observed),
                'bytes': observed.type.sizeof})
    if equates:
        try:
            gdb.execute('set variable ' + equates[0]['name'] + ' = 0', to_string=True)
        except gdb.error:
            pass
        else:
            raise AssertionError('synthetic constant was writable')


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
check_equates('annotation_probe')
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
if equates:
    gdb.Breakpoint('*' + hex(bias + labels['annotation_conflict_live']['address']), temporary=True)
    gdb.execute('continue')
    assert gdb.newest_frame().name() == 'annotation_conflicts'
    local, implicit = gdb.lookup_symbol('ANNOTATION_LOCAL')
    assert local is not None and local.is_variable and not implicit
    assert gdb.lookup_global_symbol('ANNOTATION_LOCAL') is None
    assert local.type.sizeof == 4 and 'forge_equate_type_' not in str(local.type)
    # This saved first-use offset has no validated lifetime in the production exporter.
    assert gdb.parse_and_eval('ANNOTATION_LOCAL').is_optimized_out
    assert int(gdb.parse_and_eval('ANNOTATION_COLLISION')) == 101
    assert int(gdb.parse_and_eval('annotation_object.member')) == 5
    check_equates('annotation_conflicts')
gdb.execute('continue')
assert exits == [0], exits
(root / 'gdb-observation.json').write_text(json.dumps({'status': 'PASS', 'bias': bias,
    'steps': steps, 'catalogLine': catalog_line, 'exit': 0, 'equateChecks': equate_checks}, indent=4) + '\n')
print('annotation-default-gdb=PASS')

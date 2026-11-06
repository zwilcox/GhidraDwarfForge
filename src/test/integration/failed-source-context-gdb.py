"""Check file-only lookup without inventing source rows for failed functions."""
import json
import os
from pathlib import Path
import gdb

root = Path(os.environ['FORGE_FAILURE_CASE'])
reference = Path(os.environ['FORGE_FAILURE_REFERENCE'])
mode = os.environ['FORGE_FAILURE_MODE']
remote = os.environ.get('FORGE_FAILURE_REMOTE', '')
source = root / (mode + '.dbg.c')
metadata = json.loads((root / (mode + '.json')).read_text())
labels = json.loads((reference / 'labels.json').read_text())
quote = lambda value: json.dumps(str(value))
(root / 'unrelated-cwd').mkdir(exist_ok=True)
gdb.execute('cd ' + str(root / 'unrelated-cwd'))
gdb.execute('file ' + quote(reference / 'reference'))
gdb.execute('exec-file ' + quote(reference / 'stripped'))
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*annotation_probe', temporary=True)
gdb.execute('continue' if remote else 'run')
bias = int(gdb.parse_and_eval('&annotation_probe')) - labels['annotation_probe']['address']
gdb.execute('symbol-file -o ' + hex(bias) + ' ' + quote(root / (mode + '.dbg')))
assert not any(Path(obj.filename) == reference / 'reference' for obj in gdb.objfiles())
for name in metadata['nativeFailures']:
    address = int(gdb.parse_and_eval('&' + name))
    assert address == bias + labels[name]['address']
    assert gdb.find_pc_line(address).line == 0, 'failed function acquired a source row'
    assert name in gdb.execute('info functions ' + name, to_string=True)
source_rows = source.read_text().splitlines()
context_line = next(i for i, text in enumerate(source_rows, 1) if 'DECOMPILATION_FAILURE_ENTRY_SAMPLE' in text)
gdb.execute('set listsize 4')
assert 'DECOMPILATION_FAILURE_ENTRY_SAMPLE' in gdb.execute('list ' + str(source) + ':' + str(context_line), to_string=True)
assert 'Decompilation unavailable' in gdb.execute('list ' + str(source) + ':8', to_string=True)
assert int(gdb.parse_and_eval('ANNOTATION_COLLISION')) == 101
assert 'member' in gdb.execute('ptype struct ANNOTATION_TYPE', to_string=True)
steps = []
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.Breakpoint('*annotation_failure', temporary=True)
if mode == 'all':
    # A deliberately signature-free function can be exposed through GDB's
    # minimal symbols. The retained global gives us the CU's actual symtab.
    symbol = gdb.lookup_global_symbol('ANNOTATION_COLLISION') or gdb.lookup_static_symbol('ANNOTATION_COLLISION')
    assert symbol is not None and list(symbol.symtab.linetable()) == [], \
        ('file-only table observation', str(symbol), None if symbol is None else list(symbol.symtab.linetable()))
    gdb.execute('stepi')
    assert gdb.find_pc_line(int(gdb.parse_and_eval('$pc'))).line == 0
else:
    gdb.Breakpoint('*annotation_conflicts', temporary=True)
    gdb.execute('continue')
    assert 'annotation_conflicts' in gdb.execute('list annotation_conflicts', to_string=True)
    for command in ('next', 'step'):
        gdb.execute(command)
        row = gdb.find_pc_line(int(gdb.parse_and_eval('$pc')))
        if row.line:
            assert Path(row.symtab.fullname()) == source
            assert not source_rows[row.line - 1].startswith('/* Ghidra instruction context')
        steps.append({'command': command, 'line': row.line})
if int(gdb.parse_and_eval('$pc')) != bias + labels['annotation_failure']['address']:
    gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == bias + labels['annotation_failure']['address']
gdb.execute('continue')
assert exits == [0], exits
(root / (mode + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'mode': mode, 'bias': bias,
    'contextLine': context_line, 'failedFunctions': metadata['nativeFailures'], 'steps': steps, 'exit': 0}, indent=4) + '\n')
print('failed-source-context-gdb=PASS')

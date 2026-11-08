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
for name in (metadata['nativeFailures'] if mode != 'empty' else [function['name'] for function in metadata['functions']]):
    address = int(gdb.parse_and_eval('&' + name))
    assert address == bias + labels[name]['address']
    assert gdb.find_pc_line(address).line == 0, 'failed function acquired a source row'
    assert name in gdb.execute('info functions ' + name, to_string=True)
sources = [root / name for name in metadata['sourceFiles']]
source_rows_by_file = {path: path.read_text().splitlines() for path in sources}
gdb.execute('set listsize 4')
context_line = None
context_file = None
if mode != 'empty':
    context_file, context_line = next((path, i) for path, rows in source_rows_by_file.items()
        for i, text in enumerate(rows, 1) if 'DECOMPILATION_FAILURE_ENTRY_SAMPLE' in text)
    assert 'DECOMPILATION_FAILURE_ENTRY_SAMPLE' in gdb.execute('list ' + str(context_file) + ':' + str(context_line), to_string=True)
    failure_file, failure_line = next((path, i) for path, rows in source_rows_by_file.items()
        for i, text in enumerate(rows, 1) if 'Decompilation unavailable' in text)
    assert 'Decompilation unavailable' in gdb.execute('list ' + str(failure_file) + ':' + str(failure_line), to_string=True)
else:
    assert len(metadata['functions']) == 3 and metadata['sourceFunctions'] == []
    first_source = sources[1] if len(sources) > 1 else sources[0]
    assert source_rows_by_file[first_source][0] in gdb.execute('list ' + str(first_source) + ':1', to_string=True)
assert int(gdb.parse_and_eval('ANNOTATION_COLLISION')) == 101
assert 'member' in gdb.execute('ptype struct ANNOTATION_TYPE', to_string=True)
steps = []
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.Breakpoint('*' + hex(bias + labels['annotation_failure']['address']), temporary=True)
if mode != 'mixed':
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
            assert Path(row.symtab.fullname()) in source_rows_by_file
            assert not source_rows_by_file[Path(row.symtab.fullname())][row.line - 1].startswith('/* Ghidra instruction context')
        steps.append({'command': command, 'line': row.line})
if int(gdb.parse_and_eval('$pc')) != bias + labels['annotation_failure']['address']:
    gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == bias + labels['annotation_failure']['address']
gdb.execute('continue')
assert exits == [0], exits
(root / (mode + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'mode': mode, 'bias': bias,
    'contextLine': context_line, 'contextFile': str(context_file) if context_file else None,
    'sourceFiles': [str(path) for path in sources], 'failedFunctions': metadata['nativeFailures'], 'steps': steps, 'exit': 0}, indent=4) + '\n')
print('failed-source-context-gdb=PASS')

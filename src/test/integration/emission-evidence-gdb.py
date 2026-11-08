"""Instruction-correlated values and honest omissions in the producer fixture."""
import gdb
import json
import os
from pathlib import Path

annotations = os.environ.get('FORGE_EMISSION_ANNOTATIONS') == '1'
if annotations:
    case = Path(os.environ['FORGE_EMISSION_CASE'])
    manifest = json.loads((case / 'forge.dbg.annotations.json').read_text())
    source = case / 'forge.dbg.c'
    source_lines = source.read_text().splitlines()
    assert Path.cwd() == case / 'unrelated-debugger-cwd'
    gdb.execute('set listsize 100')


def check_source(expected=None):
    if not annotations:
        return
    sal = gdb.find_pc_line(int(gdb.parse_and_eval('$pc')))
    assert sal.symtab is not None and Path(sal.symtab.fullname()) == source
    assert sal.line > 0 and sal.line not in manifest['annotationLines']
    if expected:
        assert source_lines[sal.line - 1] == expected, (sal.line, source_lines[sal.line - 1])

exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('info functions')
gdb.execute('list observed')
if annotations:
    listing = gdb.execute('list observed', to_string=True)
    assert 'FORGE_STATEMENT' in listing and '\\u002f' in listing and 'second line\\tend' in listing
    catalog_line = next(i for i, text in enumerate(source_lines, 1) if 'FORGE_FAILED_CATALOG' in text)
    assert 'FORGE_FAILED_CATALOG' in gdb.execute('list ' + str(source) + ':' + str(catalog_line), to_string=True)
gdb.execute('ptype struct Node')
gdb.Breakpoint('*observed', temporary=True)
gdb.execute('run')
check_source()
for name, expected in [('x', 41), ('moving', 41), ('counter', 23)]:
    gdb.execute('print ' + name)
    assert int(gdb.parse_and_eval(name)) == expected
for name in ['late', 'partial', 'mixed', 'no_storage', 'opaque_pointer', 'recursive']:
    assert gdb.parse_and_eval(name).is_optimized_out, name
gdb.execute('ptype opaque_pointer')
gdb.execute('stepi')
check_source('    x = x;')
assert int(gdb.parse_and_eval('moving')) == 41
assert int(gdb.parse_and_eval('late')) == 41
assert int(gdb.parse_and_eval('$rax')) == 41
gdb.Breakpoint('*failed', temporary=True)
gdb.execute('next')
check_source('    return x;')
gdb.execute('step')
if int(gdb.parse_and_eval('$pc')) != int(gdb.parse_and_eval('&failed')):
    gdb.execute('continue')
assert int(gdb.parse_and_eval('$pc')) == int(gdb.parse_and_eval('&failed'))
try:
    gdb.parse_and_eval('hidden')
except gdb.error as error:
    assert 'No symbol "hidden"' in str(error)
else:
    raise AssertionError('symbol-only failed function retained a parameter')
gdb.execute('continue')
assert exits == [0], exits
print('emission-evidence-gdb=PASS')

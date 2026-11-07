"""GDB runtime oracle for the source-built multi-file presentation fixture."""
import gdb
import json
import os
from pathlib import Path
sidecar=Path(os.environ['FORGE_TEST_SIDECAR'])
index=Path(str(sidecar)+'.c').read_text()
manifest_name=next(line.removeprefix(' * Manifest: ') for line in index.splitlines() if line.startswith(' * Manifest: '))
manifest=json.loads((sidecar.parent/manifest_name).read_text())
functions={item['name']:item for item in manifest['functions']}
def expected_file(name):
    return manifest['parts'][functions[name]['file']-1]['name']
gdb.execute('file '+json.dumps(os.environ['FORGE_TEST_ORIGINAL']))
gdb.execute('set auto-solib-add off')
gdb.execute('symbol-file '+json.dumps(str(sidecar)))
gdb.execute('info functions recovered_')
gdb.execute('list recovered_first')
gdb.execute('list recovered_second')
gdb.execute('ptype recovered_first')
resolved=gdb.Breakpoint(expected_file('recovered_second')+':recovered_second')
assert resolved.locations and not resolved.pending
resolved.enabled=False
gdb.execute('break recovered_first')
gdb.execute('run')
first=gdb.selected_frame().find_sal().symtab.fullname()
assert 'forge-src-' in first, first
assert Path(first).name==expected_file('recovered_first')
assert gdb.selected_frame().name()=='recovered_first'
for count in range(12):
    gdb.execute('step')
    if gdb.selected_frame().name()=='recovered_second': break
else: raise AssertionError('step did not enter second function')
second=gdb.selected_frame().find_sal().symtab.fullname()
assert second != first and 'forge-src-' in second, (first,second)
assert Path(second).name==expected_file('recovered_second')
gdb.execute('list')
gdb.execute('finish')
assert int(gdb.parse_and_eval('observed'))==10
gdb.execute('next')
gdb.execute('continue')
assert gdb.selected_inferior().pid==0
print('MULTIFILE_GDB_PASS '+json.dumps({'first':first,'second':second}))

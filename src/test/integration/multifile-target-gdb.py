"""Observe compiler, single-file and partitioned source across a real call."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_MULTI_CASE'])
mode = os.environ['FORGE_MULTI_MODE']
source = Path(os.environ['FORGE_MULTI_SYMBOLS'] + '.c')
expected = {}
if mode == 'multi':
    name, = [line.removeprefix(' * Manifest: ') for line in source.read_text().splitlines()
        if line.startswith(' * Manifest: ')]
    manifest = json.loads((source.parent / name).read_text())
    for function in ('recovered_first', 'recovered_second'):
        row, = [row for row in manifest['functions'] if row['name'] == function]
        expected[function] = source.parent / manifest['parts'][row['file'] - 1]['name']
        qualified = expected[function].name + ':' + function
        assert function in gdb.execute('list ' + qualified, to_string=True)
        point = gdb.Breakpoint(qualified)
        assert not point.pending and point.locations
        point.delete()
    assert len(set(expected.values())) == 2
elif mode == 'single':
    expected = {name: source for name in ('recovered_first', 'recovered_second')}

gdb.execute('info functions recovered_')
gdb.execute('ptype recovered_first')
gdb.execute('list recovered_first')
gdb.execute('list recovered_second')
remote = os.environ.get('FORGE_MULTI_REMOTE', '')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('recovered_first', temporary=True)
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue' if remote else 'run')
assert gdb.selected_frame().name() == 'recovered_first'


def source_at_stop(function):
    sal = gdb.selected_frame().find_sal()
    assert sal.symtab is not None and sal.line > 0
    path = Path(sal.symtab.fullname())
    assert path.is_file() and sal.line <= len(path.read_text().splitlines())
    if expected:
        assert path == expected[function], (path, expected[function])
    return {'function': function, 'file': str(path), 'line': sal.line}


stops = [source_at_stop('recovered_first')]
for step in range(20):
    gdb.execute('step')
    if gdb.selected_frame().name() == 'recovered_second':
        break
else:
    raise AssertionError('source stepping did not enter recovered_second')
stops.append(source_at_stop('recovered_second'))
gdb.execute('list')
gdb.execute('next')
if gdb.selected_frame().name() == 'recovered_second':
    gdb.execute('finish')
assert gdb.selected_frame().name() == 'recovered_first'
assert int(gdb.parse_and_eval('observed')) == 10
gdb.execute('print observed')
gdb.execute('continue')
assert gdb.selected_inferior().pid == 0 and exits == [0], exits
(case / (mode + '-observations.json')).write_text(json.dumps({
    'status': 'PASS', 'stops': stops, 'observed': 10, 'exitCodes': exits}, indent=4) + '\n')
print('multifile-target-gdb=' + mode + ' PASS')

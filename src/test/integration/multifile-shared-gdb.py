"""Verify source files and stepping after independently measured DSO relocation."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_SHARED_CASE'])
mode = os.environ['FORGE_SHARED_MODE']
artifact = Path(os.environ['FORGE_SHARED_SYMBOLS'])
addresses = json.loads((case / 'addresses.json').read_text())
remote = os.environ.get('FORGE_SHARED_REMOTE', '')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('forge_library_ready', temporary=True)
gdb.execute('continue' if remote else 'run')
bias = int(gdb.parse_and_eval('forge_library_bias'))
assert bias != 0
gdb.execute('add-symbol-file ' + json.dumps(str(artifact)) + ' -o ' + hex(bias))
expected = {}
if mode == 'multi':
    source = Path(str(artifact) + '.c')
    name, = [line.removeprefix(' * Manifest: ') for line in source.read_text().splitlines()
        if line.startswith(' * Manifest: ')]
    manifest = json.loads((source.parent / name).read_text())
    for name in ('recovered_first', 'recovered_second'):
        function, = [row for row in manifest['functions'] if row['name'] == name]
        expected[name] = source.parent / manifest['parts'][function['file'] - 1]['name']
    assert len(set(expected.values())) == 2
elif mode == 'single':
    expected = {name: Path(str(artifact) + '.c') for name in ('recovered_first', 'recovered_second')}
for name in ('recovered_first', 'recovered_second'):
    assert int(gdb.parse_and_eval('&' + name)) == bias + addresses[name][0]
    listing = gdb.execute('list ' + name, to_string=True)
    assert name in listing and 'No such file' not in listing
    if expected:
        point = gdb.Breakpoint(str(expected[name]) + ':' + name)
        assert not point.pending and point.locations
        assert all(bias + addresses[name][0] <= location.address < bias + addresses[name][1]
            for location in point.locations)
        point.delete()
gdb.execute('ptype recovered_first')
gdb.Breakpoint('recovered_first', temporary=True)
gdb.execute('continue')


def observe(name):
    frame = gdb.selected_frame()
    assert frame.name() == name
    assert bias + addresses[name][0] <= frame.pc() < bias + addresses[name][1]
    sal = frame.find_sal()
    assert sal.symtab is not None and sal.line > 0
    path = Path(sal.symtab.fullname())
    assert path.is_file() and sal.line <= len(path.read_text().splitlines())
    if expected:
        assert path == expected[name]
    return {'function': name, 'linkPc': int(frame.pc()) - bias, 'source': str(path), 'line': sal.line}


stops = [observe('recovered_first')]
for unused in range(20):
    gdb.execute('step')
    if gdb.selected_frame().name() == 'recovered_second':
        break
else:
    raise AssertionError('source stepping did not enter the second function')
stops.append(observe('recovered_second'))
gdb.execute('next')
if gdb.selected_frame().name() == 'recovered_second':
    gdb.execute('finish')
assert gdb.selected_frame().name() == 'recovered_first'
assert int(gdb.parse_and_eval('observed')) == 10
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue')
assert exits == [0]
(case / (mode + '-observations.json')).write_text(json.dumps({'status': 'PASS',
    'mode': mode, 'bias': bias, 'stops': stops, 'observed': 10, 'exitCodes': exits}, indent=4) + '\n')
print('multifile-shared-gdb=PASS', mode)

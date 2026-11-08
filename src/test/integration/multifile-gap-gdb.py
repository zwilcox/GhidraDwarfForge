"""Source step/next across an explicitly excluded gap in one function body."""
import json
import os
from pathlib import Path
import gdb

source = Path(os.environ['FORGE_FRAME_SYMBOLS'] + '.c')
manifests = [line.removeprefix(' * Manifest: ') for line in source.read_text().splitlines()
    if line.startswith(' * Manifest: ')]
expected_source = source
if manifests:
    name, = manifests
    manifest = json.loads((source.parent / name).read_text())
    function, = [row for row in manifest['functions'] if row['name'] == 'cf_recurse']
    expected_source = source.parent / manifest['parts'][function['file'] - 1]['name']
remote = os.environ.get('FORGE_FRAME_REMOTE', '')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*cf_gap_jump', temporary=True)
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('continue' if remote else 'run')
addresses = {name: int(gdb.parse_and_eval('&' + name))
    for name in ('cf_gap_jump', 'cf_gap_first', 'cf_gap_after', 'cf_body_end')}


def observe():
    frame = gdb.newest_frame()
    assert frame.name() == 'cf_recurse'
    sal = frame.find_sal()
    assert sal.symtab is not None and sal.line > 0
    assert Path(sal.symtab.fullname()) == expected_source
    listing = gdb.execute('list *$pc', to_string=True)
    assert 'No such file' not in listing and 'No source' not in listing
    return {'pc': int(frame.pc()), 'function': frame.name(), 'source': str(expected_source), 'line': sal.line}


rows = []
for operation in ('step', 'next'):
    assert int(gdb.parse_and_eval('$pc')) == addresses['cf_gap_jump']
    before = observe()
    for address in range(addresses['cf_gap_first'], addresses['cf_gap_after']):
        sal = gdb.find_pc_line(address)
        assert sal.symtab is None and sal.line == 0, 'source mapping leaked into excluded bytes'
    # GDB stops at the next range boundary. In the prologue fixture, its
    # first instructions have no decompiler-token mapping; retain that fact.
    gdb.execute(operation)
    assert int(gdb.parse_and_eval('$pc')) == addresses['cf_gap_after']
    source_stop = gdb.newest_frame().find_sal()
    instruction_stops = []
    if os.environ['FORGE_GAP_POSITION'] == 'prologue':
        assert source_stop.symtab is None and source_stop.line == 0
        for unused in range(8):
            gdb.execute('stepi')
            frame = gdb.newest_frame()
            assert frame.name() == 'cf_recurse'
            assert addresses['cf_gap_after'] < int(frame.pc()) < addresses['cf_body_end']
            instruction_stops.append(int(frame.pc()))
            if frame.find_sal().symtab is not None and frame.find_sal().line > 0:
                break
        else:
            raise AssertionError('no recovered line after bounded unmapped prologue')
    else:
        assert source_stop.symtab is not None and source_stop.line > 0
    after = observe()
    rows.append({'operation': operation, 'before': before, 'after': after,
        'sourceCommandStop': addresses['cf_gap_after'], 'instructionFallbackStops': instruction_stops})
    if operation == 'step':
        gdb.Breakpoint('*cf_gap_jump', temporary=True)
        gdb.execute('continue')
gdb.execute('continue')
assert exits == [0], exits
Path(os.environ['FORGE_FRAME_RESULT']).write_text(json.dumps({'status': 'PASS_MULTIFILE_GAP_SOURCE',
    'rows': rows, 'addresses': addresses, 'exitCodes': exits}, indent=4) + '\n')
print('multifile-gap-source=PASS')

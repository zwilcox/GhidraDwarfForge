"""Observe automatic installed symbols for a shared object or sectionless ELF."""
import json
import os
from pathlib import Path

import gdb

config = json.loads(Path(os.environ['FORGE_BUILD_ID_LAYOUT']).read_text())
remote = os.environ.get('FORGE_BUILD_ID_REMOTE')
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
shared = config['role'] == 'shared'
for command in ['set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set python print-stack full',
        'set filename-display absolute', 'set disable-randomization off',
        'set auto-solib-add ' + ('on' if shared else 'off'),
        'set debug-file-directory ' + config['debugRoot'],
        'set solib-search-path ' + str(Path(config['original']).parent),
        'set sysroot ' + config['sysroot'], 'file ' + json.dumps(config['driver'])]:
    gdb.execute(command)
if config.get('explicitFallback'):
    gdb.execute('symbol-file ' + json.dumps(config['registration']))
if remote:
    gdb.execute('target remote ' + remote)
if shared:
    main = gdb.Breakpoint('*' + hex(config['mainAddress']))
    gdb.execute('continue' if remote else 'run')
    assert int(gdb.parse_and_eval('$pc')) == config['mainAddress']
    main.delete()
symbols = [gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
    for name in config['functionCandidates']]
symbols = [symbol for symbol in symbols if symbol is not None and symbol.symtab is not None]
if not config['present']:
    assert not symbols, 'unexpected full DWARF without installed registration'
    gdb.execute('continue' if shared or remote else 'run')
else:
    assert len(symbols) == 1 and symbols[0].is_function
    symbol = symbols[0]
    function = symbol.name
    assert Path(symbol.symtab.objfile.filename).resolve() == Path(config['registration']).resolve()
    assert Path(symbol.symtab.fullname()).resolve() == Path(config['source']).resolve()
    address = int(symbol.value().address)
    if shared:
        assert address != config['linkAddress'], 'shared object was not relocated'
        assert 'int (int, int)' in gdb.execute('ptype ' + function, to_string=True)
        assert 'struct fixture_state' in gdb.execute('ptype struct fixture_state', to_string=True)
    else:
        assert address == config['linkAddress']
    listing = gdb.execute('list ' + function, to_string=True)
    assert function in listing and 'No such file' not in listing
    point = gdb.Breakpoint(function)
    gdb.execute('continue' if shared or remote else 'run')
    assert gdb.newest_frame().name() == function
    if shared:
        assert int(gdb.parse_and_eval('left')) == 19 and int(gdb.parse_and_eval('right')) == 23
        assert int(gdb.parse_and_eval('fixture_sink')) == 0
    point.delete()
    gdb.execute('next')
    if shared:
        if config['target'] == 'arm32':
            gdb.execute('next')
        assert int(gdb.parse_and_eval('fixture_sink')) == 42
    gdb.execute('continue')
assert exits == [0], exits
print('build-id-layout-gdb=PASS role=' + config['role'] + ' present=' + str(config['present']))

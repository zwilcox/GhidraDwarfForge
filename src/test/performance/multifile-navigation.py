"""Run inside fresh GDB; measure source-layout navigation and verify all symbols."""
import json
from pathlib import Path
import time
import gdb

request = json.loads(Path(gdb.convenience_variable('forge_request').string()).read_text())
binary, sidecar = Path(request['binary']), Path(request['sidecar'])
addresses = request['addresses']
source = Path(str(sidecar) + '.c')
expected = {}
if request['layout'] == 'multi':
    name, = [line.removeprefix(' * Manifest: ') for line in source.read_text().splitlines()
        if line.startswith(' * Manifest: ')]
    manifest = json.loads((source.parent / name).read_text())
    for function in manifest['functions']:
        if function['name'] in addresses:
            assert function['name'] not in expected
            expected[function['name']] = source.parent / manifest['parts'][function['file'] - 1]['name']
    assert expected.keys() == addresses.keys()
else:
    expected = {name: source for name in addresses}
for setting in ('pagination off', 'confirm off', 'debuginfod enabled off', 'auto-solib-add off',
        'disable-randomization off', 'startup-with-shell off'):
    gdb.execute('set ' + setting)
gdb.execute('file ' + json.dumps(str(binary)))
metrics = {}
started = time.perf_counter_ns()
gdb.execute('symbol-file ' + json.dumps(str(sidecar)))
metrics['symbolLoadSeconds'] = (time.perf_counter_ns() - started) / 1e9
started = time.perf_counter_ns()
for name, interval in addresses.items():
    symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
    assert symbol is not None and symbol.is_function and symbol.type.code == gdb.TYPE_CODE_FUNC, name
    assert symbol.symtab is not None and Path(symbol.symtab.fullname()) == expected[name], name
    assert int(symbol.value().address) == interval[0], name
metrics['allFunctionLookupSeconds'] = (time.perf_counter_ns() - started) / 1e9
started = time.perf_counter_ns()
listing_bytes = 0
for name in request['queries']:
    listing = gdb.execute('list ' + name, to_string=True)
    assert name in listing and 'No such file' not in listing and 'No source' not in listing, name
    listing_bytes += len(listing.encode('utf-8'))
metrics['scatteredListingSeconds'] = (time.perf_counter_ns() - started) / 1e9
started = time.perf_counter_ns()
for name in request['queries']:
    point = gdb.Breakpoint(str(expected[name]) + ':' + name, internal=True)
    assert not point.pending and point.locations, name
    assert all(addresses[name][0] <= loc.address < addresses[name][1] for loc in point.locations), name
    point.delete()
metrics['fileQualifiedBreakpointsSeconds'] = (time.perf_counter_ns() - started) / 1e9

# Runtime behavior is outside the navigation intervals. The fixture calls every
# function through its table, and bench_i adds 2*i+1 to the shared sink.
count = len(addresses)
gdb.Breakpoint('*bench_0', temporary=True)
gdb.Breakpoint('*bench_' + str(count - 1), temporary=True)
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
gdb.execute('run')
assert gdb.selected_frame().name() == 'bench_0'
assert int(gdb.parse_and_eval('*(unsigned int*)&benchmark_sink')) == 0
assert Path(gdb.selected_frame().find_sal().symtab.fullname()) == expected['bench_0']
gdb.execute('next')
gdb.execute('continue')
assert gdb.selected_frame().name() == 'bench_' + str(count - 1)
assert int(gdb.parse_and_eval('*(unsigned int*)&benchmark_sink')) == (count - 1) ** 2
gdb.execute('next')
gdb.execute('continue')
assert exits == [0], exits
Path(request['result']).write_text(json.dumps({'status': 'PASS', 'layout': request['layout'],
    'functions': count, 'queryCount': len(request['queries']), 'listingUtf8Bytes': listing_bytes,
    'sourceFilesVisited': len({str(expected[name]) for name in request['queries']}),
    'metrics': metrics, 'exitCodes': exits}, indent=4) + '\n')
print('multifile-navigation=PASS')

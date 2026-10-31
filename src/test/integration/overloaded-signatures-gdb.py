"""Observe distinct prototypes and source rows for one qualified display name."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['OVERLOAD_CASE'])
compiler = os.environ['OVERLOAD_VARIANT'] == 'compiler'
metadata = json.loads((case / 'metadata.json').read_text())
entries = metadata['entries']
curated = json.loads((case / 'curated.json').read_text())
gdb.execute('file ' + str(case / 'overloads.input'))
gdb.execute('symbol-file ' + str(case / ('overloads.reference' if compiler else 'overloads.dbg')))
original = ['_ZN8observed7combineEi', '_ZN8observed7combineEd']
aliases = [row['alias'] for row in curated]


def missing(name):
    try:
        gdb.parse_and_eval("&'" + name + "'")
    except gdb.error as error:
        assert 'No symbol' in str(error), str(error)
    else:
        raise AssertionError('unexpected alias ' + name)


lookups = {}
for index in range(2):
    names = ([original[index]] if compiler or original[index] in metadata['originalNames'] else [])
    if not compiler:
        names.append(aliases[index])
        if original[index] not in metadata['originalNames']:
            missing(original[index])
    for name in names:
        assert int(gdb.parse_and_eval("&'" + name + "'")) == entries[index], name
        prototype = gdb.execute("ptype '" + name + "'", to_string=True)
        expected = 'int (int)' if index == 0 else 'double (double)'
        assert expected in prototype, (name, prototype)
        lookups[name] = {'entry': entries[index], 'prototype': prototype}
if not compiler:
    missing('Recovered::nested::ambiguous_alias')
    same = gdb.Breakpoint("'Recovered::nested::combine'", internal=True)
    assert len(same.locations) == 2, list(same.locations)
    selected = {next(index for index in range(2)
        if entries[index] <= location.address < entries[index] + curated[index]['size'])
        for location in same.locations}
    assert selected == {0, 1}
    same.delete()
remote = os.environ.get('OVERLOAD_REMOTE', '')
if remote:
    gdb.execute('set sysroot ' + os.environ['OVERLOAD_SYSROOT'])
    gdb.execute('target remote ' + remote)
exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
rows = []
for iteration in range(4):
    index = iteration % 2
    argument = 19 if iteration < 2 else -19
    name = original[index] if compiler else aliases[index]
    breakpoint = gdb.Breakpoint("*'" + name + "'", internal=True)
    gdb.execute('run' if iteration == 0 and not remote else 'continue')
    breakpoint.delete()
    address = int(gdb.parse_and_eval('$pc'))
    bias = address - entries[index]
    assert address == int(gdb.parse_and_eval("&'" + name + "'"))
    if metadata['role'] != 'exec':
        assert bias != 0
    value = gdb.parse_and_eval('value')
    assert not value.is_optimized_out and float(value) == argument
    assert value.type.sizeof == (4 if index == 0 else 8)
    frame = gdb.newest_frame()
    sal = frame.find_sal()
    assert sal.symtab is not None
    if not compiler:
        assert frame.name() == 'Recovered::nested::combine'
        assert sal.symtab.filename.endswith('overloads.dbg.c')
    listing = gdb.execute('list *' + hex(address), to_string=True)
    assert 'combine' in listing and 'No such file' not in listing
    guard = gdb.FinishBreakpoint(frame, internal=True)
    command = 'next' if iteration < 2 else 'step'
    for unused in range(12):
        if not guard.is_valid():
            break
        # Duplicate names may not redirect navigation into the other definition.
        assert entries[index] + bias <= int(gdb.parse_and_eval('$pc')) < entries[index] + bias + curated[index]['size']
        gdb.execute(command)
    assert not guard.is_valid(), 'navigation did not return'
    returned = guard.return_value
    assert returned is not None
    expected = argument + (7 if index == 0 else -0.5)
    assert float(returned) == expected and returned.type.sizeof == (4 if index == 0 else 8), (iteration, str(returned))
    rows.append({'name': name, 'entry': entries[index], 'bias': bias, 'argument': argument,
        'return': float(returned), 'type': str(returned.type), 'line': sal.line,
        'source': sal.symtab.filename, 'navigation': command})
gdb.execute('continue')
assert exits == [0], exits
assert rows[0]['line'] != rows[1]['line']
variant = 'compiler' if compiler else 'forge'
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'lookup': lookups,
    'calls': rows, 'exitCodes': exits}, indent=4) + '\n')
print('OVERLOADED_SIGNATURES_RUNTIME_PASS ' + variant)

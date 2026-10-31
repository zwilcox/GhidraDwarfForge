"""Keep original ELF alias lookup distinct from typed curated DWARF identity."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['ALIAS_CASE'])
target = os.environ['ALIAS_TARGET']
variant = os.environ['ALIAS_VARIANT']
compiler = variant == 'compiler'
metadata = json.loads((case / 'metadata.json').read_text())
functions = metadata['functions']
binary = case / ('aliases.reference' if compiler else 'aliases.input')
gdb.execute('file ' + str(binary))
gdb.execute('symbol-file ' + str(case / ('aliases.reference' if compiler else 'aliases.dbg')))
remote = os.environ.get('ALIAS_REMOTE', '')


def expression(name):
    return "&'" + name + "'"


def missing(name):
    try:
        gdb.parse_and_eval(expression(name))
    except gdb.error as error:
        assert 'No symbol' in str(error), str(error)
        return
    raise AssertionError('unexpected symbol ' + name)


lookup = {}
for row in functions:
    names = [row['original']] + (['second_identity'] if row['name'].endswith('analyst_alias') else [])
    for name in names:
        present = compiler or name in metadata['originalSymbols']
        if present:
            assert int(gdb.parse_and_eval(expression(name))) == row['entry']
            # Record this consumer observation separately from typed curated lookup.
            prototype = gdb.execute("ptype '" + name + "'", to_string=True)
            assert 'int (int)' in prototype, (name, prototype)
            stop = gdb.Breakpoint(name, internal=True)
            locations = list(stop.locations)
            assert len(locations) == 1 and row['entry'] <= locations[0].address < row['end']
            stop.delete()
            lookup[name] = {'address': row['entry'], 'ptype': prototype, 'breakpointLocations': len(locations)}
        else:
            missing(name)
            lookup[name] = {'absent': True}
    if not compiler:
        assert int(gdb.parse_and_eval(expression(row['name']))) == row['entry']
        prototype = gdb.execute("ptype '" + row['name'] + "'", to_string=True)
        assert 'int (int)' in prototype, prototype
        stop = gdb.Breakpoint(row['name'], internal=True)
        locations = list(stop.locations)
        assert len(locations) == 1 and row['entry'] <= locations[0].address < row['end']
        stop.delete()
        missing('unbacked_' + row['name'].split('::')[-1])
if remote:
    gdb.execute('set sysroot ' + os.environ['ALIAS_SYSROOT'])
    gdb.execute('target remote ' + remote)

rows, exits, navigation = [], [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for iteration, argument in enumerate((19, -19)):
    for row in functions:
        # The second invocation enters through an original alias where available.
        original = row['original'] if row['name'].endswith('analyst_unique') else 'second_identity'
        name = original if compiler or (iteration == 1 and original in metadata['originalSymbols']) else row['name']
        stop = gdb.Breakpoint('*' + expression(name)[1:], internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        stop.delete()
        pc = int(gdb.parse_and_eval('$pc'))
        bias = pc - row['entry']
        if metadata['role'] != 'exec':
            assert bias != 0
        current = gdb.newest_frame()
        value = gdb.parse_and_eval('value')
        assert value.type.sizeof == 4 and not value.is_optimized_out and int(value) == argument
        owner = ('observed::unique(int)' if row['name'].endswith('analyst_unique') else 'observed::aliased(int)') if compiler else row['name']
        owned = gdb.parse_and_eval("'" + owner + "'::private_count")
        assert owned.type.sizeof == 4 and int(owned) == row['privateValue']
        assert int(gdb.parse_and_eval("&'" + owner + "'::private_count")) == row['privateAddress'] + bias
        if not compiler:
            assert current.name() == row['name']
            listing = gdb.execute("list '" + row['name'] + "'", to_string=True)
            assert row['name'].split('::')[-1] in listing and 'No such file' not in listing
            assert current.find_sal().symtab.filename.endswith('aliases.dbg.c')
        rows.append({'function': row['name'], 'lookup': name, 'pc': pc, 'bias': bias,
            'argument': int(value), 'privateValue': int(owned), 'frame': current.name()})
        # Exercise both commands with a return guard; synthetic and compiler line
        # grouping need not match, but neither may escape unnoticed.
        return_pc = row['returnInstruction'] + bias
        guard = gdb.Breakpoint('*' + hex(return_pc), internal=True)
        command = 'next' if iteration == 0 else 'step'
        gdb.execute(command)
        if not row['entry'] + bias < int(gdb.parse_and_eval('$pc')) <= return_pc:
            # A source step may enter the fixture's independently decoded PIC
            # helper. Prove its exact bytes and stacked return before returning.
            thunk = row.get('entryThunk')
            assert target == 'i386' and command == 'step' and thunk is not None
            thunk_pc = int(gdb.parse_and_eval('$pc'))
            assert thunk_pc == thunk['entry'] + bias
            assert bytes(gdb.selected_inferior().read_memory(thunk_pc, 4)).hex() == thunk['bytes']
            assert int(gdb.parse_and_eval('*(unsigned int *)$esp')) == thunk['returnPc'] + bias
            back = gdb.Breakpoint('*' + hex(thunk['returnPc'] + bias), internal=True)
            gdb.execute('continue')
            assert int(gdb.parse_and_eval('$pc')) == thunk['returnPc'] + bias
            back.delete()
            rows[-1]['steppedPicThunk'] = {'linkPc': thunk['entry'], 'bytes': thunk['bytes'],
                'returnPc': thunk['returnPc']}
        assert row['entry'] + bias < int(gdb.parse_and_eval('$pc')) <= return_pc
        navigation.append(command)
        if int(gdb.parse_and_eval('$pc')) != return_pc:
            gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == return_pc
        guard.delete()
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        gdb.execute('continue')
        expected = argument + row['privateValue'] if row['name'].endswith('analyst_unique') else argument - row['privateValue']
        assert int(finish.return_value) == expected
        rows[-1]['returned'] = expected
gdb.execute('continue')
assert exits == [0] and navigation == ['next', 'next', 'step', 'step']
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'lookup': lookup,
    'calls': rows, 'navigation': navigation, 'exitCodes': exits}, indent=4) + '\n')
print('retained-function-aliases-gdb=' + variant + ' PASS')

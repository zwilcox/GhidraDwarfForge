import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['PREFIX_CASE'])
target, variant = os.environ['PREFIX_TARGET'], os.environ['PREFIX_VARIANT']
compiler = variant == 'compiler'
proof = json.loads((case / 'proof.json').read_text())
labels = json.loads((case / 'labels.json').read_text())
function = proof['function']
entry, end = [int(x, 16) for x in function['ranges'][0]]
write, boundary = proof['writes'][0]['address'], proof['writes'][0]['fallthrough']
expected = [0x1122334455667788, 0x99aabbccddeeff00]
registers = ['rdi', 'rsi'] if target == 'x86_64' else ['x0', 'x1']
result = {'status': 'STARTED', 'target': target, 'variant': variant, 'entry': entry,
          'firstWrite': write, 'boundary': boundary, 'states': [], 'exitCodes': []}
gdb.events.exited.connect(lambda event: result['exitCodes'].append(getattr(event, 'exit_code', None)))


def number(expression):
    return int(gdb.parse_and_eval(expression))


try:
    chosen = 'capture_pair' if compiler else 'curated_capture_pair'
    symbol = gdb.lookup_global_symbol(chosen) if compiler else gdb.lookup_static_symbol(chosen)
    assert symbol is not None and symbol.symtab is not None
    expected_source = Path(os.environ['PREFIX_SOURCE']) if compiler else case / ('custom.prefix.dbg.c' if variant == 'custom' else 'prefix.dbg.c')
    assert Path(symbol.symtab.fullname()).resolve() == expected_source.resolve()
    result['ptype'] = gdb.execute('ptype ' + chosen, to_string=True)
    assert result['ptype'].startswith('type = void (')
    assert chosen in gdb.execute('list ' + chosen, to_string=True)
    breakpoint = gdb.Breakpoint('*' + hex(entry))
    remote = os.environ.get('PREFIX_REMOTE', '')
    if remote:
        gdb.execute('target remote ' + remote)
    gdb.execute('continue' if remote else 'run')
    assert number('$pc') == entry
    breakpoint.delete()
    for step in range(128):
        pc = number('$pc')
        if not entry <= pc < end:
            break
        raw = [number('$' + name) & ((1 << 64) - 1) for name in registers]
        value = gdb.selected_frame().read_var('value')
        assert value.type.sizeof == 16 and value.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT
        state = {'pc': pc, 'raw': raw, 'type': str(value.type), 'bytes': value.type.sizeof, 'available': not value.is_optimized_out}
        assert not value.is_optimized_out, state
        if not compiler:
            omissions = [o for o in proof['reports'][0 if variant == 'forge' else 2]['omittedLocations']
                if o['function'] == function['name'] and o['variable'] == 'value']
            assert not omissions, state
        backup = 'rax' if target == 'x86_64' else 'x2'
        if pc >= boundary:
            assert number('$' + backup) & ((1 << 64) - 1) == expected[0], state
        if not value.is_optimized_out:
            state['fields'] = {}
            for name, wanted in zip(('first', 'second'), expected):
                field = value[name]
                assert not field.is_optimized_out
                assert field.type.sizeof == 8 and field.type.strip_typedefs().code == gdb.TYPE_CODE_INT
                assert int(gdb.Value(-1).cast(field.type)) == (1 << 64) - 1
                assert int(field) == wanted, state
                state['fields'][name] = int(field)
        if pc <= write:
            assert raw == expected, state
        if pc == boundary:
            assert raw == [expected[0] & ~0xffff if target == 'x86_64' else 0, expected[1]], state
        result['states'].append(state)
        gdb.execute('stepi')
    else:
        raise AssertionError('bounded leaf did not return')
    assert {entry, labels['prefix_before']['address'], write, boundary} <= {s['pc'] for s in result['states']}
    result['globals'] = {name: number(name) for name in ('observed_first', 'observed_second')}
    assert list(result['globals'].values()) == expected
    result['returnPc'] = number('$pc')
    gdb.execute('continue')
    assert result['exitCodes'] == [0]
    result['status'] = 'PASS'
    print('composite-register-prefix-gdb=' + variant + ' PASS')
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

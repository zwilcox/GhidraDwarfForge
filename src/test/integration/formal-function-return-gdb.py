"""Actual normal caller; no injected call or finish-return interpretation."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['RETURN_CASE'])
variant = os.environ['RETURN_VARIANT']
assert variant in ('compiler', 'forge')
model = json.loads((case / 'model.json').read_text())
start, end = model['start'], model['end']
wanted = model['wanted']
result = {'status': 'STARTED', 'variant': variant, 'states': [], 'exitCodes': []}
gdb.events.exited.connect(lambda event: result['exitCodes'].append(getattr(event, 'exit_code', None)))

def number(expression):
    return int(gdb.parse_and_eval(expression))


def type_record(data_type, depth=0):
    plain = data_type.strip_typedefs()
    value = {'display': str(data_type), 'code': plain.code, 'bytes': plain.sizeof}
    if plain.code == gdb.TYPE_CODE_PTR and depth < 3:
        value['pointee'] = type_record(plain.target(), depth + 1)
    if plain.code == gdb.TYPE_CODE_STRUCT and depth < 3:
        value['fields'] = [{'name': field.name, 'bitpos': field.bitpos, 'type': type_record(field.type, depth + 1)} for field in plain.fields()]
    return value


try:
    name = 'make_result' if variant == 'compiler' else 'curated_make_result'
    symbol = gdb.lookup_global_symbol(name) if variant == 'compiler' else gdb.lookup_static_symbol(name)
    assert symbol is not None and symbol.symtab is not None
    expected_source = Path(os.environ['RETURN_SOURCE']) if variant == 'compiler' else case / 'return.dbg.c'
    assert Path(symbol.symtab.fullname()).resolve() == expected_source.resolve()
    function_type = symbol.type.strip_typedefs()
    assert function_type.code == gdb.TYPE_CODE_FUNC
    result['returnType'] = type_record(function_type.target())
    returned = function_type.target().strip_typedefs()
    assert returned.code == gdb.TYPE_CODE_STRUCT and returned.sizeof == 24, result['returnType']
    assert [(field.name, field.bitpos, field.type.sizeof) for field in returned.fields()] == [
        ('first', 0, 8), ('second', 64, 8), ('third', 128, 8)]
    result['ptype'] = gdb.execute('ptype ' + name, to_string=True)
    result['sourceList'] = gdb.execute('list ' + name, to_string=True)
    breakpoint = gdb.Breakpoint('*' + hex(start))
    gdb.execute('run')
    assert number('$pc') == start
    breakpoint.delete()
    destination = number('$rdi')
    result['entryCarriers'] = {'rdi': destination, 'rsi': number('$rsi') & ((1 << 64) - 1), 'edx': number('$edx') & 0xffffffff}
    assert destination != 0 and result['entryCarriers']['rsi'] == wanted[0] and result['entryCarriers']['edx'] == ((-19) & 0xffffffff)
    observed_positive = {'seed': 0, 'delta': 0}
    for step in range(128):
        pc = number('$pc')
        if not start <= pc < end:
            break
        state = {'pc': pc, 'raw': {name: number('$' + name) & ((1 << 64) - 1) for name in ('rdi', 'rsi', 'rdx', 'rax')}, 'parameters': {}}
        result['states'].append(state)
        names = ['seed', 'delta'] if variant == 'compiler' else [item['name'] for item in model['parameters']]
        for param_name in names:
            row = {}
            try:
                value = gdb.selected_frame().read_var(param_name)
                row['type'] = type_record(value.type)
                row['available'] = not value.is_optimized_out
                if row['available']:
                    row['value'] = int(value)
            except gdb.error as error:
                row['available'] = False
                row['error'] = str(error)
            state['parameters'][param_name] = row
            if variant == 'forge':
                description, = [item for item in model['parameters'] if item['name'] == param_name]
                expected_available = any(lo <= pc < hi for lo, hi, _ in description['locations'])
                assert row['available'] == expected_available, (pc, param_name, row, description)
                if not expected_available:
                    omissions = [o for o in model['report']['omittedLocations'] if o['function'] == name and o['variable'] == param_name
                        and int(o['startAddress'], 16) <= pc < int(o['endAddress'], 16)]
                    assert len(omissions) == 1, (pc, param_name, omissions)
                    row['omission'] = omissions[0]
            if row['available']:
                expected = wanted[0] if param_name == 'seed' else (-19 if param_name == 'delta' else destination)
                assert row['value'] == expected, (pc, param_name, row, expected)
                if param_name in observed_positive:
                    observed_positive[param_name] += 1
        gdb.execute('stepi')
    else:
        raise AssertionError('callee did not return within128 instructions')
    if variant == 'compiler':
        assert all(observed_positive.values()), observed_positive
    result['explicitPositivePCs'] = observed_positive
    result['returnPc'] = number('$pc')
    result['returnRax'] = number('$rax')
    result['hiddenDestination'] = destination
    assert result['returnRax'] == destination
    result['returnedBytes'] = bytes(gdb.selected_inferior().read_memory(destination, 24)).hex()
    assert result['returnedBytes'] == b''.join(value.to_bytes(8, 'little') for value in wanted).hex()
    breakpoint = gdb.Breakpoint('*' + hex(model['mainReturn']))
    gdb.execute('continue')
    assert number('$pc') == model['mainReturn']
    breakpoint.delete()
    result['callerGlobals'] = {name: number(name) for name in ('observed_first', 'observed_second', 'observed_third')}
    assert list(result['callerGlobals'].values()) == wanted
    gdb.execute('continue')
    assert result['exitCodes'] == [0]
    result['status'] = 'PASS'
    print('return-triple-gdb=' + variant + ' PASS')
except BaseException as error:
    result['error'] = repr(error)
    result['status'] = 'FAIL'
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

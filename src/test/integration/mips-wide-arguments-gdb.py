"""Source-known wide arguments, independently decoded homes and precise compiler windows."""
import importlib.util
import json
import os
from pathlib import Path

import gdb

case = Path(os.environ['FORGE_MIPS_WIDE_CASE'])
mode = os.environ['FORGE_MIPS_WIDE_MODE']
assert mode in ('compiler', 'forge')
failed = os.environ.get('FORGE_MIPS_WIDE_FAILED_FUNCTION')
assert failed is None or failed == 'wide_pair' and mode == 'forge'
phase = os.environ.get('FORGE_MIPS_WIDE_PHASE', 'instructions')
assert phase in ('instructions', 'source', 'calls')
result_prefix = mode + ('-' + phase if phase != 'instructions' else '')
metadata = json.loads((case / 'metadata.json').read_text())
shared = metadata['role'].startswith('shared')
artifact = case / ('abi.reference' if mode == 'compiler' else 'abi.dbg')
for command in ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
        'set auto-solib-add off', 'set sysroot ' + metadata['sysroot'],
        'set solib-search-path ' + str(case), 'file ' + str(case / metadata['runtime'])]:
    gdb.execute(command)
if metadata['role'] == 'exec':
    gdb.execute('symbol-file ' + str(artifact))
gdb.execute('target remote ' + os.environ['FORGE_MIPS_WIDE_REMOTE'])
if not shared and metadata['role'] != 'exec':
    # With MIPS PIE, GDB 15 can relocate the symbols but retain a wrong frame
    # lookup when a separate symbol-file is supplied before remote attach.
    # Apply the actual loader bias explicitly; never suppress that warning.
    auxiliary = gdb.execute('info auxv', to_string=True)
    entry, = [line.split()[-1] for line in auxiliary.splitlines() if 'AT_ENTRY' in line]
    bias = int(entry, 16) - metadata['entryAddress']
    assert bias > 0
    gdb.execute('symbol-file -o ' + hex(bias) + ' ' + str(artifact))
    (case / (mode + '-loader.json')).write_text(json.dumps({
        'runtimeEntry': int(entry, 16), 'linkEntry': metadata['entryAddress'],
        'bias': bias, 'auxiliaryVector': auxiliary}, indent=4) + '\n')
if shared:
    stop = gdb.Breakpoint('*main', temporary=True, internal=True)
    gdb.execute('continue')
    assert gdb.selected_frame().name() == 'main'
    libraries = gdb.execute('info sharedlibrary', to_string=True)
    library, = [line for line in libraries.splitlines()
        if line.split()[-1:] == [str(case / 'abi.input')]]
    bias = int(library.split()[0], 16) - metadata['textAddress']
    assert bias > 0
    gdb.execute('add-symbol-file ' + str(artifact) + ' -o ' + hex(bias))

spec = importlib.util.spec_from_file_location('wide_oracle', Path(__file__).with_name('mips-wide-arguments-oracle.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
endian = 'big' if metadata['endian'] == 'be' else 'little'
pointer_bytes = 4 if metadata['abi'] == 'n32' else 8
raw_order = None


def register(number):
    names = {2: 'v0', 3: 'v1', **{i + 4: 'a' + str(i) for i in range(8)}, 29: 'sp'}
    value = gdb.selected_frame().read_register(names[number] if number < 32 else 'f' + str(number - 32))
    if number < 32:
        return int(value) & ((1 << (value.type.sizeof * 8)) - 1)
    return int.from_bytes(value.bytes, raw_order)


def memory(address, size):
    return bytes(gdb.selected_inferior().read_memory(address, size))


rows, bindings, limitations, returns, positives = [], {}, [], {}, {}
strict_reference = os.environ.get('FORGE_MIPS_WIDE_STRICT_REFERENCE') == '1'
if phase == 'calls':
    # All three earlier ordinary calls have initialized the aggregate globals.
    gdb.Breakpoint('*wide_mixed', temporary=True, internal=True)
    gdb.execute('continue')
    calls = []
    for name, arguments in [
            ('wide_words', '(11LL,22LL,33LL,44LL,55LL,66LL,77LL,88LL,909LL,-1010LL)'),
            ('wide_pair', '(pair_sink)'), ('wide_large', '(large_sink)'),
            ('wide_mixed', '(17LL,1.25,-19,-2.5f,pair_sink,23LL,3.75,29LL,-31)')]:
        for binding in (name, name.removeprefix('wide_') + '_callback'):
            wanted = oracle.RETURNS[name]
            before = {register: int(gdb.parse_and_eval('$' + register)) for register in ('pc', 'sp')}
            print("CALL_EXPRESSION", binding + arguments)
            value = gdb.parse_and_eval(binding + arguments)
            actual = {field: int(value[field]) for field in wanted} if isinstance(wanted, dict) else int(value)
            assert actual == wanted, (mode, binding, str(value))
            assert before == {register: int(gdb.parse_and_eval('$' + register)) for register in before}
            calls.append({'expression': binding + arguments, 'expected': wanted, 'actual': actual})
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$_exitcode')) == 0
    (case / (result_prefix + '-observations.json')).write_text(json.dumps(calls, indent=4) + '\n')
    print('MIPS_WIDE_ARGUMENTS_' + mode.upper() + '_PASS calls=' + str(len(calls)))
    gdb.execute('quit')

for function, expected in oracle.EXPECTED.items():
    start = int(gdb.parse_and_eval('&' + function))
    current_bias = start - metadata['symbols'][function]
    assert (current_bias == 0) == (metadata['role'] == 'exec')
    bindings[function] = current_bias
    assert len(set(bindings.values())) == 1
    if metadata['abi'] == 'n64' and metadata['role'] == 'exec':
        assert start > 0xffffffff
    if metadata['role'] != 'exec':
        assert current_bias == bias
    named = gdb.Breakpoint(function, internal=True)
    assert named.locations and all(start <= location.address < start + metadata['sizes'][function]
        for location in named.locations)
    named.delete()
    gdb.Breakpoint('*' + hex(start), temporary=True, internal=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == start
    # GDB 15.1 exposes target-order Value.bytes even though newer manuals
    # specify little endian. Calibrate the buffer representation using a GPR
    # with an independently available integer conversion; never guess for FP.
    value = gdb.selected_frame().read_register('a0')
    orders = [order for order in ('big', 'little') if int.from_bytes(value.bytes, order) == register(4)]
    assert len(orders) == 1 and raw_order in (None, orders[0])
    raw_order = orders[0]
    entry_values = oracle.entry_arguments(function, register, memory, endian, pointer_bytes)
    assert entry_values == expected, (mode, function, entry_values)
    entry_stack = register(29) & ((1 << (pointer_bytes * 8)) - 1)
    code = memory(start, metadata['sizes'][function])
    assert code.hex() == metadata['code'][function], 'runtime code differs from compiler fixture'
    proof = oracle.contract(function, code, endian, metadata['homes'].get(function))
    if function != failed:
        listing = gdb.execute('list ' + function, to_string=True)
        assert function in listing and 'No such file' not in listing
        assert 'type =' in gdb.execute('ptype ' + next(iter(expected)), to_string=True)
    hidden_buffer = register(4) & ((1 << (pointer_bytes * 8)) - 1) if function == 'wide_large' else None
    return_type = gdb.parse_and_eval(function).type.target()
    finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
    positives[function] = dict.fromkeys(expected, 0)
    for step in range(200):
        pc = int(gdb.parse_and_eval('$pc'))
        if not start <= pc < start + proof['size']:
            break
        offset = pc - start
        raw = oracle.entry_arguments(function, register, memory, endian, pointer_bytes)
        # Stack addresses are relative to the captured incoming pointer, not
        # the changing physical register at this instruction.
        if function == 'wide_words':
            raw.update(i=int.from_bytes(memory(entry_stack, 8), endian, signed=True),
                j=int.from_bytes(memory(entry_stack + 8, 8), endian, signed=True))
        if function == 'wide_mixed':
            raw.update(h=int.from_bytes(memory(entry_stack, 8), endian, signed=True),
                tail=int.from_bytes(memory(entry_stack + (12 if endian == 'big' else 8), 4), endian, signed=True))
        for expression, wanted in expected.items():
            gap = offset >= proof['clobbers'].get(expression, proof['size'])
            if not gap:
                assert raw[expression] == wanted, (function, offset, expression, raw[expression])
            if function == failed:
                try:
                    unavailable = gdb.parse_and_eval(expression)
                except gdb.error as error:
                    assert 'No symbol' in str(error), str(error)
                else:
                    assert unavailable.is_optimized_out, 'failed decompilation retained a variable location'
                rows.append({'function': function, 'offset': offset, 'expression': expression,
                    'unavailable': True, 'failedDecompilation': True})
                continue
            value = gdb.parse_and_eval(expression)
            row = {'function': function, 'offset': offset, 'expression': expression,
                'display': str(value), 'expected': wanted, 'unavailable': value.is_optimized_out}
            window = oracle.reference_window(function, expression, offset, proof) if mode == 'compiler' else None
            if gap:
                assert value.is_optimized_out, (mode, function, offset, expression, str(value))
            elif window and not strict_reference:
                assert raw[expression] == wanted
                row['referenceWindow'] = window
                limitations.append(dict(row))
            else:
                assert not value.is_optimized_out, (mode, function, offset, expression)
                actual = float(value) if isinstance(wanted, float) else int(value)
                assert actual == wanted, (mode, function, offset, expression, actual, wanted)
                row['actual'] = actual
                positives[function][expression] += 1
            rows.append(row)
        command = 'next' if phase == 'source' and step == 1 and function != failed else 'step' if phase == 'source' and step == 2 and function != failed else 'stepi'
        gdb.execute(command)
    else:
        raise AssertionError('instruction bound exceeded')
    if phase == 'instructions' and function != failed:
        assert all(positives[function].values()), (function, positives[function])
    returned = finish.return_value
    if function == failed:
        assert returned is None, 'failed symbol-only function unexpectedly retained a typed return'
        raw_return = {'first': oracle.signed(register(2), 64), 'second': oracle.signed(register(3), 64)}
        assert raw_return == oracle.RETURNS[function]
        returns[function] = {'value': None, 'automatic': False, 'symbolOnly': True, 'raw': raw_return}
        if finish.is_valid():
            finish.delete()
        continue
    automatic = returned is not None and not returned.is_optimized_out
    if not automatic:
        assert function == 'wide_large' and hidden_buffer, (mode, function, 'return unavailable')
        returned = gdb.Value(hidden_buffer).cast(return_type.pointer()).dereference()
        assert not returned.is_optimized_out
    wanted = oracle.RETURNS[function]
    actual = {field: int(returned[field]) for field in wanted} if isinstance(wanted, dict) else int(returned)
    assert actual == wanted, (mode, function, 'return', str(returned))
    returns[function] = {'value': actual, 'automatic': automatic}
    if finish.is_valid():
        finish.delete()
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
(case / (result_prefix + '-observations.json')).write_text(json.dumps({
    'rows': rows, 'referenceWindows': limitations, 'positiveCounts': positives,
    'returns': returns, 'biases': bindings, 'registerByteOrder': raw_order}, indent=4) + '\n')
print('MIPS_WIDE_ARGUMENTS_' + mode.upper() + '_PASS observations=' + str(len(rows)))

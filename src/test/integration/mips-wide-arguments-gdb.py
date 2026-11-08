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

o32 = metadata['abi'] == 'o32'
spec = importlib.util.spec_from_file_location('wide_oracle', Path(__file__).with_name(
    'mips-o32-arguments-oracle.py' if o32 else 'mips-wide-arguments-oracle.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)
endian = 'big' if metadata['endian'] == 'be' else 'little'
pointer_bytes = 8 if metadata['abi'] == 'n64' else 4
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
    call_cases = [
            ('wide_words', '(11LL,22LL,33LL,44LL,55LL,66LL,77LL,88LL,909LL,-1010LL)'),
            ('wide_pair', '(pair_sink)'), ('wide_large', '(large_sink)'),
            ('wide_mixed', '(17LL,1.25,-19,-2.5f,pair_sink,23LL,3.75,29LL,-31)')]
    if o32:
        # A compiler-reference aggregate injection can corrupt its own sink.
        # Exercise the scalar/mixed calls before those independent reference probes.
        call_cases = [call_cases[index] for index in (0, 3, 1, 2)]
    for name, arguments in call_cases:
        for binding in (name, name.removeprefix('wide_') + '_callback'):
            wanted = oracle.RETURNS[name]
            before = {register: int(gdb.parse_and_eval('$' + register)) for register in ('pc', 'sp')}
            print("CALL_EXPRESSION", binding + arguments)
            if o32 and mode == 'forge' and name in ('wide_pair', 'wide_large'):
                def state():
                    return {
                        'registers': {item.name: str(gdb.selected_frame().read_register(item.name))
                            for item in gdb.selected_frame().architecture().registers()},
                        'stack': memory(before['sp'], 256).hex(),
                        'globals': {symbol: memory(int(gdb.parse_and_eval('&' + symbol)),
                            metadata['sizes'][symbol]).hex() for symbol in
                            ('integer_sink', 'real_sink', 'pair_sink', 'large_sink')}}
                unchanged = state()
                try:
                    gdb.parse_and_eval(binding + arguments)
                except gdb.error as error:
                    assert 'does not follow the target calling convention' in str(error), str(error)
                    calls.append({'expression': binding + arguments, 'guard': str(error), 'unchanged': True})
                else:
                    raise AssertionError('unclassified O32 aggregate call was accepted')
                assert state() == unchanged
                continue
            reference_entry = []
            probe = None
            if o32 and mode == 'compiler' and name in ('wide_pair', 'wide_large'):
                global_name = name.removeprefix('wide_') + '_sink'
                passed = memory(int(gdb.parse_and_eval('&' + global_name)), metadata['sizes'][global_name])

                class ObserveAggregateCall(gdb.Breakpoint):
                    def stop(self):
                        sp = register(29) & 0xffffffff
                        slots = b''.join(register(number).to_bytes(4, endian) for number in (5, 6, 7))
                        slots += memory(sp + 16, len(passed))
                        raw = oracle.entry_arguments(name, register, memory, endian, 4)
                        correct = slots[4:4 + len(passed)] == passed
                        # GDB 15's O32 aggregate push neglects this eight-byte
                        # alignment hole after the hidden return pointer. Prove
                        # the exact misplaced bytes before accepting a limitation.
                        assert correct or slots[:len(passed)] == passed
                        reference_entry.append({'correctTransfer': correct, 'raw': raw,
                            'passedBytes': passed.hex(), 'slotBytes': slots.hex(), 'buffer': register(4)})
                        return False

                probe = ObserveAggregateCall('*' + name, internal=True)
            value = gdb.parse_and_eval(binding + arguments)
            actual = {field: int(value[field]) for field in wanted} if isinstance(wanted, dict) else int(value)
            if probe is not None:
                probe.delete()
                entry, = reference_entry
                raw_return = {field: int.from_bytes(memory(entry['buffer'] + index * 8, 8), endian, signed=True)
                    for index, field in enumerate(wanted)}
                assert actual == raw_return == {field: entry['raw']['value.' + field] for field in wanted}
                calls.append({'expression': binding + arguments, 'actual': actual, 'compilerReference': entry})
            else:
                assert actual == wanted, (mode, binding, str(value))
                calls.append({'expression': binding + arguments, 'expected': wanted, 'actual': actual})
            assert before == {register: int(gdb.parse_and_eval('$' + register)) for register in before}
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
    calibration = 29 if o32 else 4
    value = gdb.selected_frame().read_register('sp' if o32 else 'a0')
    orders = [order for order in ('big', 'little') if int.from_bytes(value.bytes, order) == register(calibration)]
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
    hidden_buffer = register(4) & ((1 << (pointer_bytes * 8)) - 1) if function == 'wide_large' or o32 and function == 'wide_pair' else None
    return_type = gdb.parse_and_eval(function).type.target()
    guarded_return = o32 and mode == 'forge' and function in ('wide_pair', 'wide_large') and function != failed
    finish = None if guarded_return else gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
    positives[function] = dict.fromkeys(expected, 0)
    for step in range(200):
        pc = int(gdb.parse_and_eval('$pc'))
        if not start <= pc < start + proof['size']:
            break
        offset = pc - start
        raw = oracle.entry_arguments(function, register, memory, endian, pointer_bytes,
            **({'stack_pointer': entry_stack} if o32 else {}))
        # Stack addresses are relative to the captured incoming pointer, not
        # the changing physical register at this instruction.
        if not o32 and function == 'wide_words':
            raw.update(i=int.from_bytes(memory(entry_stack, 8), endian, signed=True),
                j=int.from_bytes(memory(entry_stack + 8, 8), endian, signed=True))
        if not o32 and function == 'wide_mixed':
            raw.update(h=int.from_bytes(memory(entry_stack, 8), endian, signed=True),
                tail=int.from_bytes(memory(entry_stack + (12 if endian == 'big' else 8), 4), endian, signed=True))
        for expression, wanted in expected.items():
            gap = oracle.unavailable(function, expression, offset, proof, mode) if o32 else (
                offset >= proof['clobbers'].get(expression, proof['size']))
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
            if window and not strict_reference:
                assert gap or raw[expression] == wanted
                row['referenceWindow'] = window
                limitations.append(dict(row))
            elif gap:
                assert value.is_optimized_out, (mode, function, offset, expression, str(value))
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
    returned = None if finish is None else finish.return_value
    if function == failed:
        assert returned is None, 'failed symbol-only function unexpectedly retained a typed return'
        raw_return = {field: int.from_bytes(memory(hidden_buffer + index * 8, 8), endian, signed=True)
            for index, field in enumerate(oracle.RETURNS[function])} if o32 else {
            'first': oracle.signed(register(2), 64), 'second': oracle.signed(register(3), 64)}
        assert raw_return == oracle.RETURNS[function]
        returns[function] = {'value': None, 'automatic': False, 'symbolOnly': True, 'raw': raw_return}
        if finish.is_valid():
            finish.delete()
        continue
    automatic = returned is not None and not returned.is_optimized_out
    if not automatic:
        assert (function == 'wide_large' or o32 and function == 'wide_pair') and hidden_buffer, (mode, function, 'return unavailable')
        returned = gdb.Value(hidden_buffer).cast(return_type.pointer()).dereference()
        assert not returned.is_optimized_out
    wanted = oracle.RETURNS[function]
    actual = {field: int(returned[field]) for field in wanted} if isinstance(wanted, dict) else int(returned)
    assert actual == wanted, (mode, function, 'return', str(returned))
    returns[function] = {'value': actual, 'automatic': automatic}
    if finish is not None and finish.is_valid():
        finish.delete()
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
(case / (result_prefix + '-observations.json')).write_text(json.dumps({
    'rows': rows, 'referenceWindows': limitations, 'positiveCounts': positives,
    'returns': returns, 'biases': bindings, 'registerByteOrder': raw_order}, indent=4) + '\n')
print('MIPS_WIDE_ARGUMENTS_' + mode.upper() + '_PASS observations=' + str(len(rows)))

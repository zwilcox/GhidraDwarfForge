"""Compare immutable AAPCS64 arguments at entry and every executed instruction."""
import json
import importlib.util
import os
from pathlib import Path

import gdb

spec = importlib.util.spec_from_file_location('abi_oracle', Path(__file__).with_name('aarch64-abi-oracle.py'))
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)

case = Path(os.environ['FORGE_AARCH64_ABI_CASE'])
remote = os.environ['FORGE_AARCH64_ABI_REMOTE']
mode = os.environ.get('FORGE_AARCH64_ABI_MODE', 'compiler')
assert mode in ('compiler', 'forge'), mode
failed_function = os.environ.get('FORGE_AARCH64_ABI_FAILED_FUNCTION')
assert failed_function is None or mode == 'forge' and failed_function == 'abi_large_spill'
failed_symbols = []
result_prefix = os.environ.get('FORGE_AARCH64_ABI_RESULT_PREFIX', mode)
sidecar = os.environ.get('FORGE_AARCH64_ABI_SIDECAR', str(case / 'abi.dbg'))
metadata = json.loads((case / 'metadata.json').read_text()) if (case / 'metadata.json').exists() else None
shared = bool(metadata and 'driver' in metadata)
gdb.execute('set pagination off')
gdb.execute('set confirm off')
gdb.execute('set debuginfod enabled off')
gdb.execute('set auto-solib-add off')
gdb.execute('set sysroot /usr/aarch64-linux-gnu')
gdb.execute('set solib-search-path ' + str(case))
gdb.execute('file ' + str(case / (metadata['driver'] if shared else 'abi.input')))
artifact = str(case / 'abi.reference') if mode == 'compiler' else sidecar
if not shared:
    gdb.execute('symbol-file ' + artifact)
gdb.execute('target remote ' + remote)

if shared:
    # Wait for the real loader, then explicitly relocate the separate symbol
    # file. Automatic library symbols remain disabled for both references.
    stop = gdb.Breakpoint('*main', internal=True)
    gdb.execute('continue')
    stop.delete()
    assert gdb.selected_frame().name() == 'main'
    libraries = gdb.execute('info sharedlibrary', to_string=True)
    library, = [line for line in libraries.splitlines() if line.split()[-1:] == [str(case / 'abi.input')]]
    runtime_text = int(library.split()[0], 16)
    shared_bias = runtime_text - metadata['textAddress']
    assert shared_bias > 0
    if mode == 'forge':
        for name in metadata['symbols']:
            try:
                gdb.parse_and_eval('&curated_' + name)
            except gdb.error as error:
                assert 'No symbol' in str(error)
            else:
                raise AssertionError('curated symbol available before explicit sidecar load')
    gdb.execute('add-symbol-file ' + artifact + ' -o ' + hex(shared_bias))
    bindings = {}
    for name, link_address in metadata['symbols'].items():
        original = int(gdb.parse_and_eval('&' + name))
        assert original == link_address + shared_bias
        curated = int(gdb.parse_and_eval('&curated_' + name)) if mode == 'forge' else None
        assert curated is None or curated == original
        bindings[name] = {'original': original, 'curated': curated, 'linkAddress': link_address}
    (case / (result_prefix + '-shared-bindings.json')).write_text(json.dumps({
        'bias': shared_bias, 'library': str(case / 'abi.input'), 'artifact': artifact,
        'runtimeText': runtime_text, 'linkText': metadata['textAddress'], 'symbols': bindings,
        'autoSolibAdd': False}, indent=4) + '\n')

wide_positive = (0x1234567890abcdef << 64) | 0x0fedcba987654321
expected = {
    'abi_words': dict(zip('abcdefghij', (11, 22, 33, 44, 55, 66, 77, 88, 909, -1010))),
    'abi_floats': dict(zip('abcdefghij', (1.25, 2.5, 3.75, 4, 5, 6, 7, 8, 9.5, -10.25))),
    'abi_pair': {'value.first': 101, 'value.second': -202},
    'abi_large': {'value.first': 303, 'value.second': -404, 'value.third': 505},
    'abi_large_stack': {**dict(zip('abcdefgh', range(1, 9))),
        'value.first': 303, 'value.second': -404, 'value.third': 505},
    'abi_large_spill': {'value.first': 303, 'value.second': -404, 'value.third': 505},
    'abi_large_spill_alias': {'value.first': 303, 'value.second': -404, 'value.third': 505},
    'abi_hfa': {'value.first': 1.25, 'value.second': -2.5, 'value.third': 3.75, 'value.fourth': 4.5},
    'abi_hfa_exhausted': {
        **dict(zip('abcdefg', (1, 2, 3, 4, 5, 6, 7))),
        'value.first': 1.25, 'value.second': -2.5, 'value.third': 3.75,
        'value.fourth': 4.5, 'tail': 9.5,
    },
    'abi_narrow_stack': {**dict(zip('abcdefgh', range(1, 9))), 'low': -37,
        'high': 50001, 'middle': -123456, 'wide': 0x1234567890abcdef},
    'abi_aligned_stack': {**dict(zip('abcdefgh', range(1, 9))), 'lead': -19,
        'wide': wide_positive, 'tail': 23},
    'abi_aligned_register': {'first': 11, 'wide': -wide_positive, 'tail': -13},
    'abi_pair_stack': {**dict(zip('abcdefg', range(1, 8))),
        'value.first': 101, 'value.second': -202, 'tail': -41},
    'abi_pair_chain': {**dict(zip('abcdefg', range(1, 8))), 'value.first': 101,
        'value.second': -202, 'tail': -41, 'wide': wide_positive, 'object.first': 13,
        'object.second': 24, 'object.third': 35, 'floating': 42.5},
    'abi_pair_variadic': {**dict(zip('abcdefg', range(1, 8))),
        'value.first': 101, 'value.second': -202, 'tail': -41},
}
rows = []
failures = []
returns = {}
entries = {}
reference_limits = []
strict_reference = os.environ.get('FORGE_AARCH64_ABI_STRICT_REFERENCE', '0') == '1'
biases = {}
locations = json.loads((case / 'indirect-locations.json').read_text()) if mode == 'forge' else {}
carriers = []
expected_returns = {
    'abi_words': 295, 'abi_floats': 36.75,
    'abi_pair': {'first': 102, 'second': -200},
    'abi_large': {'first': 304, 'second': -402, 'third': 508},
    'abi_large_stack': 440,
    'abi_large_spill': {'first': 304, 'second': -402, 'third': 508},
    'abi_large_spill_alias': {'first': 304, 'second': -402, 'third': 508},
    'abi_hfa': {'first': 2.25, 'second': -0.5, 'third': 6.75, 'fourth': 8.5},
    'abi_hfa_exhausted': 44.5,
    'abi_narrow_stack': 0x1234567890abcdef - 73456,
    'abi_aligned_stack': wide_positive + 40, 'abi_aligned_register': -wide_positive - 2,
    'abi_pair_stack': -114, 'abi_pair_chain': 0x0fedcba987654321, 'abi_pair_variadic': -114,
}


def number(value):
    if value.type.strip_typedefs().code == gdb.TYPE_CODE_FLT:
        return float(value)
    # GDB 15's Python int(Value) conversion stops at eight bytes, although
    # its typed decimal formatter supports the actual 128-bit integer.
    return int(value.format_string(format='d')) if value.type.sizeof > 8 else int(value)


def register(name):
    return bytes(gdb.selected_frame().read_register(name).bytes)


def memory(address, size):
    return bytes(gdb.selected_inferior().read_memory(address, size))


exits = []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
for name, parameters in expected.items():
    symbol = name if mode == 'compiler' else 'curated_' + name
    entry = int(gdb.parse_and_eval('&' + symbol))
    gdb.Breakpoint('*' + hex(entry), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == entry, name
    if name == failed_function:
        assert metadata and biases and entry - metadata['symbols'][name] == next(iter(biases.values()))
        try:
            gdb.parse_and_eval('value')
        except gdb.error as error:
            failed_symbols.append({'function': name, 'entry': entry, 'unavailable': str(error),
                'arguments': gdb.execute('info args', to_string=True)})
        else:
            raise AssertionError('failed function acquired an invented argument')
        continue
    # Observe the same return stop while single-stepping both symbol files.
    # The independently captured buffer below also tests the case in which
    # GDB cannot display a return after the callee legally overwrites x8.
    finish_breakpoint = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
    return_type = gdb.parse_and_eval(symbol).type.target()
    if metadata:
        bias = entry - metadata['symbols'][name]
        assert (bias == 0) == (metadata['role'] == 'exec'), (name, bias, metadata['role'])
        biases[name] = bias
        assert len(set(biases.values())) == 1, biases
    raw_entry = oracle.entry_arguments(name, register, memory)
    assert raw_entry == parameters, (name, raw_entry, parameters)
    entries[name] = raw_entry
    object_address = None
    if name in locations:
        object_address = int.from_bytes(memory(int.from_bytes(register('sp'), 'little'), 8), 'little') \
            if name == 'abi_large_stack' else int.from_bytes(memory(int.from_bytes(register('sp'), 'little') + 48, 8), 'little') if name == 'abi_pair_chain' else int.from_bytes(register('x0'), 'little')
    hidden_buffer = int.from_bytes(register('x8'), 'little') if name in ('abi_large', 'abi_large_spill', 'abi_large_spill_alias') else None
    prefix = memory(entry, 40)
    positive = dict.fromkeys(parameters, 0)
    for index in range(128):
        pc = int(gdb.parse_and_eval('$pc'))
        instruction = gdb.selected_frame().architecture().disassemble(pc, count=1)[0]['asm']
        window = oracle.reference_window(name, pc - entry, prefix) if mode == 'compiler' and not strict_reference else None
        if window:
            # The exact prefix is read-only for the incoming ABI carriers. It
            # must still hold all source-known arguments at every excluded PC.
            raw_window = oracle.entry_arguments(name, register, memory)
            assert raw_window == parameters, (name, pc, window)
        values = {}
        for expression, wanted in parameters.items():
            try:
                value = gdb.parse_and_eval(expression)
                values[expression] = {'display': str(value), 'optimizedOut': value.is_optimized_out}
                if not value.is_optimized_out:
                    numeric = number(value)
                    values[expression]['numeric'] = numeric
                    if numeric != wanted:
                        if window and expression.startswith(('value.', 'object.')):
                            reference_limits.append({'function': name, 'offset': pc - entry,
                                'expression': expression, 'compilerDisplay': str(value), 'abiValue': raw_window[expression],
                                'reason': window, 'instruction': instruction})
                        else:
                            failures.append([name, pc - entry, expression, str(value), wanted])
                    else:
                        positive[expression] += 1
                elif index == 0:
                    failures.append([name, 0, expression, 'unavailable at entry'])
            except gdb.error as error:
                values[expression] = {'unavailable': str(error)}
                if window and name == 'abi_pair_chain' and expression.startswith('object.') and str(error).startswith('Cannot access memory at address '):
                    reference_limits.append({'function': name, 'offset': pc - entry,
                        'expression': expression, 'compilerError': str(error), 'abiValue': raw_window[expression],
                        'reason': window, 'instruction': instruction})
                elif index == 0:
                    failures.append([name, 0, expression, str(error)])
        rows.append({'function': name, 'pc': pc, 'offset': pc - entry,
            'instruction': instruction, 'values': values})
        if name in locations:
            matches = [row for row in locations[name] if row['start'] <= pc - entry < row['end']]
            assert len(matches) <= 1
            carrier = {'function': name, 'offset': pc - entry, 'available': bool(matches)}
            if matches:
                location, = matches
                base = int.from_bytes(register('sp' if location['register'] == 31 else
                    'x' + str(location['register'])), 'little')
                address = base + location['displacement']
                if location['dereference']:
                    address = int.from_bytes(memory(address, 8), 'little')
                assert address == object_address, (name, pc, location, address, object_address)
                assert all(values[field].get('numeric') == wanted for field, wanted in parameters.items()
                    if field.startswith('object.' if name == 'abi_pair_chain' else 'value.')), (name, pc, values)
                carrier.update(location=location, address=address)
            else:
                assert all(values[field].get('optimizedOut') or 'unavailable' in values[field]
                    for field in parameters if field.startswith('object.' if name == 'abi_pair_chain' else 'value.')), (name, pc, values)
            # Observe the actual state after the final deliberate register write.
            # Every possible integer carrier except the frame register is zero.
            if name.startswith('abi_large_spill') and pc > entry and memory(pc - 4, 4) == bytes.fromhex('fe031faa'):
                zeroed = {str(index): int.from_bytes(register('x' + str(index)), 'little')
                    for index in (*range(29), 30)}
                assert set(zeroed.values()) == {0}, zeroed
                carrier['allIntegerCarriersZero'] = zeroed
                assert bool(matches) == (name == 'abi_large_spill'), carrier
                if matches:
                    assert matches[0]['register'] == 31 and matches[0]['dereference'], matches
            carriers.append(carrier)
        if instruction.split()[0] == 'ret':
            raw_return = oracle.return_value(name, register, memory, hidden_buffer)
            assert raw_return == expected_returns[name], (name, raw_return)
            final_buffer_register = int.from_bytes(register('x8'), 'little') if hidden_buffer else None
            transcript = gdb.execute('continue', to_string=True)
            value = finish_breakpoint.return_value
            automatic_unavailable = value is None
            if automatic_unavailable:
                # A negative consumer control, reproduced using compiler DWARF:
                # this fixture zeroes x8 and GDB 15 does not retain its entry
                # buffer address. Still require the declared return type and
                # the independently captured, actual caller-owned memory.
                assert name in ('abi_large_spill', 'abi_large_spill_alias') and hidden_buffer and final_buffer_register == 0, name
                value = gdb.Value(hidden_buffer).cast(return_type.pointer()).dereference()
            wanted = expected_returns[name]
            assert value.type.sizeof == {'abi_pair': 16, 'abi_large': 24, 'abi_large_spill': 24, 'abi_large_spill_alias': 24, 'abi_hfa': 16, 'abi_aligned_stack': 16, 'abi_aligned_register': 16}.get(name, 8), name
            observed = {field: number(value[field]) for field in wanted} if isinstance(wanted, dict) else number(value)
            assert observed == wanted, (name, observed, wanted)
            returns[name] = {'value': observed, 'abiValue': raw_return, 'type': str(value.type),
                'automaticReturnUnavailable': automatic_unavailable, 'transcript': transcript}
            break
        gdb.execute('stepi')
    else:
        raise AssertionError('fixture did not reach its return: ' + name)
    assert all(count >= 2 for count in positive.values()), (name, 'insufficient positive typed observations', positive)
gdb.execute('continue')
assert exits == [0], exits
(case / (result_prefix + '-observations.json')).write_text(json.dumps(rows, indent=4) + '\n')
(case / (result_prefix + '-failures.json')).write_text(json.dumps(failures, indent=4) + '\n')
(case / (result_prefix + '-returns.json')).write_text(json.dumps(returns, indent=4) + '\n')
(case / (result_prefix + '-abi-entries.json')).write_text(json.dumps(entries, indent=4) + '\n')
(case / (result_prefix + '-reference-limitations.json')).write_text(json.dumps(reference_limits, indent=4) + '\n')
(case / (result_prefix + '-biases.json')).write_text(json.dumps(biases, indent=4) + '\n')
(case / (result_prefix + '-carriers.json')).write_text(json.dumps(carriers, indent=4) + '\n')
(case / (result_prefix + '-failed-symbols.json')).write_text(json.dumps(failed_symbols, indent=4) + '\n')
if mode == 'forge':
    assert [row['function'] for row in failed_symbols] == ([failed_function] if failed_function else [])
    for name in ('abi_large_spill', 'abi_large_spill_alias'):
        if name == failed_function:
            continue
        samples = [row for row in carriers if row['function'] == name]
        clobber, = [row for row in samples if 'allIntegerCarriersZero' in row]
        after = [row for row in samples if row['offset'] > clobber['offset']]
        if name == 'abi_large_spill':
            assert any(row['available'] and not row['location']['dereference'] for row in after), \
                'missing positive reloaded carrier'
            assert any(not row['available'] for row in after), 'missing post-store unavailable tail'
        else:
            assert all(not row['available'] for row in after), 'unproven pointer slot revived after reload'
    reference = json.loads((case / 'compiler-observations.json').read_text())
    assert [(row['function'], row['offset']) for row in rows] == [
        (row['function'], row['offset']) for row in reference if row['function'] != failed_function], 'different executed instruction sequence'
    reference_returns = json.loads((case / 'compiler-returns.json').read_text())
    assert {name: row['automaticReturnUnavailable'] for name, row in returns.items()} == {
        name: row['automaticReturnUnavailable'] for name, row in reference_returns.items()
        if name != failed_function}, 'return behavior differs from compiler reference'
assert not failures, failures
print('AARCH64_ABI_' + mode.upper() + '_ORACLE_PASS', len(rows))

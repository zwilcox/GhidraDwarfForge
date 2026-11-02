"""Compiler-relative i386 ABI values, independently read carriers and exact SSE clobbers."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import gdb

spec = importlib.util.spec_from_file_location('diagnostics', Path(__file__).with_name('i386-abi-matrix-diagnostics.py'))
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)

case = Path(os.environ['I386_CASE'])
variant = os.environ['I386_VARIANT']
failed = os.environ.get('I386_ABI_FAILED_FUNCTION')
assert failed is None or variant == 'forge' and failed == 'vector_add'
expected = [
    ('scalar_float', {'a': 1.25, 'b': 2.5}, 4.25),
    ('scalar_double', {'a': 8.5, 'b': 2.25}, 6.5),
    ('scalar_extended', {'a': 1.25, 'b': 2.5}, 3.875),
    ('vector_add', {'a': [1., 2., 3., 4.], 'b': [.5, 1.5, 2.5, 3.5]}, [1.5, 3.5, 5.5, 7.5]),
    ('pair_return', {'value': {'left': 7, 'right': -3}, 'tail': 5}, {'left': 12, 'right': -8}),
    ('mixed_return', {'leading': 7, 'value': {'code': 19, 'value': 2.5, 'fraction': 1.25}, 'tail': -2},
        {'code': 24, 'value': 3., 'fraction': 1.}),
    ('sse_parameters', {'a': 1.25, 'b': 8.5, 'c': 2.25}, 7.5),
    ('register_parameters', {'a': 1, 'b': 2, 'c': 3, 'd': 4}, 18),
    ('stdcall_parameters', {'a': 11, 'b': 4, 'c': 2}, 9),
    ('fastcall_parameters', {'a': 11, 'b': 4, 'c': 2}, 13),
    ('thiscall_parameters', {'object': {'left': 7, 'right': -3}, 'tail': 5}, 9),
]
nondefault = {'vector_add', 'sse_parameters', 'register_parameters', 'stdcall_parameters',
    'fastcall_parameters', 'thiscall_parameters'}
result = {'status': 'RUNNING', 'variant': variant, 'rows': [], 'referenceLimits': []}


def decode(value):
    if value.is_optimized_out:
        return None
    kind = value.type.strip_typedefs()
    if kind.code == gdb.TYPE_CODE_PTR:
        return decode(value.dereference())
    if kind.code == gdb.TYPE_CODE_STRUCT:
        return {field.name: decode(value[field]) for field in kind.fields()}
    if kind.code == gdb.TYPE_CODE_ARRAY:
        low, high = kind.range()
        return [decode(value[index]) for index in range(low, high + 1)]
    if kind.code == gdb.TYPE_CODE_FLT:
        return float(value)
    return int(value)


def memory(address, layout):
    return struct.unpack(layout, bytes(gdb.selected_inferior().read_memory(address, struct.calcsize(layout))))


def reg(name):
    return int(gdb.parse_and_eval('$' + name))


def xmm(index, vector=False):
    return [float(gdb.parse_and_eval(f'$xmm{index}.v4_float[{i}]')) for i in range(4)] if vector else float(
        gdb.parse_and_eval(f'$xmm{index}.v2_double[0]'))


def raw_arguments(name, sp):
    if name == 'vector_add':
        return {'a': xmm(0, True), 'b': xmm(1, True)}
    if name == 'sse_parameters':
        return dict(zip(('a', 'b', 'c'), [xmm(i) for i in range(3)]))
    if name == 'pair_return':
        left, right, tail = memory(sp + 8, '<iii')
        return {'value': {'left': left, 'right': right}, 'tail': tail}
    if name == 'mixed_return':
        leading, code, value, fraction, tail = memory(sp + 8, '<iidfi')
        return {'leading': leading, 'value': {'code': code, 'value': value, 'fraction': fraction}, 'tail': tail}
    if name == 'register_parameters':
        return {'a': reg('eax'), 'b': reg('edx'), 'c': reg('ecx'), 'd': memory(sp + 4, '<i')[0]}
    if name == 'stdcall_parameters':
        return dict(zip(('a', 'b', 'c'), memory(sp + 4, '<iii')))
    if name == 'fastcall_parameters':
        return {'a': reg('ecx'), 'b': reg('edx'), 'c': memory(sp + 4, '<i')[0]}
    if name == 'thiscall_parameters':
        left, right = memory(reg('ecx') & 0xffffffff, '<ii')
        return {'object': {'left': left, 'right': right}, 'tail': memory(sp + 4, '<i')[0]}
    return None


try:
    for command in ('set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set auto-solib-add off'):
        gdb.execute(command)
    gdb.execute('file ' + str(case / ('profile.reference' if variant == 'compiler' else 'profile.input')))
    if variant == 'forge':
        gdb.execute('symbol-file ' + str(case / 'profile.dbg'))
    gdb.execute('starti')
    for name, arguments, returned in expected:
        gdb.Breakpoint('*' + name, temporary=True)
        gdb.execute('continue')
        entry = reg('pc')
        assert entry == int(gdb.parse_and_eval('&' + name))
        if name == failed:
            raw = raw_arguments(name, reg('esp'))
            assert raw == arguments
            for parameter in arguments:
                try:
                    gdb.parse_and_eval(parameter)
                    raise AssertionError('failed function retained a parameter')
                except gdb.error as error:
                    assert 'No symbol' in str(error), str(error)
            return_pc = memory(reg('esp'), '<I')[0]
            assert bytes(gdb.selected_inferior().read_memory(entry, 3)).hex() == '0f58c1'
            gdb.execute('stepi')
            assert reg('pc') == entry + 3 and xmm(0, True) == returned
            gdb.Breakpoint('*' + hex(return_pc), temporary=True)
            gdb.execute('continue')
            assert reg('pc') == return_pc and xmm(0, True) == returned
            result['rows'].append({'function': name, 'symbolOnly': True, 'rawArguments': raw,
                'rawReturned': xmm(0, True), 'entry': entry})
            continue
        actual = {key: decode(gdb.parse_and_eval(key)) for key in arguments}
        row = {'function': name, 'entry': entry, 'arguments': actual, 'rawArguments': raw_arguments(name, reg('esp'))}
        result['rows'].append(row)
        if row['rawArguments'] is not None:
            assert row['rawArguments'] == arguments, row
        if variant == 'compiler' and name == 'mixed_return' and actual['value'] is None:
            assert actual['leading'] == 7 and actual['tail'] == -2
            result['referenceLimits'].append({'function': name, 'kind': 'compiler entry aggregate optimized out',
                'rawArguments': row['rawArguments']})
        else:
            assert actual == arguments, row
        row['listing'] = gdb.execute('list ' + name, to_string=True)
        assert name in row['listing']
        if variant == 'forge' and name in nondefault:
            # The original signature remains usable, while an unsupported injected call
            # must fail before registers or the active frame change.
            expressions = {
                'vector_add': 'vector_add(a,b)', 'sse_parameters': 'sse_parameters(a,b,c)',
                'register_parameters': 'register_parameters(a,b,c,d)',
                'stdcall_parameters': 'stdcall_parameters(a,b,c)',
                'fastcall_parameters': 'fastcall_parameters(a,b,c)',
                'thiscall_parameters': 'thiscall_parameters(object,tail)',
            }
            before = [reg(r) for r in ('pc', 'esp', 'eax', 'ecx', 'edx')] + [int(gdb.parse_and_eval(f'$xmm{i}.v4_int32[{j}]')) for i in range(3) for j in range(4)]
            try:
                gdb.parse_and_eval(expressions[name])
                raise AssertionError('unsupported injected call executed')
            except gdb.error as error:
                row['callRefusal'] = str(error)
                assert 'calling convention' in str(error), row
            after = [reg(r) for r in ('pc', 'esp', 'eax', 'ecx', 'edx')] + [int(gdb.parse_and_eval(f'$xmm{i}.v4_int32[{j}]')) for i in range(3) for j in range(4)]
            assert before == after
        if name in ('vector_add', 'sse_parameters'):
            steps = [('0f58c1', 3)] if name == 'vector_add' else [('f20f58c1', 4), ('f20f5cc2', 4)]
            row['steps'] = []
            for opcode, length in steps:
                pc = reg('pc')
                assert bytes(gdb.selected_inferior().read_memory(pc, length)).hex() == opcode
                gdb.execute('stepi')
                assert reg('pc') == pc + length
                values = {key: decode(gdb.parse_and_eval(key)) for key in arguments}
                row['steps'].append({'offset': reg('pc') - entry, 'values': values})
                if variant == 'forge':
                    assert values['a'] is None, row
                    assert all(values[key] == arguments[key] for key in arguments if key != 'a'), row
            assert bytes(gdb.selected_inferior().read_memory(reg('pc'), 1)) == b'\xc3'
        finish = gdb.FinishBreakpoint(gdb.newest_frame(), internal=True)
        # Capture only the known compiler-vector consumer boundary, so a GDB
        # internal exception is tied to this exact operation and retained.
        # Forge and every other function keep the ordinary strict stderr gate.
        capture_vector = variant == 'compiler' and name == 'vector_add'
        if capture_vector:
            finish.silent = True
            vector_return_pc = memory(reg('esp'), '<I')[0]
            vector_eax = reg('eax') & 0xffffffff
        finish_output = gdb.execute('continue', to_string=True) if capture_vector else gdb.execute('continue')
        row['returned'] = decode(finish.return_value) if finish.return_value is not None else None
        if name == 'vector_add':
            row['rawReturned'] = xmm(0, True)
        elif name == 'sse_parameters':
            row['rawReturned'] = xmm(0)
        elif name in nondefault:
            row['rawReturned'] = reg('eax')
        if 'rawReturned' in row:
            assert row['rawReturned'] == returned, row
        if capture_vector:
            assert reg('pc') == vector_return_pc and reg('eax') & 0xffffffff == vector_eax
            unreadable = False
            if finish_output:
                try:
                    gdb.selected_inferior().read_memory(reg('eax') & 0xffffffff, 16)
                except gdb.MemoryError:
                    unreadable = True
            row['finishDiagnostic'] = diagnostics.vector_finish(variant, name, finish_output,
                row['returned'], row['rawReturned'], returned, reg('eax') & 0xffffffff, unreadable)
        if variant == 'forge' and name in nondefault:
            assert row['returned'] is None, row
        elif variant == 'compiler' and name in ('vector_add', 'sse_parameters') and row['returned'] != returned:
            result['referenceLimits'].append({'function': name, 'kind': 'GDB automatic return mismatch',
                'automatic': row['returned'], 'raw': row['rawReturned'], 'expected': returned})
        else:
            assert row['returned'] == returned, row
    gdb.execute('continue')
    result['exitCode'] = int(gdb.parse_and_eval('$_exitcode'))
    assert result['exitCode'] == 0
    result['status'] = 'PASS'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

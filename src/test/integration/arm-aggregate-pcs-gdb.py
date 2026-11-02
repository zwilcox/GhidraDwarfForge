"""Independent source-known aggregate values and raw AAPCS entry transfers."""
import gdb
import json
import os
from pathlib import Path
import re
import struct

case = Path(os.environ['FORGE_PCS_CASE'])
variant = os.environ['FORGE_PCS_VARIANT']
profile = json.loads((case / 'profile.json').read_text())
order = '>' if profile['order'] == 'big' else '<'
kinds = ['pair', 'float3', 'double2', 'mixed', 'split', 'exhaust']
names = [pcs + '_' + kind for pcs in ('base', 'vfp') for kind in kinds]
result = {'status': 'STARTED', 'variant': variant, 'natural': [], 'injected': []}


def integer(expression):
    return int(gdb.parse_and_eval(expression))


def register(name):
    return gdb.parse_and_eval('$' + name).bytes


def memory(address, length):
    return gdb.selected_inferior().read_memory(address, length).tobytes()


def unpack(kind, data):
    return list(struct.unpack(order + kind, data))


def fields(value, kind):
    if kind in ('split', 'exhaust'):
        return int(value) if kind == 'split' else float(value)
    return [int(value[name]) if kind == 'pair' or (kind == 'mixed' and name == 'a')
        else float(value[name]) for name in ('abc' if kind == 'float3' else 'ab')]


def expected(kind):
    return {'pair': [17, -23], 'float3': [1.25, 2.5, 4.75], 'double2': [1.25, 2.5],
        'mixed': [17, 2.5], 'split': [17, -23], 'exhaust': [1.25, 2.5, 4.75]}[kind]


def expected_return(kind):
    return {'pair': [18, -21], 'float3': [2.25, 3.5, 5.75], 'double2': [2.25, 3.5],
        'mixed': [18, 3.5], 'split': 25, 'exhaust': 36.5}[kind]


def matched(name):
    return name.split('_')[1] in ('pair', 'mixed', 'split') or name.startswith(
        'vfp_' if profile['pcs'] == 'hard' else 'base_')


def raw_entry(name):
    pcs, kind = name.split('_')
    stack = integer('$sp')
    row = {'pc': integer('$pc'), 'sp': stack,
        'core': [register('r' + str(n)).hex() for n in range(4)],
        'vfp': [register('d' + str(n)).hex() for n in range(8)],
        'stack': memory(stack, 64).hex()}
    if kind in ('pair', 'mixed'):
        data = register('r1') + register('r2')
        value = unpack('ii' if kind == 'pair' else 'if', data)
    elif kind == 'float3':
        data = b''.join(register(('s' + str(n)) if pcs == 'vfp' else ('r' + str(n + 1)))
            for n in range(3))
        value = unpack('fff', data)
    elif kind == 'double2':
        data = register('d0') + register('d1') if pcs == 'vfp' else (
            register('r2') + register('r3') + memory(stack, 8))
        value = unpack('dd', data)
    elif kind == 'split':
        assert [integer('$r' + str(n)) for n in range(3)] == [7, 11, 13]
        value = unpack('ii', register('r3') + memory(stack, 4))
    else:
        data = b''.join(register('d' + str(n)) for n in range(7)) if pcs == 'vfp' else (
            b''.join(register('r' + str(n)) for n in range(4)) + memory(stack, 40))
        assert unpack('ddddddd', data) == list(range(1, 8)), (name, row)
        value = unpack('fff', memory(stack if pcs == 'vfp' else stack + 40, 12))
    row['value'] = value
    assert value == expected(kind), (name, row)
    return row


try:
    gdb.execute('target remote ' + os.environ['FORGE_PCS_REMOTE'])
    architecture = gdb.execute('maintenance print architecture', to_string=True)
    selected, = re.findall(r'arm_dump_tdep: fp_model = (\d+)', architecture)
    result['selectedFpModel'] = int(selected)
    assert int(selected) == (4 if profile['pcs'] == 'hard' else 3)
    auxv = gdb.execute('info auxv', to_string=True)
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', auxv)
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = memory(result['vdsoAddress'], 4096).hex()
    for name in names:
        kind = name.split('_')[1]
        entry = gdb.Breakpoint('*' + name)
        gdb.execute('continue')
        entry.delete()
        row = {'name': name, 'entry': raw_entry(name)}
        body = gdb.Breakpoint('*' + name + '_observe')
        gdb.execute('continue')
        body.delete()
        observed = fields(gdb.parse_and_eval('value'),
            'pair' if kind == 'split' else 'float3' if kind == 'exhaust' else kind)
        assert observed == expected(kind), (name, observed)
        row['arguments'] = observed
        if kind in ('split', 'exhaust'):
            convert = int if kind == 'split' else float
            row['leading'] = [convert(gdb.parse_and_eval(p)) for p in
                ('abc' if kind == 'split' else 'abcdefg')]
            assert row['leading'] == ([7, 11, 13] if kind == 'split' else list(range(1, 8)))
        if matched(name):
            row['finish'] = gdb.execute('finish', to_string=True)
            row['return'] = fields(gdb.parse_and_eval('$'), kind)
            assert row['return'] == expected_return(kind), row
        result['natural'].append(row)
    stop = gdb.Breakpoint('marker')
    gdb.execute('continue')
    stop.delete()
    assert integer('calls') == 12
    for pointer in (False, True):
        for name in names:
            if not matched(name):
                continue
            kind = name.split('_')[1]
            argument = {'split': '7,11,13,input_pair', 'exhaust': '1.,2.,3.,4.,5.,6.,7.,input_float3'}.get(
                kind, 'input_' + kind)
            expression = name + ('_pointer' if pointer else '') + '(' + argument + ')'
            count = integer('calls')
            returned = fields(gdb.parse_and_eval(expression), kind)
            global_kind = 'pair' if kind == 'split' else 'float3' if kind == 'exhaust' else kind
            seen = fields(gdb.parse_and_eval('seen_' + global_kind), global_kind)
            row = {'expression': expression, 'return': returned, 'seen': seen}
            result['injected'].append(row)
            assert returned == expected_return(kind) and seen == expected(kind), row
            assert integer('calls') == count + 1
            if kind in ('split', 'exhaust'):
                convert = int if kind == 'split' else float
                row['leading'] = [convert(gdb.parse_and_eval(
                    ('seen_ints' if kind == 'split' else 'seen_doubles') + '[' + str(n) + ']'))
                    for n in range(3 if kind == 'split' else 7)]
                assert row['leading'] == ([7, 11, 13] if kind == 'split' else list(range(1, 8)))
    gdb.execute('continue')
    result['exitCode'] = integer('$_exitcode')
    assert result['exitCode'] == 0
    result['status'] = 'PASS_COMPILER_REFERENCE'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

"""Source-known PCS values, typed returns, injected calls and unchanged-state rejection."""
import gdb
import json
import os
from pathlib import Path
import re

case = Path(os.environ['FORGE_PCS_CASE'])
variant = os.environ['FORGE_PCS_VARIANT']
profile = json.loads((case / 'profile.json').read_text())
names = [pcs + '_' + kind for kind in ('float', 'double', 'wide', 'many') for pcs in ('base', 'vfp')]
result = {'status': 'STARTED', 'variant': variant, 'natural': [], 'injected': []}


def integer(expression):
    return int(gdb.parse_and_eval(expression))


def values(name):
    if name.endswith('wide'):
        return [0x123456789, -0x23456789]
    return list(range(1, 11)) if name.endswith('many') else [1.25, 2.5]


def matched(name):
    return name.endswith('wide') or name.startswith('vfp' if profile['pcs'] == 'hard' else 'base')


def callable_signature(name, pointer=False):
    guarded = variant == 'forge' and profile.get('guardControls', False)
    return matched(name) and not (guarded and (name == 'vfp_float' or (pointer and name == 'vfp_double')))


def state():
    registers = ['pc', 'sp', 'lr'] + ['r' + str(n) for n in range(13)] + ['d' + str(n) for n in range(16)]
    return {'registers': {name: gdb.parse_and_eval('$' + name).bytes.hex() for name in registers},
        'memory': {name: gdb.parse_and_eval(name).bytes.hex() for name in
            ('calls', 'seen_float', 'seen_double', 'seen_wide')}}


try:
    gdb.execute('target remote ' + os.environ['FORGE_PCS_REMOTE'])
    result['auxv'] = gdb.execute('info auxv', to_string=True)
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', result['auxv'])
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = gdb.selected_inferior().read_memory(result['vdsoAddress'], 4096).tobytes().hex()
    for name in names:
        stop = gdb.Breakpoint(name)
        gdb.execute('continue')
        stop.delete()
        expected = values(name)
        parameters = list('abcdefghij') if name.endswith('many') else ['first', 'second']
        convert = int if name.endswith('wide') else float
        observed = [convert(gdb.parse_and_eval(parameter)) for parameter in parameters]
        assert observed == expected, (name, observed, expected)
        row = {'name': name, 'pc': integer('$pc'), 'arguments': observed}
        if callable_signature(name):
            row['finish'] = gdb.execute('finish', to_string=True)
            row['return'] = convert(gdb.parse_and_eval('$'))
            assert row['return'] == sum(expected), row
        result['natural'].append(row)
    stop = gdb.Breakpoint('marker')
    gdb.execute('continue')
    stop.delete()
    assert integer('calls') == 8
    for pointer in (False, True):
        for name in names:
            expected = values(name)
            expression = name + ('_pointer' if pointer else '') + '(' + ','.join(
                str(value) + ('LL' if name.endswith('wide') else '.0' if isinstance(value, int) else '')
                for value in expected) + ')'
            before = state()
            allowed = callable_signature(name, pointer)
            if not allowed and variant == 'compiler':
                continue  # Wrong global PCS is retained in the independent compiler limitation harness.
            if not allowed:
                try:
                    gdb.parse_and_eval(expression)
                    raise AssertionError('unsupported per-function PCS call was accepted: ' + expression)
                except gdb.error as error:
                    assert 'calling convention' in str(error).lower(), str(error)
                    assert before == state(), 'rejected call changed inferior state'
                    result['injected'].append({'expression': expression, 'rejected': str(error), 'unchanged': True})
                continue
            count = integer('calls')
            convert = int if name.endswith('wide') else float
            if os.environ.get('FORGE_PCS_DEBUG_ARM') == '1' and name.endswith('many'):
                gdb.execute('set debug arm 1')
                gdb.execute('set debug remote 1')
            returned = convert(gdb.parse_and_eval(expression))
            if os.environ.get('FORGE_PCS_DEBUG_ARM') == '1' and name.endswith('many'):
                gdb.execute('set debug arm 0')
                gdb.execute('set debug remote 0')
            global_name = 'seen_wide' if name.endswith('wide') else 'seen_float' if name.endswith('float') else 'seen_double'
            seen = [convert(gdb.parse_and_eval(global_name + '[' + str(index) + ']')) for index in range(len(expected))]
            result['injected'].append({'expression': expression, 'return': returned, 'seen': seen})
            assert returned == sum(expected) and integer('calls') == count + 1, (expression, returned, seen)
            assert seen == expected, (expression, seen)
    gdb.execute('continue')
    result['exitCode'] = integer('$_exitcode')
    assert result['exitCode'] == 0
    result['status'] = 'PASS'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

"""Aggregate calls, typed entry values and instruction-level HFA prefixes."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm_aggregate_pcs_oracle import (
    gdb, json, os, re, case, variant, profile, names, result, integer, memory,
    fields, expected, expected_return, matched, raw_entry)


def state():
    registers = ['pc', 'sp', 'lr'] + ['r' + str(n) for n in range(13)] + ['d' + str(n) for n in range(16)]
    objects = ['calls', 'seen_ints', 'seen_doubles'] + [prefix + kind
        for prefix in ('input_', 'seen_') for kind in ('pair', 'float3', 'double2', 'mixed')]
    return {'registers': {name: gdb.parse_and_eval('$' + name).bytes.hex() for name in registers},
        'memory': {name: gdb.parse_and_eval(name).bytes.hex() for name in objects}}


try:
    labels = json.loads((case / 'labels.json').read_text())
    gdb.execute('target remote ' + os.environ['FORGE_PCS_REMOTE'])
    selected, = re.findall(r'arm_dump_tdep: fp_model = (\d+)',
        gdb.execute('maintenance print architecture', to_string=True))
    result['selectedFpModel'] = int(selected)
    assert int(selected) == (4 if profile['pcs'] == 'hard' else 3)
    auxv = gdb.execute('info auxv', to_string=True)
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', auxv)
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = memory(result['vdsoAddress'], 4096).hex()
    for name in names:
        kind = name.split('_')[1]
        stop = gdb.Breakpoint('*' + name)
        gdb.execute('continue')
        stop.delete()
        row = {'name': name, 'entry': raw_entry(name)}
        parameter_kind = 'pair' if kind == 'split' else 'float3' if kind == 'exhaust' else kind
        row['entryParameter'] = fields(gdb.parse_and_eval('value'), parameter_kind)
        assert row['entryParameter'] == expected(kind), row
        if name in ('vfp_float3', 'vfp_double2'):
            row['hfaPrefix'] = []
            entry_pc = integer('$pc')
            target_pc = labels[name + '_observe']
            assert 0 < target_pc - entry_pc < 1024 and (target_pc - entry_pc) % 4 == 0
            for pc in range(entry_pc, target_pc + 1, 4):
                assert integer('$pc') == pc, (name, pc, integer('$pc'))
                observed = fields(gdb.parse_and_eval('value'), kind)
                assert observed == expected(kind), (name, pc, observed)
                row['hfaPrefix'].append({'pc': pc, 'value': observed})
                if pc != target_pc:
                    gdb.execute('stepi', to_string=True)

        # The observation address comes from the independently compiled fixture.
        # It identifies completed capture, without requiring synthetic source to
        # reproduce an original compiler line or inventing a variable location.
        if integer('$pc') != labels[name + '_observe']:
            stop = gdb.Breakpoint('*' + hex(labels[name + '_observe']))
            gdb.execute('continue')
            stop.delete()
        captured_kind = 'pair' if kind == 'split' else 'float3' if kind == 'exhaust' else kind
        row['captured'] = fields(gdb.parse_and_eval('seen_' + captured_kind), captured_kind)
        assert row['captured'] == expected(kind), row
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
            kind = name.split('_')[1]
            argument = {'split': '7,11,13,input_pair', 'exhaust': '1.,2.,3.,4.,5.,6.,7.,input_float3'}.get(
                kind, 'input_' + kind)
            expression = name + ('_pointer' if pointer else '') + '(' + argument + ')'
            if not matched(name):
                before = state()
                try:
                    gdb.parse_and_eval(expression)
                    raise AssertionError('mismatched aggregate PCS call accepted: ' + expression)
                except gdb.error as error:
                    assert 'calling convention' in str(error).lower(), str(error)
                    assert state() == before, 'rejected call changed inferior state'
                    result['injected'].append({'expression': expression, 'rejected': str(error), 'unchanged': True})
                continue
            count = integer('calls')
            returned = fields(gdb.parse_and_eval(expression), kind)
            captured_kind = 'pair' if kind == 'split' else 'float3' if kind == 'exhaust' else kind
            seen = fields(gdb.parse_and_eval('seen_' + captured_kind), captured_kind)
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
    result['status'] = 'PASS_AGGREGATE_CALLS'
    result['scope'] = 'Call classification, raw transfers, captured arguments and typed returns; typed entry values and HFA prefix values; later aggregate lifetimes remain separate'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

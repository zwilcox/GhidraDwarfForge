"""Strict compiler reference at raw entry and post-capture observation labels."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm_aggregate_pcs_oracle import (
    gdb, json, os, re, case, variant, profile, names, result, integer, memory,
    fields, expected, expected_return, matched, raw_entry)

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

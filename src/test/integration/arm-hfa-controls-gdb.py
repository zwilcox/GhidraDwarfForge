"""Exact whole-value gaps after independently known alias/clobber boundaries."""
import gdb
import json
import os
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arm_hfa_control_oracle import GAP_START

case = Path(os.environ['FORGE_PCS_CASE'])
variant = os.environ['FORGE_PCS_VARIANT']
profile = json.loads((case / 'profile.json').read_text())
labels = json.loads((case / 'labels.json').read_text())
control = profile['control']
core = profile['storage'] != 'hfa'
mixed = profile['storage'] == 'mixed'
expected_fields = [0x40c80000 if mixed else 6.25, 7.5]
order = '>' if profile['order'] == 'big' else '<'
result = {'status': 'STARTED', 'variant': variant, 'control': control, 'observations': []}


def integer(expression):
    return int(gdb.parse_and_eval(expression))


def floating(register):
    return struct.unpack(order + 'f', gdb.parse_and_eval('$' + register).bytes)[0]


def word(address):
    return int.from_bytes(gdb.selected_inferior().read_memory(address, 4).tobytes(), profile['order'])


try:
    gdb.execute('target remote ' + os.environ['FORGE_PCS_REMOTE'])
    vdso = re.search(r'AT_SYSINFO_EHDR.*?(0x[0-9a-f]+)', gdb.execute('info auxv', to_string=True))
    if vdso:
        result['vdsoAddress'] = int(vdso[1], 16)
        result['vdsoMemory'] = gdb.selected_inferior().read_memory(result['vdsoAddress'], 4096).tobytes().hex()
    entry = labels['hfa_control']
    stop = gdb.Breakpoint('*' + hex(entry))
    gdb.execute('continue')
    stop.delete()
    entry_stack = integer('$sp')
    second_slot = entry_stack - 12
    destination = integer('$r2' if core else '$r0')
    assert destination == (second_slot if control == 'unknown-alias' else labels['control_guard'])
    assert integer('$r3' if core else '$r1') == 0x12345678
    for offset in range(0, 56, 4):
        assert integer('$pc') == entry + offset
        first_carrier = 's14' if control == 'lower' and offset >= 44 else ('r0' if core else 's0')
        assert floating(first_carrier) == 6.25
        expected_second = 13.75 if offset >= 44 and control not in ('lower', 'neighbor') else 7.5
        assert floating('r1' if core else 's1') == expected_second
        if offset >= 16:
            assert floating('s14') == 6.25
        if offset >= 20:
            assert floating('s15') == (13.75 if offset >= 40 else 7.5)
        if offset >= 44 and control == 'neighbor':
            assert floating('r12' if core else 's2') == 13.75
        row = {'offset': offset, 'firstCarrier': first_carrier, 'first': 6.25, 'secondRegister': expected_second}
        if offset >= 28:
            overwritten = control in ('reuse', 'unknown-alias') and offset >= 36
            row['secondSlotBits'] = word(second_slot)
            assert row['secondSlotBits'] == (0x12345678 if overwritten else 0x40f00000)
        if offset >= 36 and control == 'adjacent':
            assert word(entry_stack - 8) == 0x12345678
        if offset >= 36 and control.startswith('unknown-'):
            assert word(destination) == 0x12345678
        reference = gdb.parse_and_eval('control_input')
        row['typedInput'] = [int(reference['first']) if mixed else float(reference['first']), float(reference['second'])]
        assert row['typedInput'] == expected_fields
        if variant == 'forge' and profile.get('symbolOnly'):
            try:
                gdb.parse_and_eval('value')
            except gdb.error as error:
                assert 'No symbol' in str(error), str(error)
            else:
                raise AssertionError('failed function retained a fabricated formal parameter')
            row['symbolOnly'] = True
        elif variant == 'forge':
            value = gdb.parse_and_eval('value')
            available = GAP_START[control] is None or offset < GAP_START[control]
            assert value.is_optimized_out == (not available), (control, offset, str(value))
            if available:
                row['typed'] = [int(value['first']) if mixed else float(value['first']), float(value['second'])]
                assert row['typed'] == expected_fields, (control, offset, row)
            else:
                row['unavailable'] = True
        result['observations'].append(row)
        gdb.execute('stepi', to_string=True)
    assert not entry <= integer('$pc') < entry + 56
    assert floating('r0' if core else 's0') == (13.75 if control == 'lower' else 6.25)
    gdb.execute('continue')
    assert integer('$_exitcode') == 0
    result['status'] = 'PASS_HFA_CONTROLS'
    result['compilerReference'] = 'Typed immutable caller input and raw ABI/memory; assembly has no compiler parameter DIE'
except BaseException as error:
    result['status'] = 'FAIL'
    result['error'] = repr(error)
    raise
finally:
    (case / (variant + '-gdb.json')).write_text(json.dumps(result, indent=4) + '\n')

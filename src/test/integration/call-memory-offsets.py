"""Calibrate outgoing copies from compiler parameter addresses and actual stores.

Only these source-built x86-64/AArch64 fixture instruction spellings are
accepted. No target memory is changed by the debugger. The resulting first-use
boundary is checked again against Ghidra's independent raw p-code.
"""
import json
import os
import re
from pathlib import Path
import gdb

case = Path(os.environ['LOCAL_CASE'])
target = os.environ['LOCAL_TARGET']
labels = json.loads((case / 'boundaries.json').read_text())
gdb.execute('file ' + str(case / 'local.reference'))
remote = os.environ.get('LOCAL_REMOTE', '')
if remote:
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
    gdb.execute('target remote ' + remote)
offsets, observations, exits = {}, [], []
gdb.events.exited.connect(lambda event: exits.append(getattr(event, 'exit_code', None)))
started = False
for argument in (19, -19, -81985529216486895):
    for shape in ('overlap', 'adjacent', 'released', 'unknown', 'incompatible'):
        name, helper = 'local_call_' + shape, 'inspected_' + shape
        stop = gdb.Breakpoint('*' + name, internal=True)
        gdb.execute('run' if not started and not remote else 'continue')
        started = True
        entry_sp = int(gdb.parse_and_eval('$sp'))
        bias = int(gdb.parse_and_eval('&' + name)) - labels[name]['entry']
        stop.delete()
        stores = []
        for step in range(80):
            pc = int(gdb.parse_and_eval('$pc'))
            if pc == labels[helper]['entry'] + bias:
                break
            assert labels[name]['entry'] <= pc - bias < labels[name]['end']
            instruction, = gdb.selected_frame().architecture().disassemble(pc, count=1)
            assembly = instruction['asm']
            sp = int(gdb.parse_and_eval('$sp'))
            if target == 'x86_64':
                match = re.fullmatch(r'mov\s+%(r\w+),((?:-?0x[0-9a-f]+)?)\(%rsp\)', assembly)
                offset = int(match[2], 0) if match and match[2] else 0
            else:
                match = re.fullmatch(r'str\s+(x\d+), \[sp(?:, #(\d+))?\]', assembly)
                offset = int(match[2]) if match and match[2] else 0
            value = int(gdb.parse_and_eval('(long long)$' + match[1])) if match else None
            gdb.execute('stepi')
            if match:
                address = sp + offset
                data = bytes(gdb.selected_inferior().read_memory(address, 8))
                assert int.from_bytes(data, 'little', signed=True) == value
                stores.append({'pc': pc - bias, 'next': int(gdb.parse_and_eval('$pc')) - bias,
                    'assembly': assembly, 'address': address, 'value': value, 'bytes': data.hex()})
        else:
            raise AssertionError('fixture did not call helper')
        held = int(gdb.parse_and_eval('held'))
        address = int(gdb.parse_and_eval('&held'))
        adjacent = int(gdb.parse_and_eval('&adjacent'))
        assert held == argument + 7 and adjacent == address + 8
        definition, = [store for store in stores if store['address'] == address]
        assert definition['value'] == held
        offset = address - entry_sp
        assert -4096 < offset < 0
        assert name not in offsets or offsets[name] == offset
        offsets[name] = offset
        for field, value in [('definition', definition['pc']), ('ready', definition['next'])]:
            assert field not in labels[name] or labels[name][field] == value
            labels[name][field] = value
        stop = gdb.Breakpoint('*' + hex(labels[helper]['written'] + bias), internal=True)
        gdb.execute('continue')
        stop.delete()
        raw = bytes(gdb.selected_inferior().read_memory(address, 12))
        before = held.to_bytes(8, 'little', signed=True) + (0x11223344).to_bytes(4, 'little')
        expected = bytearray(before)
        if shape in ('overlap', 'adjacent'):
            expected[2 if shape == 'overlap' else 10] = 0
        assert raw == expected, (name, raw.hex(), expected.hex())
        observations.append({'function': name, 'input': argument, 'entrySp': entry_sp,
            'address': address, 'adjacentAddress': adjacent, 'offset': offset, 'value': held,
            'store': definition, 'before': before.hex(), 'after': raw.hex()})
gdb.execute('continue')
assert exits == [0] and len(observations) == 15
(case / 'boundaries.json').write_text(json.dumps(labels, indent=4) + '\n')
(case / 'stack-offsets.json').write_text(json.dumps({'status': 'PASS', 'functions': offsets,
    'observations': observations, 'exitCodes': exits}, indent=4) + '\n')
print('stack-call-offsets=PASS')

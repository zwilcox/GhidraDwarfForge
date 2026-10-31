"""Compiler-correlated storage and instruction-boundary lexical lookup."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_LEXICAL_CASE'])
mode = os.environ['FORGE_LEXICAL_MODE']
labels = json.loads((case / 'labels.json').read_text())
remote = os.environ.get('FORGE_LEXICAL_REMOTE', '')
exits = []
gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
gdb.execute('ptype scoped')
if mode != 'failed':
    gdb.execute('list scoped')
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*scoped', temporary=True)
gdb.execute('continue' if remote else 'run')
bias = int(gdb.parse_and_eval('$pc')) - labels['scoped']
entry_stack = int(gdb.parse_and_eval('$sp'))


def stop(name):
    address = labels[name] + bias
    gdb.Breakpoint('*' + hex(address), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == address


if mode == 'compiler':
    storage = {}
    for block, expected in [('outer', 11), ('inner', 23)]:
        stop(block + '_live')
        value = gdb.parse_and_eval('shadow')
        assert int(value) == expected
        storage[block] = int(value.address) - entry_stack
    if 'inner_gap_begin' in labels:
        stop('inner_gap_begin')
        assert int(gdb.parse_and_eval('shadow')) == 23
        stop('inner_gap_end')
        assert int(gdb.parse_and_eval('shadow')) == 23
    stop('inner_end')
    assert int(gdb.parse_and_eval('shadow')) == 11
    assert storage['outer'] != storage['inner']
    (case / 'compiler-storage.json').write_text(json.dumps(storage, indent=4) + '\n')
elif mode == 'failed':
    for marker in ['outer_live', 'inner_live', 'inner_end']:
        stop(marker)
        try:
            gdb.parse_and_eval('shadow')
        except gdb.error as error:
            assert 'No symbol "shadow" in current context.' in str(error)
        else:
            raise AssertionError('failed function retained a lexical variable')
    assert 'scoped' in gdb.execute('info functions scoped', to_string=True)
elif mode in ('stale', 'coalesced', 'previous'):
    observations = []
    for marker in ['outer_live', 'inner_begin', 'inner_live', 'inner_end']:
        stop(marker)
        if mode in ('stale', 'previous'):
            outer = gdb.parse_and_eval('shadow')
            assert int(outer) == 11 and outer.type.sizeof == 4
            inner = gdb.parse_and_eval('stale_shadow' if mode == 'stale' else 'shadow_1')
            if marker in ('outer_live', 'inner_begin'):
                assert inner.is_optimized_out
            else:
                assert int(inner) == 23
            observations.append({'marker': marker, 'outer': str(outer), 'inner': str(inner)})
        else:
            value = gdb.parse_and_eval('merged')
            assert value.is_optimized_out, 'invalid register definition acquired a location'
            try:
                gdb.parse_and_eval('shadow')
            except gdb.error as error:
                assert 'No symbol "shadow" in current context.' in str(error)
            else:
                raise AssertionError('coalesced binding incorrectly emitted a shadowed object')
            observations.append({'marker': marker, 'merged': str(value), 'shadow': 'absent'})
    (case / (mode + '-observations.json')).write_text(json.dumps(observations, indent=4) + '\n')
else:
    prepared = json.loads((case / 'prepared.json').read_text())
    observations = []
    for instruction in prepared['instructions']:
        address = instruction['address']
        pc = int(gdb.parse_and_eval('$pc'))
        assert pc == address + bias, (hex(pc), instruction)
        raw = bytes(gdb.selected_inferior().read_memory(pc, len(bytes.fromhex(instruction['bytes']))))
        assert raw.hex() == instruction['bytes']
        visible = labels['outer_begin'] <= address < labels['outer_end']
        inner = labels['inner_begin'] <= address < labels['inner_end']
        if 'inner_gap_begin' in labels and labels['inner_gap_begin'] <= address < labels['inner_gap_end']:
            inner = False
        available = visible and address >= labels['inner_live' if inner else 'outer_live']
        try:
            value = gdb.parse_and_eval('shadow')
        except gdb.error as error:
            assert not visible and 'No symbol "shadow" in current context.' in str(error), (hex(pc), str(error))
            state = 'out-of-scope'
        else:
            assert visible, (hex(pc), 'scope leaked', str(value))
            assert value.type.strip_typedefs().code == gdb.TYPE_CODE_INT and value.type.sizeof == 4
            assert value.is_optimized_out != available, (hex(pc), str(value), available)
            if available:
                assert int(value) == (23 if inner else 11), (hex(pc), str(value), inner)
                storage = json.loads((case / 'compiler-storage.json').read_text())
                raw_value = int.from_bytes(gdb.selected_inferior().read_memory(
                    entry_stack + storage['inner' if inner else 'outer'], 4), 'little', signed=True)
                assert raw_value == int(value)
            state = str(value)
        observations.append({'address': address, 'inner': inner, 'value': state})
        if instruction == prepared['instructions'][-1]:
            break
        gdb.execute('stepi')
    assert any(r['inner'] and r['value'] == '<optimized out>' for r in observations)
    assert any(r['value'] == '11' for r in observations) and any(r['value'] == '23' for r in observations)
    assert any(r['value'] == 'out-of-scope' for r in observations)
    if 'inner_gap_begin' in labels:
        gap = next(r for r in observations if r['address'] == labels['inner_gap_begin'])
        after = next(r for r in observations if r['address'] == labels['inner_gap_end'])
        assert gap['value'] == '11' and after['value'] == '23', (gap, after)
    (case / (mode + '-observations.json')).write_text(json.dumps(observations, indent=4) + '\n')
gdb.execute('continue')
assert gdb.selected_inferior().pid == 0
assert exits == [0], exits
print('lexical-shadow-gdb=' + mode + ' PASS')

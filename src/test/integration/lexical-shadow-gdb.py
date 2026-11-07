"""Compiler-correlated storage and instruction-boundary lexical lookup."""
import json
import os
from pathlib import Path
import gdb

case = Path(os.environ['FORGE_LEXICAL_CASE'])
mode = os.environ['FORGE_LEXICAL_MODE']
labels = json.loads((case / 'labels.json').read_text())
remote = os.environ.get('FORGE_LEXICAL_REMOTE', '')
source_files = {}
if mode == 'forge' and os.environ.get('FORGE_LEXICAL_SYMBOLS'):
    source = Path(os.environ['FORGE_LEXICAL_SYMBOLS'] + '.c')
    manifests = [line.removeprefix(' * Manifest: ') for line in source.read_text().splitlines()
        if line.startswith(' * Manifest: ')]
    if manifests:
        assert len(manifests) == 1
        manifest = json.loads((source.parent / manifests[0]).read_text())
        wanted = ['scoped'] + (['lexical_leaf'] if 'lexical_leaf' in labels else [])
        for name in wanted:
            function, = [f for f in manifest['functions'] if f['name'] == name]
            part = manifest['parts'][function['file'] - 1]
            source_files[name] = source.parent / part['name']
            qualified = part['name'] + ':' + name
            assert name in gdb.execute('list ' + qualified, to_string=True)
            breakpoint = gdb.Breakpoint(qualified)
            assert not breakpoint.pending and breakpoint.locations
            breakpoint.delete()
        assert len(set(source_files.values())) == len(wanted), 'fixture functions share a source part'
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
if source_files:
    assert Path(gdb.selected_frame().find_sal().symtab.fullname()) == source_files['scoped']


def stop(name):
    address = labels[name] + bias
    gdb.Breakpoint('*' + hex(address), temporary=True)
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$pc')) == address


call_observations = []


def trace_callee(block):
    expected = 11 if block == 'outer' else 23
    for step in range(40):
        pc = int(gdb.parse_and_eval('$pc'))
        address = pc - bias
        assert labels['lexical_leaf'] <= address < labels['leaf_end']
        decoded, = gdb.selected_frame().architecture().disassemble(pc, count=1)
        raw = bytes(gdb.selected_inferior().read_memory(pc, decoded['length'])).hex()
        caller = gdb.newest_frame().older()
        assert caller is not None and caller.name() == 'scoped'
        if source_files:
            assert Path(gdb.newest_frame().find_sal().symtab.fullname()) == source_files['lexical_leaf']
            assert Path(caller.find_sal().symtab.fullname()) == source_files['scoped']
        value = caller.read_var('shadow')
        assert not value.is_optimized_out and value.type.sizeof == 4 and int(value) == expected
        if mode == 'forge':
            saved, = [i for i in prepared['calleeInstructions'] if i['address'] == address]
            assert saved['bytes'] == raw and saved['next'] == address + decoded['length']
        call_observations.append({'block': block, 'address': address, 'bytes': raw, 'callerValue': int(value)})
        gdb.execute('stepi')
        if int(gdb.parse_and_eval('$pc')) == labels[block + '_returned'] + bias:
            break
    else:
        raise AssertionError('callee did not return')


if mode == 'compiler':
    storage = {}
    for block, expected in [('outer', 11), ('inner', 23)]:
        stop(block + '_live')
        value = gdb.parse_and_eval('shadow')
        assert int(value) == expected
        storage[block] = int(value.address) - entry_stack
        if 'lexical_leaf' in labels:
            stop(block + '_call')
            for step in range(10):
                gdb.execute('stepi')
                if int(gdb.parse_and_eval('$pc')) == labels['lexical_leaf'] + bias:
                    break
            else:
                raise AssertionError('call marker did not reach helper')
            trace_callee(block)
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
        if instruction.get('call'):
            trace_callee('inner' if inner else 'outer')
    assert any(r['inner'] and r['value'] == '<optimized out>' for r in observations)
    assert any(r['value'] == '11' for r in observations) and any(r['value'] == '23' for r in observations)
    assert any(r['value'] == 'out-of-scope' for r in observations)
    if 'inner_gap_begin' in labels:
        gap = next(r for r in observations if r['address'] == labels['inner_gap_begin'])
        after = next(r for r in observations if r['address'] == labels['inner_gap_end'])
        assert gap['value'] == '11' and after['value'] == '23', (gap, after)
    (case / (mode + '-observations.json')).write_text(json.dumps(observations, indent=4) + '\n')
if mode in ('compiler', 'forge') and 'lexical_leaf' in labels:
    assert {row['block'] for row in call_observations} == {'outer', 'inner'}
    (case / (mode + '-calls.json')).write_text(json.dumps(call_observations, indent=4) + '\n')
gdb.execute('continue')
assert gdb.selected_inferior().pid == 0
assert exits == [0], exits
print('lexical-shadow-gdb=' + mode + ' PASS')

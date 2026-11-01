"""Compare original scalar arguments with the analyst aggregate at every instruction."""
import json
import os
from pathlib import Path
from collections import Counter

import gdb

case = Path(os.environ['LOCAL_CASE'])
variant, target = os.environ['LOCAL_VARIANT'], os.environ['LOCAL_TARGET']
remote = os.environ.get('LOCAL_REMOTE', '')
compiler = variant == 'compiler'
labels = json.loads((case / 'labels.json').read_text())
storage = {} if compiler else json.loads((case / 'compiler-storage.json').read_text())
locations = json.loads((case / 'locations.json').read_text()) if variant == 'forge' else {}
prepared = {} if compiler else json.loads((case / 'prepared.json').read_text())
expected = [labels['first'], labels['second']]
mask = (1 << 64) - 1
if target == 'aarch64':
    gdb.execute('set sysroot /usr/aarch64-linux-gnu')
binary = case / ('local.reference' if compiler else 'local.input')
symbols = binary if compiler else case / ('local.dbg' if variant == 'forge' else 'previous.dbg')
gdb.execute('file "' + str(binary) + '"')
gdb.execute('symbol-file "' + str(symbols) + '"')
for name in [*labels['order'], 'navigation_control']:
    assert int(gdb.parse_and_eval('&' + name)) == labels['functions'][name]['entry']
    assert 'void (' in gdb.execute('ptype ' + name, to_string=True)
    gdb.execute('list ' + name)
if remote:
    gdb.execute('target remote ' + remote)


def number(expression):
    return int(gdb.parse_and_eval(expression))


def register(number):
    if target == 'aarch64':
        assert 0 <= number <= 31
        return 'sp' if number == 31 else 'x' + str(number)
    names = ['rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
    assert 0 <= number < len(names)
    return names[number]


def memory(address):
    return int.from_bytes(gdb.selected_inferior().read_memory(address, 8), 'little')


points, returns = [], []
started = False
invocations = Counter()
for name in labels['order']:
    row = labels['functions'][name]
    invocation = invocations[name]
    invocations[name] += 1
    mixed = name.endswith('mixed')
    alias = 'alias' in name
    gdb.Breakpoint('*' + name, temporary=True)
    gdb.execute('continue' if started or remote else 'run')
    started = True
    entry = number('&' + name)
    bias = entry - row['entry']
    assert number('$pc') == entry
    entry_stack = number('$sp')
    assert number('$rdi' if target == 'x86_64' else '$x0') & mask == expected[0]
    if compiler:
        for parameter, wanted in zip(('first', 'second'), expected):
            value = gdb.selected_frame().read_var(parameter)
            assert not value.is_optimized_out and int(value) == wanted, (name, parameter, str(value))
        storage[name] = {}
        if mixed:
            offset = number('&second') - entry_stack
            assert offset == (8 if target == 'x86_64' else 0), (name, offset)
            assert memory(entry_stack + offset) == expected[1]
            storage[name]['incomingSecond'] = offset
    visited = []
    visits = Counter()
    calls = 0
    boundary = row['returned'] if name in ('pieces_volatile_call', 'pieces_memory_unknown') else row['alias_done'] if alias else row['lost']
    if name in ('pieces_memory_registers', 'pieces_memory_mixed'):
        if labels['redZone']:
            boundary = row['restored']
        elif labels['framePointerLeaf']:
            boundary = row['slot_changed']
    for step in range(256):
        address = number('$pc') - bias
        assert row['entry'] <= address < row['end'], (name, hex(address))
        if name == 'pieces_split':
            assert not row['hole'] <= address < row['afterhole']
        visits[address] += 1
        visited.append(address)
        instruction, = gdb.selected_inferior().architecture().disassemble(address + bias, count=1)
        raw = bytes(gdb.selected_inferior().read_memory(address + bias, instruction['length'])).hex()
        if compiler and address == row['before']:
            for variable in ('first_slot', 'second_slot'):
                offset = number('&' + variable) - entry_stack
                assert -4096 < offset < 4096
                storage[name][variable] = offset
        record = {'function': name, 'linkPc': address, 'pc': address + bias, 'bytes': raw,
            'stackDelta': number('$sp') - entry_stack, 'visit': visits[address], 'invocation': invocation}
        if address >= row['before']:
            wanted_a = 0x7777777777777777 if address < row['first_saved'] else expected[0]
            if address >= row['slot_changed']:
                wanted_a ^= labels['changedMask']
            wanted_b = 0x5555555555555555 if address < row['second_saved'] else expected[1]
            slot_values = [memory(entry_stack + storage[name][key]) for key in ('first_slot', 'second_slot')]
            assert slot_values == [wanted_a, wanted_b], (name, hex(address), slot_values)
            record['slots'] = slot_values
            if compiler and address in [row[key] for key in ('before', 'first_saved', 'second_saved', 'slot_changed', 'stale')]:
                assert [number(key) for key in ('first_slot', 'second_slot')] == slot_values
        if not compiler:
            saved, = [item for item in prepared[name + '_instructions'] if item['address'] == address]
            assert saved['bytes'] == raw and saved['next'] == address + instruction['length']
            value = gdb.selected_frame().read_var('value')
            assert value.type.sizeof == 16 and value.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT
            available = not value.is_optimized_out
            record['available'] = available
            if variant == 'forge':
                matches = [item for item in locations[name] if item['start'] <= address < item['end']]
                assert len(matches) == int(available) and available == (address < boundary), (name, hex(address), str(value))
                if available:
                    physical = []
                    for index, piece in enumerate(matches[0]['pieces']):
                        value_at = number('$' + register(piece['register']))
                        if piece['kind'] == 'stack':
                            value_at += piece['offset']
                            permitted = [storage[name]['first_slot']] if index == 0 else [storage[name]['second_slot']]
                            if mixed and index == 1:
                                permitted.append(storage[name]['incomingSecond'])
                            # Prologue observations precede the live stack-local declarations,
                            # but the compiler oracle records their eventual entry offsets.
                            assert value_at - entry_stack in permitted, (name, hex(address), piece, value_at - entry_stack)
                            value_at = memory(value_at)
                        physical.append(value_at & mask)
                    assert physical == expected, (name, hex(address), physical)
                    record['physicalPieces'] = physical
            if available:
                fields = [value[field] for field in ('first', 'second')]
                assert all(not field.is_optimized_out and field.type.sizeof == 8 for field in fields)
                assert [int(field) for field in fields] == expected, (name, hex(address), str(value))
                record['fields'] = [int(field) for field in fields]
            record['value'] = str(value)
        if name == 'pieces_memory_unknown' and address == row['returned']:
            retained = number('$r12' if target == 'x86_64' else '$x20') & mask
            assert retained == expected[1]
            assert record['slots'] == expected
            record['survivingSecond'] = retained
            if variant == 'forge':
                assert not record['available']
        if labels['redZone'] and name == 'pieces_memory_mixed' and address == row['restored']:
            retained = memory(entry_stack + storage[name]['incomingSecond'])
            assert retained == expected[1]
            record['survivingSecond'] = retained
            if variant == 'forge':
                assert not record['available']
        if address == row['stale']:
            stale = number(('$rbx' if target == 'x86_64' else '$x19') if name == 'pieces_call' else ('$r10' if target == 'x86_64' else '$x9')) & mask
            retained = number(('$r12' if target == 'x86_64' else '$x20') if name == 'pieces_call' else ('$r11' if target == 'x86_64' else '$x10')) & mask
            assert stale == (expected[0] ^ labels['changedMask']) and retained == expected[1]
            record.update(staleFirst=stale, survivingSecond=retained)
            if variant == 'forge':
                assert not record['available']
        points.append(record)
        if instruction['asm'].startswith('ret'):
            assert number('effect_sink') == ((expected[0] ^ labels['changedMask']) ^ expected[1])
            returns.append(name)
            break
        if instruction['asm'].split()[0] in ('call', 'callq', 'bl'):
            assert name in ('pieces_call', 'pieces_volatile_call', 'pieces_memory_registers', 'pieces_memory_mixed', 'pieces_memory_unknown')
            calls += 1
            trace = []
            leaf_name = ('pieces_memory_alias' if name == 'pieces_memory_unknown' else
                'pieces_memory_leaf' if name in ('pieces_memory_registers', 'pieces_memory_mixed') else 'pieces_leaf')
            leaf = labels['functions'][leaf_name]
            gdb.execute('stepi')
            for leaf_step in range(16):
                leaf_address = number('$pc') - bias
                assert leaf['entry'] <= leaf_address < leaf['end']
                leaf_instruction, = gdb.selected_inferior().architecture().disassemble(number('$pc'), count=1)
                leaf_bytes = bytes(gdb.selected_inferior().read_memory(number('$pc'), leaf_instruction['length'])).hex()
                if not compiler:
                    saved, = [item for item in prepared[leaf_name + '_instructions'] if item['address'] == leaf_address]
                    assert saved['bytes'] == leaf_bytes and saved['next'] == leaf_address + leaf_instruction['length']
                trace.append({'address': leaf_address, 'bytes': leaf_bytes})
                gdb.execute('stepi')
                if leaf_instruction['asm'].startswith('ret'):
                    break
            else:
                raise AssertionError('callee did not return')
            assert number('$pc') - bias == address + instruction['length']
            record['callee'] = trace
        else:
            gdb.execute('stepi')
    else:
        raise AssertionError('instruction bound exceeded')
    assert {row[key] for key in ('entry', 'before', 'first_memory', 'second_memory', 'first_loaded', 'second_loaded', 'lost', 'stale')} <= set(visited)
    assert calls == int(name in ('pieces_call', 'pieces_volatile_call', 'pieces_memory_registers', 'pieces_memory_mixed', 'pieces_memory_unknown'))
    if name == 'pieces_branch':
        assert visits[row['left']] == int(invocation == 0) and visits[row['right']] == int(invocation == 1)
    if name == 'pieces_loop':
        assert visits[row['loop']] == invocation + 2
    if not compiler:
        body_addresses = [item['address'] for item in prepared[name + '_instructions']]
        if name == 'pieces_branch':
            assert set(visited) <= set(body_addresses)
        elif name == 'pieces_loop':
            assert set(visited) == set(body_addresses)
        else:
            assert visited == body_addresses

gdb.Breakpoint('*navigation_control', temporary=True)
gdb.execute('continue')
assert number('$pc') == number('&navigation_control')
for command in ('next', 'step'):
    gdb.execute(command)
gdb.execute('continue')
assert number('$_exitcode') == 0
if compiler:
    (case / 'compiler-storage.json').write_text(json.dumps(storage, indent=4) + '\n')
(case / (variant + '-gdb.json')).write_text(json.dumps({'status': 'PASS', 'points': points,
    'returns': returns, 'navigation': ['next', 'step'], 'exitCode': 0}, indent=4) + '\n')
print('composite-value-flow-gdb=' + variant + ' PASS')

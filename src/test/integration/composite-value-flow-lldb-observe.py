"""Compare LLDB observations with retained independent compiler/GDB execution."""
import json
import os
from pathlib import Path
import lldb


config = json.loads(Path(os.environ['FORGE_LLDB_FLOW_CONFIG']).read_text())
case = Path(config['case'])
labels = json.loads((case / 'labels.json').read_text())
reference = json.loads((case / 'compiler-gdb.json').read_text())
forge_reference = json.loads((case / 'forge-gdb.json').read_text())
storage = json.loads((case / 'compiler-storage.json').read_text())
locations = json.loads((case / 'locations.json').read_text())
assert reference['status'] == forge_reference['status'] == 'PASS'
assert len(reference['points']) == len(forge_reference['points'])
lldb.debugger.SetAsync(False)
target = lldb.debugger.GetSelectedTarget()
process = target.GetProcess()
observations = []


def number(value):
    assert value.IsValid(), 'missing value'
    error = lldb.SBError()
    result = value.GetValueAsUnsigned(error)
    assert error.Success(), (value.GetName(), str(error), str(value.GetError()))
    return result


def memory(address, size):
    error = lldb.SBError()
    result = process.ReadMemory(address, size, error)
    assert error.Success() and len(result) == size, (hex(address), size, str(error))
    return result


def register(frame, dwarf_number):
    if config['target'] == 'aarch64':
        assert 0 <= dwarf_number <= 31
        name = 'sp' if dwarf_number == 31 else 'x' + str(dwarf_number)
    else:
        names = ['rax', 'rdx', 'rcx', 'rbx', 'rsi', 'rdi', 'rbp', 'rsp',
            'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']
        name = names[dwarf_number]
    return number(frame.FindRegister(name))


def frame_at(address):
    assert process.GetState() == lldb.eStateStopped
    frame = process.GetSelectedThread().GetFrameAtIndex(0)
    assert frame.GetPC() == address, (hex(frame.GetPC()), hex(address))
    return frame


def observe():
    cursor = 0
    for invocation, name in enumerate(labels['order']):
        entry = labels['functions'][name]['entry']
        address = target.ResolveFileAddress(entry)
        assert address.IsValid()
        runtime_entry = address.GetLoadAddress(target)
        if invocation:
            breakpoint = target.BreakpointCreateBySBAddress(address)
            assert breakpoint.IsValid() and breakpoint.GetNumLocations() == 1
            breakpoint.SetOneShot(True)
            assert process.Continue().Success()
        frame = frame_at(runtime_entry)
        bias, entry_stack = runtime_entry - entry, frame.GetSP()
        if config['mode'] == 'compiler':
            assert [number(frame.FindVariable(field)) for field in ('first', 'second')] == [labels['first'], labels['second']]
        for step in range(256):
            expected = reference['points'][cursor]
            expected_forge = forge_reference['points'][cursor]
            assert expected['function'] == expected_forge['function'] == name
            assert expected['linkPc'] == expected_forge['linkPc']
            pc = expected['linkPc'] + bias
            frame = frame_at(pc)
            assert frame.GetSP() - entry_stack == expected['stackDelta']
            instruction_bytes = memory(pc, len(bytes.fromhex(expected['bytes']))).hex()
            assert instruction_bytes == expected['bytes']
            row = {key: expected[key] for key in ('function', 'linkPc', 'bytes', 'stackDelta', 'visit', 'invocation')}
            if 'slots' in expected:
                row['slots'] = [int.from_bytes(memory(entry_stack + storage[name][field], 8), 'little')
                    for field in ('first_slot', 'second_slot')]
                assert row['slots'] == expected['slots']
            if config['mode'] == 'forge':
                value = frame.FindVariable('value')
                assert value.IsValid() and value.GetByteSize() == 16, (name, hex(pc), str(value))
                dtype = value.GetType().GetCanonicalType()
                assert dtype.GetNumberOfFields() == 2
                available = expected_forge['available']
                matches = [item for item in locations[name] if item['start'] <= expected['linkPc'] < item['end']]
                assert len(matches) == int(available)
                row['available'] = available
                if available:
                    values = [number(value.GetChildMemberWithName(field)) for field in ('first', 'second')]
                    assert values == expected_forge['fields'] == [labels['first'], labels['second']], (name, hex(pc), values)
                    physical = []
                    for piece in matches[0]['pieces']:
                        carrier = register(frame, piece['register'])
                        if piece['kind'] == 'stack':
                            carrier = int.from_bytes(memory(carrier + piece['offset'], 8), 'little')
                        physical.append(carrier)
                    assert physical == values == expected_forge['physicalPieces']
                    row.update(fields=values, physicalPieces=physical)
                else:
                    assert value.GetError().Fail(), (name, hex(pc), str(value))
                    for field in ('first', 'second'):
                        child = value.GetChildMemberWithName(field)
                        error = lldb.SBError()
                        child.GetValueAsUnsigned(error)
                        assert error.Fail(), (name, hex(pc), field, str(child))
                    row['unavailable'] = str(value.GetError())
            observations.append(row)
            cursor += 1
            instruction = target.ReadInstructions(frame.GetPCAddress(), 1).GetInstructionAtIndex(0)
            assert instruction.IsValid() and instruction.GetByteSize() == len(bytes.fromhex(expected['bytes']))
            if instruction.GetMnemonic(target).startswith('ret'):
                assert number(target.FindFirstGlobalVariable('effect_sink')) == ((labels['first'] ^ labels['changedMask']) ^ labels['second'])
                break
            if 'callee' in expected:
                process.GetSelectedThread().StepInstruction(False)
                for leaf in expected['callee']:
                    frame_at(leaf['address'] + bias)
                    assert memory(leaf['address'] + bias, len(bytes.fromhex(leaf['bytes']))).hex() == leaf['bytes']
                    process.GetSelectedThread().StepInstruction(False)
                frame_at(pc + instruction.GetByteSize())
                row['callee'] = expected['callee']
            else:
                process.GetSelectedThread().StepInstruction(False)
        else:
            raise AssertionError('function instruction limit exceeded')
    assert cursor == len(reference['points'])
    assert process.Continue().Success()
    assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0


try:
    observe()
finally:
    Path(config['observations']).write_text(json.dumps(observations, indent=4) + '\n')
print('FORGE_LLDB_FLOW_PASS', len(observations))

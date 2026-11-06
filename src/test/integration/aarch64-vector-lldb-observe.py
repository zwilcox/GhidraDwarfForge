"""Inspect vector lane display, raw carriers, exact lifetime gaps and returns."""
import json
import os
from pathlib import Path
import struct
import lldb

config = json.loads(Path(os.environ['FORGE_LLDB_VECTOR_CONFIG']).read_text())
case = Path(config['case'])
metadata = json.loads((case / 'metadata.json').read_text())
locations = json.loads((case / 'vector-locations.json').read_text())
returns = json.loads((case / (config['mode'] + '-returns.json')).read_text())
expected = {
    'vector_plain': [11, -22, 33, -44],
    'vector_copy': [101, -202, 303, -404],
    'vector_stack': [501, -602, 703, -804],
    'vector_alias': [1501, -1602, 1703, -1804],
    'vector_float': [1.25, -2.5, 3.75, -4.0],
    'vector_stack_arg': [901, -902, 903, -904],
}
lldb.debugger.SetAsync(False)
target = lldb.debugger.GetSelectedTarget()
process = target.GetProcess()
observations = []


def owner(name):
    thread = process.GetSelectedThread()
    frame = thread.GetFrameAtIndex(0)
    for index in range(thread.GetNumFrames()):
        candidate = thread.GetFrameAtIndex(index)
        if candidate.GetFunctionName() == name and not candidate.IsInlined():
            # Inline parents expose the call-site PC. Read the machine PC from
            # frame zero, but resolve the parameter in its owning lexical scope.
            assert candidate.GetCFA() == frame.GetCFA() and candidate.GetSP() == frame.GetSP()
            return candidate
    raise AssertionError('missing owning frame ' + name)


def register(frame, number):
    value = frame.FindRegister('v' + str(number - 64))
    assert value.IsValid() and value.GetByteSize() == 16
    data, error = value.GetData(), lldb.SBError()
    result = bytearray()
    for index in range(16):
        result.append(data.GetUnsignedInt8(error, index))
        assert error.Success(), str(error)
    return bytes(result)


def lanes(value, floating, unavailable):
    assert value.IsValid() and value.GetByteSize() == 16 and value.GetNumChildren() == 4, str(value)
    result = []
    for index in range(4):
        child = value.GetChildAtIndex(index)
        assert child.IsValid() and child.GetByteSize() == 4
        text = child.GetValue()
        if unavailable:
            assert text is None and child.GetError().Fail(), str(child)
            result.append(None)
        else:
            assert text is not None and child.GetError().Success(), str(child)
            error = lldb.SBError()
            data = child.GetData()
            raw = data.GetFloat(error, 0) if floating else data.GetSignedInt32(error, 0)
            assert error.Success(), str(error)
            shown = float(text) if floating else int(text, 0)
            assert shown == raw, (text, raw)
            result.append(shown)
    return result


def observe():
    for index, (name, wanted) in enumerate(expected.items()):
        if index:
            assert process.Continue().Success()
        assert process.GetState() == lldb.eStateStopped
        frame = owner(name)
        entry = frame.GetPC()
        assert frame.GetFunction().GetStartAddress().GetLoadAddress(target) == entry
        bias = entry - metadata['symbols'][name]
        assert (bias == 0) == (metadata['role'] == 'exec')
        entry_stack = frame.GetSP()
        zero_carriers = 0
        for step in range(200):
            frame = owner(name)
            machine_frame = process.GetSelectedThread().GetFrameAtIndex(0)
            offset = machine_frame.GetPC() - entry
            raw = [item for item in locations[name]['intervals'] if item['start'] <= offset < item['end']]
            assert len(raw) <= 1
            missing = config['mode'] == 'forge' and not raw
            actual = lanes(frame.FindVariable('value'), name == 'vector_float', missing)
            assert actual == ([None] * 4 if missing else wanted), (name, offset, actual)
            row = {'name': name, 'offset': offset, 'linkPc': machine_frame.GetPC() - bias, 'lanes': actual}
            if config['mode'] == 'forge':
                line = frame.GetLineEntry()
                assert line.IsValid() and line.GetLine() > 0
                assert Path(line.GetFileSpec().fullpath).resolve() == case / 'abi.dbg.c'
                if raw:
                    location = raw[0]
                    if location['kind'] == 'register':
                        data = register(frame, location['register'])
                    else:
                        assert location['register'] == 31
                        address = frame.GetSP() + location['displacement']
                        error = lldb.SBError()
                        data = process.ReadMemory(address, 16, error)
                        assert error.Success() and len(data) == 16
                        if name == 'vector_stack_arg':
                            assert address == entry_stack
                        row['memoryAddress'] = address
                    decoded = list(struct.unpack('<4f' if name == 'vector_float' else '<4i', data))
                    assert decoded == wanted, (name, offset, location, decoded)
                    row['rawLocation'], row['rawLanes'] = location, decoded
            if name in ('vector_stack', 'vector_alias') and all(register(frame, number) == bytes(16) for number in range(64, 96)):
                zero_carriers += 1
                if config['mode'] == 'forge':
                    assert (bool(raw) and raw[0]['kind'] == 'memory') == (name == 'vector_stack')
            observations.append(row)
            instruction = target.ReadInstructions(machine_frame.GetPCAddress(), 1).GetInstructionAtIndex(0)
            assert instruction.IsValid()
            if instruction.GetMnemonic(target) == 'ret':
                decoded = list(struct.unpack('<4f' if name == 'vector_float' else '<4i', register(frame, 64)))
                assert decoded == returns[name]['rawLanes']
                if config['mode'] == 'forge' and name == 'vector_stack':
                    assert raw and raw[0]['kind'] == 'register'
                row['returnLanes'] = decoded
                break
            process.GetSelectedThread().StepInstruction(False)
            assert process.GetState() == lldb.eStateStopped
        else:
            raise AssertionError('no terminal return ' + name)
        if name in ('vector_stack', 'vector_alias'):
            assert zero_carriers > 0
    assert process.Continue().Success()
    assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0


def transport_control():
    assert process.GetState() == lldb.eStateStopped
    frame = owner('vector_plain')
    assert frame.GetPC() == frame.GetFunction().GetStartAddress().GetLoadAddress(target)
    value = frame.FindVariable('value')
    assert value.IsValid() and value.GetByteSize() == 16
    assert value.GetValue() is None and value.GetError().Fail()
    message = str(value.GetError())
    assert message == 'error: Unable to convert register kind=1 reg_num=64 to a native register number.', message
    assert not frame.FindRegister('v0').IsValid()
    assert frame.FindRegister('vg').IsValid() and frame.FindRegister('z0').IsValid()
    observations.append({'function': 'vector_plain', 'error': message,
        'sveRegistersPresent': True, 'neonRegisterAbsent': True})
    assert process.Continue().Success()
    assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0


try:
    if config.get('transportControl', False):
        transport_control()
    else:
        observe()
finally:
    Path(config['observations']).write_text(json.dumps(observations, indent=4) + '\n')
print('FORGE_LLDB_VECTOR_TRANSPORT_CONTROL_PASS' if config.get('transportControl', False) else 'FORGE_LLDB_VECTOR_PASS')

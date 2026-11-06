"""Read actual scalar FP values and require the clobbered tail to be unavailable."""
import json
import os
from pathlib import Path
import lldb

config = json.loads(Path(os.environ['FORGE_LLDB_FP_CONFIG']).read_text())
lldb.debugger.SetAsync(False)
target = lldb.debugger.GetSelectedTarget()
process = target.GetProcess()
observations = []


def scalar(value, expected, unavailable=False, allow_unavailable=False):
    assert value.IsValid()
    text = value.GetValue()
    if unavailable or (allow_unavailable and text is None):
        assert text is None and value.GetError().Fail(), str(value)
        return {'unavailable': str(value.GetError())}
    assert text is not None and value.GetError().Success(), str(value)
    assert float(text) == expected, (value.GetName(), text, expected)
    return {'value': float(text)}


def observe():
    for index, (name, values) in enumerate([
            ('fp_float', [('first', 19.25), ('second', -7.5)]),
            ('fp_double', [('first', 21.5), ('second', -9.25)]),
            ('fp_clobbered', [('value', 13.75)])]):
        if index:
            assert process.Continue().Success()
        assert process.GetState() == lldb.eStateStopped
        frame = process.GetSelectedThread().GetFrameAtIndex(0)
        assert frame.GetFunctionName() == name
        bias = frame.GetPC() - config['labels'][name]
        function = frame.GetFunction()
        assert function.GetStartAddress().GetLoadAddress(target) == frame.GetPC()
        markers = ['entry', 'fp_clobber_before', 'fp_clobber_write', 'fp_clobber_after'] if name == 'fp_clobbered' else ['entry', name + '_before', name + '_after']
        for marker in markers:
            address = config['labels'][name if marker == 'entry' else marker] + bias
            if process.GetSelectedThread().GetFrameAtIndex(0).GetPC() != address:
                breakpoint = target.BreakpointCreateByAddress(address)
                breakpoint.SetOneShot(True)
                assert breakpoint.IsValid() and breakpoint.GetNumLocations() == 1
                assert process.Continue().Success()
            assert process.GetState() == lldb.eStateStopped
            frame = process.GetSelectedThread().GetFrameAtIndex(0)
            assert frame.GetPC() == address and frame.GetFunctionName() == name
            row = {'function': name, 'marker': marker, 'linkPc': address - bias, 'values': {}}
            if config['mode'] == 'forge':
                source = frame.GetLineEntry().GetFileSpec().fullpath
                assert Path(source).resolve() == Path(config['source']).resolve()
            for variable, expected in values:
                value = frame.FindVariable(variable)
                assert value.GetByteSize() == (8 if name == 'fp_double' else 4)
                row['values'][variable] = scalar(value, expected,
                    unavailable=config['mode'] == 'forge' and marker == 'fp_clobber_after',
                    allow_unavailable=config['mode'] == 'compiler' and marker == 'fp_clobber_after')
            if marker.endswith('_after'):
                if name == 'fp_clobbered':
                    row['global'] = scalar(target.FindFirstGlobalVariable('fp_clobber_sink'), 13.75)
                    register_name = 'xmm0' if config['target'] == 'x86_64' else 's0'
                    data = frame.FindRegister(register_name).GetData()
                    error = lldb.SBError()
                    assert data.GetUnsignedInt32(error, 0) == 0 and error.Success()
                else:
                    row['globals'] = {variable: scalar(target.FindFirstGlobalVariable(name + '_' + variable), expected)
                        for variable, expected in values}
            observations.append(row)
    assert process.Continue().Success()
    assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0


try:
    observe()
finally:
    Path(config['observations']).write_text(json.dumps(observations, indent=4) + '\n')
print('FORGE_LLDB_FLOATING_PASS')

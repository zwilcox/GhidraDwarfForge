"""Observe every executed ordinary boundary through LLDB; compare externally."""
import json
import os
from pathlib import Path
import lldb

lldb.debugger.SetAsync(False)
process = lldb.target.GetProcess()
thread = process.GetSelectedThread()
assert process.GetState() == lldb.eStateStopped
first = thread.GetFrameAtIndex(0)
assert first.GetFunctionName() == 'cfi_main'
entry_pc, entry_sp = first.GetPC(), first.GetSP()
register = os.environ['FORGE_LLDB_WITNESS']
trace = []
for unused in range(512):
    thread = process.GetSelectedThread()
    assert process.GetState() == lldb.eStateStopped
    top = thread.GetFrameAtIndex(0)
    if top.GetFunctionName() == '_start':
        break
    assert top.GetFunctionName() in ('cfi_main', 'cfi_outer', 'cfi_recursive', 'cfi_checkpoint')
    frames = []
    for frame in thread:
        value = frame.FindRegister(register)
        row = {'name': frame.GetFunctionName(), 'relativePc': frame.GetPC() - entry_pc,
            'stackDelta': frame.GetSP() - entry_sp}
        if value.GetValue() is None or value.GetError().Fail():
            row['unavailable'] = True
        else:
            error = lldb.SBError()
            row['witness'] = value.GetValueAsUnsigned(error)
            assert error.Success(), str(error)
        frames.append(row)
        if row['name'] == '_start':
            break
        assert len(frames) < 12
    assert frames[-1]['name'] == '_start', frames
    trace.append(frames)
    thread.StepInstruction(False)
else:
    raise AssertionError('Instruction budget exceeded')
assert max(map(len, trace)) == 8
assert {sum(row['name'] == 'cfi_recursive' for row in frames) for frames in trace} == {0, 1, 2, 3, 4}
process.Continue()
assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0
Path(os.environ['FORGE_LLDB_TRACE']).write_text(json.dumps({'trace': trace, 'exit': 0}, indent=4) + '\n')
print('FORGE_LLDB_BOUNDARIES_PASS', len(trace))

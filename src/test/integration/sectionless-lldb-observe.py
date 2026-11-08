"""Observe source and original instruction bytes from a sectionless executable."""
import json
import os
from pathlib import Path
import lldb


def sectionless_discovery_check(phase):
    config = json.loads(Path(os.environ['FORGE_LLDB_SECTIONLESS_CONFIG']).read_text())
    output = Path(config['observations'])
    rows = json.loads(output.read_text()) if output.exists() else []
    target = lldb.debugger.GetSelectedTarget()
    assert Path(target.GetExecutable().fullpath) == Path(config['original'])
    module = target.GetModuleAtIndex(0)
    assert Path(module.GetFileSpec().fullpath) == Path(config['original'])
    assert not module.GetUUIDString()
    assert module.GetNumCompileUnits() == 0
    assert module.FindFunctions(config['function']).GetSize() == 0
    assert Path(module.GetSymbolFileSpec().fullpath) != Path(config['symbolsFile'])
    if phase == 'lookup':
        breakpoint = target.BreakpointCreateByName(config['function'])
        assert breakpoint.IsValid() and breakpoint.GetNumLocations() == 0
        row = {'phase': phase, 'uuid': module.GetUUIDString(), 'compileUnits': 0,
            'namedBreakpointLocations': 0}
    else:
        assert phase == 'exit'
        process = target.GetProcess()
        assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0
        breakpoint = target.GetBreakpointAtIndex(0)
        assert breakpoint.GetNumLocations() == 0 and breakpoint.GetHitCount() == 0
        row = {'phase': phase, 'namedBreakpointHits': 0, 'exit': 0}
    rows.append(row)
    output.write_text(json.dumps(rows, indent=4) + '\n')
    print('FORGE_LLDB_SECTIONLESS_DISCOVERY_LIMIT_PASS', phase)


def sectionless_check(phase):
    config = json.loads(Path(os.environ['FORGE_LLDB_SECTIONLESS_CONFIG']).read_text())
    output = Path(config['observations'])
    rows = json.loads(output.read_text()) if output.exists() else []
    target = lldb.debugger.GetSelectedTarget()
    assert Path(target.GetExecutable().fullpath) == Path(config['original'])
    process = target.GetProcess()
    if phase == 'exit':
        assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0
        row = {'phase': phase, 'exit': 0}
    else:
        assert process.GetState() == lldb.eStateStopped
        frame = process.GetSelectedThread().GetFrameAtIndex(0)
        line = frame.GetLineEntry()
        assert line.IsValid() and line.GetLine() > 0
        source = Path(line.GetFileSpec().fullpath)
        if config['mode'] == 'compiler' and not source.is_file():
            source = Path(config['referenceSources']) / source.relative_to('/ghidra-dwarf-forge-fixture')
        assert source.is_file(), source
        if config['mode'] == 'forge':
            assert source.resolve() == Path(config['source']).resolve()
        row = {'phase': phase, 'pc': frame.GetPC(), 'function': frame.GetFunctionName(),
            'source': str(source), 'line': line.GetLine()}
        if phase == 'entry':
            assert row['function'] == config['function'] and row['pc'] == config['entry']
            error = lldb.SBError()
            data = process.ReadMemory(row['pc'], len(bytes.fromhex(config['entryBytes'])), error)
            assert error.Success() and data.hex() == config['entryBytes']
            module = frame.GetModule()
            assert Path(module.GetFileSpec().fullpath) == Path(config['module'])
            assert Path(module.GetSymbolFileSpec().fullpath).resolve() == Path(config['symbolsFile']).resolve()
            row['bytes'] = data.hex()
        elif phase == 'step':
            assert row['pc'] != rows[0]['pc'] and row['line'] != rows[0]['line']
    rows.append(row)
    output.write_text(json.dumps(rows, indent=4) + '\n')
    print('FORGE_LLDB_SECTIONLESS_CHECK_PASS', phase)

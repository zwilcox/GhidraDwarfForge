"""Assert loaded-library identity, source and values at separate LLDB stops."""
import json
import os
from pathlib import Path
import lldb


def shared_setup():
    config = json.loads(Path(os.environ['FORGE_LLDB_SHARED_CONFIG']).read_text())
    target = lldb.debugger.GetSelectedTarget()
    module, = [module for module in target.modules if Path(module.GetFileSpec().fullpath) == Path(config['library'])]
    assert Path(module.GetSymbolFileSpec().fullpath).resolve() == Path(config['symbolsFile']).resolve()
    assert module.GetUUIDString().replace('-', '').lower() == config['buildId']
    function = module.FindFunctions('recovered_add').GetContextAtIndex(0).GetFunction()
    assert function.IsValid() and function.GetStartAddress().GetFileAddress() == config['symbols']['recovered_add']
    bias = module.ResolveFileAddress(config['symbols']['recovered_add']).GetLoadAddress(target) - config['symbols']['recovered_add']
    assert bias > 0
    config['runtime'] = {name: bias + value for name, value in config['symbols'].items()}
    config['bias'] = bias
    for name in ('forge_stack_normal', 'forge_stack_changed'):
        bp = target.BreakpointCreateByAddress(config['runtime'][name])
        assert bp.IsValid() and bp.GetNumLocations() == 1
    Path(os.environ['FORGE_LLDB_SHARED_CONFIG']).write_text(json.dumps(config, indent=4) + '\n')


def shared_check(phase):
    config = json.loads(Path(os.environ['FORGE_LLDB_SHARED_CONFIG']).read_text())
    path = Path(config['observations'])
    rows = json.loads(path.read_text()) if path.exists() else []
    target = lldb.debugger.GetSelectedTarget()
    process = target.GetProcess()
    forge = config['mode'] == 'forge'
    if phase == 'exit':
        assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0
        row = {'phase': phase, 'exit': 0}
    else:
        assert process.GetState() == lldb.eStateStopped
        frame = process.GetSelectedThread().GetFrameAtIndex(0)
        carrier = frame
        if not forge and frame.IsInlined():
            carrier = process.GetSelectedThread().GetFrameAtIndex(frame.GetFrameID() + 1)
        assert carrier.GetFunctionName() == 'recovered_add'
        line = frame.GetLineEntry()
        assert line.IsValid() and line.GetLine() > 0
        source = Path(line.GetFileSpec().fullpath)
        if not forge and not source.exists():
            source = Path(config['referenceSources']) / source.relative_to('/ghidra-dwarf-forge-fixture')
        assert source.is_file(), source
        if forge:
            assert source.resolve() == Path(config['source']).resolve()
        row = {'phase': phase, 'pc': frame.GetPC(), 'sp': frame.GetSP(),
            'bias': config['bias'], 'source': str(source), 'line': line.GetLine(), 'values': {}}

        def number(value, expected):
            assert value.IsValid()
            error = lldb.SBError()
            actual = value.GetValueAsUnsigned(error)
            assert error.Success() and actual == expected, (value.GetName(), actual, expected, str(error))
            row['values'][value.GetName()] = actual

        if phase == 'entry':
            if forge:
                assert frame.GetPC() == config['runtime']['recovered_add']
            number(carrier.FindVariable('left'), 19)
            number(carrier.FindVariable('right'), 23)
            node = target.FindFirstType('list_node')
            assert node.IsValid() and node.GetNumberOfFields() == 2
            assert node.GetFieldAtIndex(1).GetType().IsPointerType()
            assert node.GetFieldAtIndex(1).GetType().GetPointeeType().GetName() == 'list_node'
        if phase in ('entry', 'normal', 'changed'):
            global_value = target.FindFirstGlobalVariable('fixture_sink')
            assert global_value.GetLoadAddress() == config['runtime']['fixture_sink']
            number(global_value, 0 if phase == 'entry' else 42)
            if forge:
                number(frame.FindVariable('analyst_register'), 31)
                unknown = frame.FindVariable('analyst_local')
                assert unknown.IsValid() and unknown.GetValue() is None and unknown.GetError().Fail()
        if phase in ('normal', 'changed'):
            assert frame.GetPC() == config['runtime']['forge_stack_' + phase]
            number(carrier.FindVariable('analyst_stack' if forge else 'sum'), 42)
            if phase == 'changed':
                assert rows[-1]['phase'] == 'normal' and frame.GetSP() == rows[-1]['sp'] - 16
        if phase == 'step':
            assert frame.GetPC() != rows[-1]['pc'] and line.GetLine() != rows[-1]['line']
    rows.append(row)
    path.write_text(json.dumps(rows, indent=4) + '\n')
    print('FORGE_LLDB_SHARED_CHECK_PASS', phase)


def shared_resume_normal():
    config = json.loads(Path(os.environ['FORGE_LLDB_SHARED_CONFIG']).read_text())
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    if process.GetSelectedThread().GetFrameAtIndex(0).GetPC() != config['runtime']['forge_stack_normal']:
        lldb.debugger.SetAsync(False)
        assert process.Continue().Success()

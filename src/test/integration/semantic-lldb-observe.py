"""Per-stop assertions, invoked as separate LLDB commands after each resume."""
import json
import os
from pathlib import Path
import lldb


def semantic_check(phase):
    config = json.loads(Path(os.environ['FORGE_LLDB_SEMANTIC_CONFIG']).read_text())
    output = Path(config['observations'])
    observations = json.loads(output.read_text()) if output.exists() else []
    target = lldb.debugger.GetSelectedTarget()
    process = target.GetProcess()
    if phase == 'exit':
        assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0
        observations.append({'phase': phase, 'status': 0})
        assert [row['phase'] for row in observations] == [
            'entry', 'step', 'normal', 'changed', 'composite', 'exit']
    else:
        assert process.GetState() == lldb.eStateStopped
        frame = process.GetSelectedThread().GetFrameAtIndex(0)
        forge = config['mode'] == 'forge'
        line = frame.GetLineEntry()
        assert line.IsValid() and line.GetLine() > 0
        source = Path(line.GetFileSpec().fullpath)
        if not forge and not source.is_file():
            source = Path(config['referenceSources']) / source.relative_to('/ghidra-dwarf-forge-fixture')
        assert source.is_file(), source
        row = {'phase': phase, 'function': frame.GetFunctionName(), 'pc': frame.GetPC(),
            'sp': frame.GetSP(), 'source': str(source), 'line': line.GetLine(), 'values': {}}

        def number(value, expected):
            assert value.IsValid(), 'Missing value'
            error = lldb.SBError()
            actual = value.GetValueAsUnsigned(error)
            assert error.Success(), (value.GetName(), str(error), str(value.GetError()))
            assert actual == expected, (value.GetName(), actual, expected)
            row['values'][value.GetName()] = actual
            return actual

        def local(name, expected):
            carrier = frame
            if not forge and frame.IsInlined():
                carrier = process.GetSelectedThread().GetFrameAtIndex(frame.GetFrameID() + 1)
                assert carrier.GetFunctionName() == 'recovered_add'
            return number(carrier.FindVariable(name), expected)

        def unavailable(name):
            value = frame.FindVariable(name)
            assert value.IsValid() and value.GetValue() is None and value.GetError().Fail(), str(value)
            row.setdefault('unavailable', {})[name] = str(value.GetError())

        if phase == 'step':
            assert row['pc'] != observations[0]['pc'] and row['line'] != observations[0]['line']
        elif phase in ('entry', 'normal', 'changed'):
            assert frame.GetFunction().GetName() == 'recovered_add'
            if forge and config['target'] == 'aarch64' and phase != 'entry':
                unavailable('left')
                unavailable('right')
            else:
                local('left', 19)
                local('right', 23)
            if forge:
                local('analyst_register', 31)
                unavailable('analyst_local')
            if phase == 'entry':
                if forge:
                    assert frame.GetPC() == config['symbols']['recovered_add']
                    assert source.resolve() == Path(config['source']).resolve()
                number(target.FindFirstGlobalVariable('fixture_sink'), 0)
                scoped_name = 'analyst_scope::scoped_counter' if forge else 'scoped_counter'
                scoped, = [value for value in frame.GetVariables(False, False, True, False)
                    if value.GetName() == scoped_name]
                number(scoped, 7)
                for name in ('fixture_state', 'list_node', 'word_view', 'binary_operation'):
                    dtype = target.FindFirstType(name)
                    assert dtype.IsValid() and dtype.GetByteSize() > 0, name
                node = target.FindFirstType('list_node')
                assert node.GetNumberOfFields() == 2
                assert node.GetFieldAtIndex(1).GetType().IsPointerType()
                assert node.GetFieldAtIndex(1).GetType().GetPointeeType().GetName() == 'list_node'
                union = target.FindFirstType('word_view')
                assert union.GetByteSize() == 4 and union.GetNumberOfFields() == 2
                array = union.GetFieldAtIndex(1)
                assert array.GetName() == 'bytes' and array.GetType().IsArrayType()
                row['unionArrayBytes'] = array.GetType().GetByteSize()
                assert row['unionArrayBytes'] == (4 if forge else 1)
                assert array.GetType().GetName().endswith('[4]' if forge else '[]')
                if not forge:
                    row['knownCompilerLimitation'] = 'LLDB 18.1.3 loses array extent for the compiler union member without DW_AT_data_member_location'
            else:
                marker = 'forge_stack_normal' if phase == 'normal' else 'forge_stack_changed'
                assert frame.GetPC() == config['symbols'][marker]
                local('analyst_stack' if forge else 'sum', 42)
                number(target.FindFirstGlobalVariable('fixture_sink'), 42)
                if phase == 'changed':
                    previous = observations[-1]
                    assert previous['phase'] == 'normal' and frame.GetSP() == previous['sp'] - 16
        elif phase == 'composite':
            assert frame.GetFunctionName() == 'recovered_composite'
            if forge:
                assert frame.GetPC() == config['symbols']['recovered_composite']
                local('analyst_composite', 0x1122334455667788)
            else:
                local('first', 0x55667788)
                local('second', 0x11223344)
        else:
            raise AssertionError('Unknown phase: ' + phase)
        observations.append(row)
    output.write_text(json.dumps(observations, indent=4) + '\n')
    print('FORGE_LLDB_SEMANTIC_CHECK_PASS', phase)


def semantic_resume_to(marker):
    config = json.loads(Path(os.environ['FORGE_LLDB_SEMANTIC_CONFIG']).read_text())
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    assert process.GetState() == lldb.eStateStopped
    if process.GetSelectedThread().GetFrameAtIndex(0).GetPC() != config['symbols'][marker]:
        lldb.debugger.SetAsync(False)
        error = process.Continue()
        assert error.Success(), str(error)

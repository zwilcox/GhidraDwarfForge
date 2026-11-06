"""Prove the chosen automatic symbol file, or absence, before launching the target."""
import json
import os
from pathlib import Path
import lldb


def discovery_lookup():
    config = json.loads(Path(os.environ['FORGE_LLDB_DISCOVERY_CONFIG']).read_text())
    target = lldb.debugger.GetSelectedTarget()
    module = target.GetModuleAtIndex(0)
    assert Path(target.GetExecutable().fullpath).resolve() == Path(config['original'])
    assert Path(module.GetFileSpec().fullpath).resolve() == Path(config['original'])
    assert module.GetUUIDString().replace('-', '').lower() == config['buildId']
    functions = module.FindFunctions('fp_float')
    units = module.GetNumCompileUnits()
    symbols = module.GetSymbolFileSpec().fullpath
    if config['control'] == 'matched':
        assert functions.GetSize() == 1 and units > 0
        function = functions.GetContextAtIndex(0).GetFunction()
        assert function.GetStartAddress().GetFileAddress() == config['labels']['fp_float']
        assert Path(symbols).resolve() == Path(config['symbolFile'])
    else:
        assert functions.GetSize() == 0 and units == 0
        assert Path(symbols).resolve() != Path(config['symbolFile'])
    Path(config['lookup']).write_text(json.dumps({'compileUnits': units, 'symbolFile': symbols,
        'functions': functions.GetSize(), 'buildId': config['buildId']}, indent=4) + '\n')
    print('FORGE_LLDB_DISCOVERY_LOOKUP_PASS')


def discovery_exit():
    process = lldb.debugger.GetSelectedTarget().GetProcess()
    assert process.GetState() == lldb.eStateExited and process.GetExitStatus() == 0
    print('FORGE_LLDB_DISCOVERY_EXIT_PASS')

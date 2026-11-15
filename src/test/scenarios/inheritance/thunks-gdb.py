"""Observe actual secondary/vcall this adjustments in the unchanged executable."""
import json
import os
from pathlib import Path
import traceback
import gdb

result = {'status': 'FAIL', 'thunks': [], 'callRestrictions': []}
try:
    case = Path(os.environ['INHERITANCE_RESULT']).parent
    evidence = json.loads((case / 'thunks.json').read_text())
    forge = os.environ['INHERITANCE_VARIANT'] == 'forge-vtables'
    remote = os.environ.get('INHERITANCE_REMOTE', '')
    if remote:
        gdb.execute('target remote ' + remote)
    gdb.Breakpoint('*inheritance_checkpoint', temporary=True)
    gdb.execute('continue' if remote else 'run')
    bias = int(gdb.parse_and_eval('&inheritance_checkpoint')) - evidence['checkpoint']
    result['bias'] = bias
    for row in evidence['thunks']:
        entry = row['address'] + bias
        destination = row['target'] + bias
        subobject = int(gdb.parse_and_eval(row['subobject']))
        complete = int(gdb.parse_and_eval(row['complete']))
        assert subobject > complete
        if forge:
            assert int(gdb.parse_and_eval('&' + row['name'])) == entry
        stop = gdb.Breakpoint('*' + hex(entry), temporary=True)
        gdb.execute('continue')
        assert int(gdb.parse_and_eval('$pc')) == entry
        register = 'rdi' if evidence['target'] == 'x86_64' else 'x0'
        assert int(gdb.parse_and_eval('$' + register)) == subobject
        steps = 0
        while int(gdb.parse_and_eval('$pc')) != destination:
            if forge:
                assert gdb.parse_and_eval('this').is_optimized_out, 'thunk borrowed destination object storage'
                assert gdb.find_pc_line(int(gdb.parse_and_eval('$pc'))).line == 0, 'thunk borrowed destination source lines'
            gdb.execute('stepi')
            steps += 1
            assert steps <= 6, 'adjustment thunk did not reach its saved direct target'
        assert int(gdb.parse_and_eval('$' + register)) == complete, 'incorrect adjusted this pointer'
        finish = gdb.execute('finish', to_string=True)
        restrictions = [line for line in finish.splitlines() if line.startswith('warning:')]
        if forge:
            assert len(restrictions) == 1 and 'does not follow the target calling convention' in restrictions[0], restrictions
            # __thiscall debugger calls remain unaudited. Keep DW_CC_nocall;
            # actual program returns are checked independently in the ABI register.
            result['callRestrictions'].extend(restrictions)
        else:
            assert not restrictions, restrictions
        returned = int(gdb.parse_and_eval('(int)$' + ('eax' if evidence['target'] == 'x86_64' else 'w0')))
        assert returned == row['return']
        result['thunks'].append({'name': row['name'], 'kind': row['kind'], 'adjustment': complete - subobject,
            'steps': steps, 'return': returned})
    gdb.execute('continue')
    assert int(gdb.parse_and_eval('$_exitcode')) == 0
    result['status'] = 'PASS_ADJUSTMENT_THUNKS'
except Exception:
    result['error'] = traceback.format_exc()
    raise
finally:
    Path(os.environ['INHERITANCE_RESULT']).write_text(json.dumps(result, indent=4) + '\n')

"""Record every executed ordinary instruction boundary using an independent reference."""
import json
import os
from pathlib import Path

import gdb

register = os.environ['FORGE_CFI_REGISTER']
stack_register = {'r12': 'rsp', 'x19': 'sp'}[register]
remote = os.environ.get('FORGE_CFI_REMOTE', '')
assert os.environ['FORGE_CFI_MODE'] == 'compiler'
assert os.environ.get('FORGE_CFI_SHARED', '') != '1'
if remote:
    gdb.execute('target remote ' + remote)
gdb.Breakpoint('*cfi_main', temporary=True)
gdb.execute('continue' if remote else 'run')
main_address = int(gdb.parse_and_eval('&cfi_main'))
entry_stack = int(gdb.newest_frame().read_register(stack_register))
trace = []
functions = set()
max_depth = 0
for unused in range(512):
    top = gdb.newest_frame()
    if top.name() == '_start':
        break
    functions.add(top.name())
    assert top.name() in ('cfi_main', 'cfi_outer', 'cfi_recursive', 'cfi_checkpoint'), top.name()
    gdb.write('FORGE_BOUNDARY_BEGIN ' + str(len(trace)) + '\n')
    gdb.execute('set debug frame 1')
    gdb.execute('maintenance flush register-cache')
    frame = gdb.newest_frame()
    stack = []
    while frame is not None and len(stack) < 12:
        row = {'name': frame.name(), 'relativePc': int(frame.pc()) - main_address,
               'stackDelta': int(frame.read_register(stack_register)) - entry_stack}
        try:
            row['witness'] = int(frame.read_register(register))
        except gdb.error as error:
            row['unavailable'] = str(error)
        stack.append(row)
        if frame.name() == '_start':
            break
        frame = frame.older()
    gdb.execute('set debug frame 0')
    gdb.write('FORGE_BOUNDARY_END ' + str(len(trace)) + '\n')
    assert stack[-1]['name'] == '_start', stack
    max_depth = max(max_depth, len(stack))
    trace.append(stack)
    gdb.execute('stepi')
else:
    raise AssertionError('compiler instruction path exceeded 512 instructions')
assert functions == {'cfi_main', 'cfi_outer', 'cfi_recursive', 'cfi_checkpoint'}, functions
assert max_depth == 8, max_depth
# Both taken and untaken recursive branches occur in the unchanged fixture.
assert {sum(row['name'] == 'cfi_recursive' for row in stack) for stack in trace} == {0, 1, 2, 3, 4}
gdb.execute('continue')
assert int(gdb.parse_and_eval('$_exitcode')) == 0
Path(os.environ['FORGE_CFI_RESULT']).write_text(json.dumps({
    'status': 'PASS_COMPILER_INSTRUCTION_PATH', 'trace': trace,
    'functions': sorted(functions), 'maxDepth': max_depth, 'exitcode': 0,
}, indent=4) + '\n')
print('compiler-cfi-boundaries=PASS snapshots=' + str(len(trace)))

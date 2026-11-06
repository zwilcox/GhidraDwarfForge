"""Record every executed ordinary instruction boundary using an independent reference."""
import json
import os
import runpy
from pathlib import Path

import gdb

register = os.environ['FORGE_CFI_REGISTER']
stack_register = {'r12': 'rsp', 'x19': 'sp'}[register]
remote = os.environ.get('FORGE_CFI_REMOTE', '')
assert os.environ['FORGE_CFI_MODE'] == 'compiler'
fixed_pointers = json.loads(os.environ.get('FORGE_CFI_FIXED_POINTERS', '[]'))
shared = os.environ.get('FORGE_CFI_SHARED', '') == '1'
companion = os.environ.get('FORGE_CFI_COMPANION', '') == '1'
loader = runpy.run_path(os.environ['FORGE_CFI_LOAD_HELPER']) if companion else None
root_name = 'main' if shared else '_start'
if remote:
    gdb.execute('target remote ' + remote)
if shared:
    gdb.Breakpoint('cfi_ready', temporary=True)
    gdb.execute('continue' if remote else 'run')
    bias = int(gdb.parse_and_eval('cfi_module_bias'))
    assert bias > 0, 'shared library was not relocated'
    if companion: loader['load_companion'](os.environ['FORGE_CFI_SYMBOLS'], bias)
    else: gdb.execute('add-symbol-file "' + os.environ['FORGE_CFI_SYMBOLS'] + '" -o ' + hex(bias))
elif companion:
    if not remote: gdb.execute('starti')
    loader['load_companion'](os.environ['FORGE_CFI_SYMBOLS'], loader['image_bias'](os.environ['FORGE_CFI_ORIGINAL']))
gdb.Breakpoint('*cfi_main', temporary=True)
gdb.execute('continue' if remote or shared or companion else 'run')
main_address = int(gdb.parse_and_eval('&cfi_main'))
root_address = int(gdb.parse_and_eval('&main')) if shared else main_address
entry_stack = int(gdb.newest_frame().read_register(stack_register))
trace = []
functions = set()
max_depth = 0
for unused in range(512):
    top = gdb.newest_frame()
    if top.name() == root_name:
        break
    for pointer in fixed_pointers:
        assert shared, 'fixed pointer runtime observation currently requires the shared loader fixture'
        value = int.from_bytes(gdb.selected_inferior().read_memory(int(pointer['address'], 16) + bias, 8), 'little')
        assert value == int(pointer['value'], 16) + bias, (pointer, value, bias)
    functions.add(top.name())
    assert top.name() in ('cfi_main', 'cfi_outer', 'cfi_recursive', 'cfi_checkpoint'), top.name()
    gdb.write('FORGE_BOUNDARY_BEGIN ' + str(len(trace)) + '\n')
    gdb.execute('set debug frame 1')
    gdb.execute('maintenance flush register-cache')
    frame = gdb.newest_frame()
    stack = []
    while frame is not None and len(stack) < 12:
        row = {'name': frame.name(), 'relativePc': int(frame.pc()) - (root_address if frame.name() == root_name else main_address),
               'stackDelta': int(frame.read_register(stack_register)) - entry_stack}
        if os.environ.get('FORGE_CFI_FRAME_POINTER_VALUES') == '1':
            pointer = int(frame.read_register('rbp' if register == 'r12' else 'x29'))
            row['framePointer'] = 'zero' if pointer == 0 else pointer - entry_stack
        try:
            row['witness'] = int(frame.read_register(register))
        except gdb.error as error:
            row['unavailable'] = str(error)
        stack.append(row)
        if frame.name() == root_name:
            break
        frame = frame.older()
    gdb.execute('set debug frame 0')
    gdb.write('FORGE_BOUNDARY_END ' + str(len(trace)) + '\n')
    assert stack[-1]['name'] == root_name, stack
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
    'observedFixedPointers': fixed_pointers,
}, indent=4) + '\n')
print('compiler-cfi-boundaries=PASS snapshots=' + str(len(trace)))

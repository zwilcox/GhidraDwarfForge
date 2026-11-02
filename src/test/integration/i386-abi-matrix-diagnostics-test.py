#!/usr/bin/env python3
"""Wrong function, value, address or diagnostic must never pass the reference gate."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('diagnostics', Path(__file__).with_name('i386-abi-matrix-diagnostics.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
message = "Python Exception <class 'gdb.MemoryError'>: Cannot access memory at address 0x1\n"
baseline = ['compiler', 'vector_add', message, None, [1.5, 3.5, 5.5, 7.5], [1.5, 3.5, 5.5, 7.5], 1, True]
assert module.vector_finish(*baseline)['typedReturnValidated'] is False
clean = baseline.copy()
clean[2] = ''
assert module.vector_finish(*clean) is None
controls = [(0, 'forge'), (1, 'sse_parameters'), (2, message * 2),
    (2, message + 'warning: malformed DWARF\n'), (2, message.replace('MemoryError', 'error')),
    (2, message.replace('0x1', '0x2')), (2, 'ordinary unexpected output\n'),
    (3, [1.5, 3.5, 5.5, 7.5]), (4, [0., 0., 0., 0.]), (5, [0., 0., 0., 0.]),
    (6, 2), (7, False)]
for index, value in controls:
    candidate = baseline.copy()
    candidate[index] = value
    try:
        module.vector_finish(*candidate)
    except AssertionError:
        continue
    raise RuntimeError(('invalid reference exception accepted', index, value))
print('i386-abi-matrix-diagnostics-test=PASS positives=2 negatives=' + str(len(controls)))

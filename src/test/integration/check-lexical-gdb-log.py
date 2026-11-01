#!/usr/bin/env python3
"""Allow only compiler-corroborated QEMU DSO diagnostics, never source comments."""
from collections import Counter
from pathlib import Path
import re
import sys

case, phase, target = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
messages = []
for name in ['compiler', phase]:
    lines = (case / (name + '-gdb.log')).read_text().splitlines()
    warnings = [line for line in lines if re.match(r'\s*(warning:|error:)', line, re.I)]
    if target == 'x86_64':
        assert not warnings, warnings
    else:
        assert target == 'aarch64'
        assert all(re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ '
            r'has a corrupt string table index', line) for line in warnings), warnings
    messages.append(Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in warnings))
assert messages[0] == messages[1], messages
print('lexical-gdb-diagnostics=' + phase + ' PASS')

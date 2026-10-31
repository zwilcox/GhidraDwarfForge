#!/usr/bin/env python3
"""Record and enforce saved-program, exporter and fixture immutability."""
import hashlib
import json
from pathlib import Path
import sys

case, phase, ghidra = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
assert phase in ('before', 'after')
source = Path(__file__).resolve().parent
fixture = source.parent / 'fixtures/stack-local-definitions.c'
files = [fixture, Path(__file__), source / 'stack-local-definitions-export.sh',
    source / 'stack-local-definitions-gdb.py', source / 'check-stack-local-definitions.py',
    source / 'ghidra_scripts/PrepareStackLocalDefinitions.java',
    source / 'ghidra_scripts/RebaseFixtureProgram.java', case / 'stack.reference', case / 'stack.stripped']
files += [p for p in (ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
files += [p for p in (case / 'project').rglob('*') if p.is_file()]
digests = {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
(case / ('protected-' + phase + '.json')).write_text(json.dumps(digests, indent=4) + '\n')
if phase == 'after':
    before = json.loads((case / 'protected-before.json').read_text())
    changed = sorted(p for p in before.keys() | digests.keys() if before.get(p) != digests.get(p))
    allowed = [str((case / 'project/StackLocals.rep/idata' / name).resolve()) for name in ('~index.bak', '~journal.bak')]
    assert set(changed) <= set(allowed), changed
    (case / 'project-backup-changes.json').write_text(json.dumps(changed, indent=4) + '\n')
    print('stack-local-protected=PASS')

#!/usr/bin/env python3
"""Actual native decompiler failure must not reacquire a class method signature."""
import hashlib
import json
from collections import Counter
from pathlib import Path
import re
import subprocess
import sys

case, ghidra = (Path(value).resolve(strict=True) for value in sys.argv[1:])
harness = Path(__file__).resolve().parent
baseline = json.loads((case / 'acceptance.json').read_text())
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
protected = {str(p): digest(p) for p in [case / 'reference', case / 'stripped', case / 'forge.dbg', case / 'forge.dbg.c']}
project = case / 'project'
before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
commands = []


def run(label, command):
    command = list(map(str, command))
    commands.append({'label': label, 'argv': command})
    (case / 'failure-commands.json').write_text(json.dumps(commands, indent=4) + '\n')
    with (case / (label + '.log')).open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
    return (case / (label + '.log')).read_text()


output = case / 'failed.dbg'
pair = None
for iteration in ['first', 'repeat']:
    log = run('failure-' + iteration, [ghidra / 'support/analyzeHeadless', project, 'Object',
        '-process', 'reference', '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts',
        '-postScript', 'ClassDecompilerFailureExport.java', output])
    assert 'class-decompiler-failure=PASS' in log
    assert 'Low-level Error: Flow exceeded maximum allowable instructions' in log
    current = [digest(output), digest(Path(str(output) + '.c'))]
    assert pair is None or current == pair
    pair = current
assert 'Flow exceeded maximum allowable instructions' in Path(str(output) + '.c').read_text()
for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
    assert 'Warning:' not in run('failed-' + view, ['readelf', '--debug-dump=' + view, output])
run('failed-classes', ['python3', harness / 'check-class-scopes.py', case / 'failed-info.log', '--failed'])
run('failed-objects', ['python3', harness / 'check-object-parameters.py', case / 'failed-info.log', '--failed'])
assert 'No errors.' in run('failed-llvm', ['llvm-dwarfdump', '--verify', output])
run('failed-strict', ['python3', harness / 'check-dwarfdump.py', output,
    case / 'failed-dwarfdump.log', '--original', case / 'reference'])
assert 'object-parameter-gdb=failed PASS' in run('failed-gdb', ['bash', harness / 'object-parameter-gdb.sh',
    case, baseline['target'], 'failed', output])
warnings = []
for mode in ['compiler', 'failed']:
    lines = (case / (mode + '-gdb.log')).read_text().splitlines()
    warnings.append(Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in lines
        if re.match(r'\s*(warning:|error:)', line, re.I)))
assert warnings[0] == warnings[1], warnings
assert protected == {p: digest(Path(p)) for p in protected}
after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
assert changed <= {str(project / 'Object.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
assert not any(p.name.startswith('.') for p in case.iterdir()), 'temporary output residue'
(case / 'failure-acceptance.json').write_text(json.dumps({'status': 'CLASS_SCOPE_FAILURE_PASS',
    'target': baseline['target'], 'role': baseline['role'], 'outputPair': pair,
    'protected': protected, 'observations': json.loads((case / 'failed-observations.json').read_text())}, indent=4) + '\n')
print('class-scope-failure=PASS')

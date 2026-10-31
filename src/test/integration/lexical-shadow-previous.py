#!/usr/bin/env python3
"""Compare explicit shadow lookup with a package predating lexical emission."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

case, previous = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
harness = Path(__file__).resolve().parent
baseline = json.loads((case / 'acceptance.json').read_text())
output = case / 'previous.dbg'
commands = []


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label, command):
    command = list(map(str, command))
    commands.append({'label': label, 'argv': command})
    (case / 'previous-commands.json').write_text(json.dumps(commands, indent=4) + '\n')
    with (case / (label + '.log')).open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)


module = previous / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
protected = {str(p): digest(p) for p in [module, case / 'stripped', case / 'reference', case / 'forge.dbg', case / 'forge.dbg.c']}
project = case / 'project'
before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
run('previous-export', [previous / 'support/analyzeHeadless', project, 'Lexical', '-process', 'stripped',
    '-readOnly', '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)])
assert 'GhidraDwarfForge symbol export PASS' in (case / 'previous-export.log').read_text()
run('previous-elf', ['readelf', '-hSWn', output])
for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
    run('previous-' + view, ['readelf', '--debug-dump=' + view, output])
    assert 'Warning:' not in (case / ('previous-' + view + '.log')).read_text()
assert 'DW_TAG_lexical_block' not in (case / 'previous-info.log').read_text()
run('previous-llvm', ['llvm-dwarfdump', '--verify', output])
assert 'No errors.' in (case / 'previous-llvm.log').read_text()
run('previous-strict', ['python3', harness / 'check-dwarfdump.py', output,
    case / 'previous-dwarfdump.log', '--original', case / 'stripped'])
run('previous-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, baseline['target'], 'previous', output])
assert 'lexical-shadow-gdb=previous PASS' in (case / 'previous-gdb.log').read_text()
run('previous-diagnostics', ['python3', harness / 'check-lexical-gdb-log.py', case, 'previous', baseline['target']])
observations = json.loads((case / 'previous-observations.json').read_text())
old = next(row for row in observations if row['marker'] == 'inner_live')
labels = json.loads((case / 'labels.json').read_text())
new = next(row for row in json.loads((case / 'forge-observations.json').read_text()) if row['address'] == labels['inner_live'])
assert old['outer'] == '11' and old['inner'] == '23' and new['value'] == '23'
assert protected == {p: digest(Path(p)) for p in protected}
after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
allowed = {str(project / 'Lexical.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
assert changed <= allowed, changed
(case / 'previous-acceptance.json').write_text(json.dumps({'status': 'LEXICAL_PREVIOUS_COMPARISON_PASS',
    'target': baseline['target'], 'role': baseline['role'], 'protected': protected,
    'previousInnerScopeLookup': old['outer'], 'candidateInnerScopeLookup': new['value']}, indent=4) + '\n')
print('lexical-shadow-previous=PASS')

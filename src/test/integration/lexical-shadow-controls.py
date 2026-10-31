#!/usr/bin/env python3
"""Reject stale/coalesced lexical evidence through real export and GDB."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

case, ghidra = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
repository = Path(__file__).resolve().parents[3]
harness = repository / 'src/test/integration'
baseline = json.loads((case / 'acceptance.json').read_text())
target = baseline['target']
commands = []


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label, command):
    command = list(map(str, command))
    commands.append({'label': label, 'argv': command})
    (case / 'controls-commands.json').write_text(json.dumps(commands, indent=4) + '\n')
    with (case / (label + '.log')).open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)


protected = {str(p): digest(p) for p in [case / 'stripped', case / 'reference', case / 'forge.dbg', case / 'forge.dbg.c']}
project = case / 'project'
before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
launcher = [ghidra / 'support/analyzeHeadless', project, 'Lexical', '-process', 'stripped', '-readOnly', '-noanalysis']
for mode in ['stale', 'coalesced']:
    output = case / (mode + '.dbg')
    run(mode + '-export', [*launcher, '-scriptPath', harness / 'ghidra_scripts',
        '-postScript', 'PrepareLexicalControl.java', mode,
        '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)])
    log = (case / (mode + '-export.log')).read_text()
    assert 'lexical-control-preparation=' + mode + ' PASS' in log
    assert 'GhidraDwarfForge symbol export PASS' in log
    assert 'Omitted saved lexical scopes for scoped' in log
    if mode == 'coalesced':
        assert 'a bound local was skipped or coalesced during extraction' in log
    assert 'Using explicitly saved lexical ownership for scoped' not in log
    run(mode + '-elf', ['readelf', '-hSWn', output])
    for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
        run(mode + '-' + view, ['readelf', '--debug-dump=' + view, output])
        assert 'Warning:' not in (case / (mode + '-' + view + '.log')).read_text()
    assert 'DW_TAG_lexical_block' not in (case / (mode + '-info.log')).read_text()
    run(mode + '-llvm', ['llvm-dwarfdump', '--verify', output])
    assert 'No errors.' in (case / (mode + '-llvm.log')).read_text()
    run(mode + '-strict', ['python3', harness / 'check-dwarfdump.py', output,
        case / (mode + '-dwarfdump.log'), '--original', case / 'stripped'])
    run(mode + '-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, target, mode, output])
    assert 'lexical-shadow-gdb=' + mode + ' PASS' in (case / (mode + '-gdb.log')).read_text()
    run(mode + '-diagnostics', ['python3', harness / 'check-lexical-gdb-log.py', case, mode, target])
    assert protected == {p: digest(Path(p)) for p in protected}
# Reopen pristine saved evidence and reproduce the original output pair.
run('controls-baseline-reopen', [*launcher, '-postScript', 'GhidraDwarfForge.java',
    '--packaged-natives', '--output=' + str(case / 'forge.dbg')])
assert 'GhidraDwarfForge symbol export PASS' in (case / 'controls-baseline-reopen.log').read_text()
assert protected == {p: digest(Path(p)) for p in protected}
after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
allowed = {str(project / 'Lexical.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
assert changed <= allowed, changed
(case / 'controls-acceptance.json').write_text(json.dumps({'status': 'LEXICAL_CONTROLS_PASS',
    'target': target, 'role': baseline['role'], 'discontiguous': baseline['discontiguous'],
    'exports': 3, 'observations': 8, 'protected': protected, 'projectBackupChanges': sorted(changed)}, indent=4) + '\n')
print('lexical-shadow-controls=PASS')

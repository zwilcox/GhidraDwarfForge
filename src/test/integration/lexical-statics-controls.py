#!/usr/bin/env python3
"""Real negative static bindings, genuine decompiler failure and copy cancellation."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

case, ghidra = (Path(value).resolve(strict=True) for value in sys.argv[1:])
harness = Path(__file__).resolve().parent
baseline = json.loads((case / 'acceptance.json').read_text())


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot(project):
    return {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}


def unchanged_project(project, before):
    after = snapshot(project)
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    assert changed <= {str(project / 'Statics.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}, changed


commands = []


def run(label, command):
    command = list(map(str, command))
    commands.append({'label': label, 'argv': command})
    (case / 'controls-commands.json').write_text(json.dumps(commands, indent=4) + '\n')
    with (case / (label + '.log')).open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=240, check=True)
    return (case / (label + '.log')).read_text()


protected = {str(p): digest(p) for p in [case / 'reference', case / 'stripped', case / 'forge.dbg', case / 'forge.dbg.c']}
project = case / 'project'
before = snapshot(project)
launcher = [ghidra / 'support/analyzeHeadless', project, 'Statics', '-process', 'stripped', '-readOnly', '-noanalysis',
    '-scriptPath', harness / 'ghidra_scripts']
receipts = []
for mode in ['stale', 'conflict', 'coalesced', 'failed']:
    output = case / (mode + '.dbg')
    pair = None
    for iteration in ['first', 'repeat']:
        args = ['-postScript', 'StaticDecompilerFailureExport.java', output] if mode == 'failed' else [
            '-postScript', 'PrepareStaticControl.java', mode, '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)]
        log = run(mode + '-export-' + iteration, [*launcher, *args])
        if mode == 'failed':
            assert 'static-decompiler-failure=PASS' in log and 'Flow exceeded maximum allowable instructions' in log
        else:
            assert 'static-control-preparation=' + mode + ' PASS' in log and 'GhidraDwarfForge symbol export PASS' in log
            assert {'stale': 'Omitted explicit static binding', 'conflict': 'conflicting declaration in the same function/lexical scope',
                'coalesced': 'a bound local was skipped or coalesced during extraction'}[mode] in log
        current = [digest(output), digest(Path(str(output) + '.c'))]
        assert pair is None or pair == current
        pair = current
    for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
        assert 'Warning:' not in run(mode + '-' + view, ['readelf', '--debug-dump=' + view, output])
    run(mode + '-scope-dies', ['python3', harness / 'check-lexical-statics.py', case, mode])
    assert 'No errors.' in run(mode + '-llvm', ['llvm-dwarfdump', '--verify', output])
    run(mode + '-strict', ['python3', harness / 'check-dwarfdump.py', output, case / (mode + '-dwarfdump.log'), '--original', case / 'stripped'])
    assert 'lexical-statics-gdb=' + mode + ' PASS' in run(mode + '-gdb', ['bash', harness / 'lexical-statics-gdb.sh', case, baseline['target'], mode, output])
    def warnings(phase):
        return Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in (case / (phase + '-gdb.log')).read_text().splitlines()
            if re.match(r'\s*(warning:|error:)', line, re.I))
    assert warnings(mode) == warnings('compiler')
    assert protected == {p: digest(p) for p in protected}
    unchanged_project(project, before)
    receipts.append({'mode': mode, 'outputPair': pair, 'observations': json.loads((case / (mode + '-observations.json')).read_text())})
# The real cancellation entry point reaches copying only after successful production.
work = Path(tempfile.mkdtemp(prefix='static-cancel-', dir=case))
padded = work / 'input'
shutil.copyfile(case / 'stripped', padded)
with padded.open('r+b') as stream:
    stream.truncate(128 * 1024 * 1024)
protected[str(padded)] = digest(padded)
cancel_project = work / 'project'
cancel_project.mkdir()
rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if baseline['role'] == 'pie-rebased' else []
run('cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'Statics', '-import', padded,
    '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', harness / 'ghidra_scripts',
    *rebase, '-postScript', 'PrepareLexicalStatics.java', case / 'labels.json', case / 'compiler-objects.json', work / 'prepared.json'])
cancel_before = snapshot(cancel_project)
log = run('cancel-export', [ghidra / 'support/analyzeHeadless', cancel_project, 'Statics', '-process', 'input',
    '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts', '-postScript', 'CancelDuringElfCopy.java', padded, case / 'forge.dbg'])
assert 'production-copy-cancellation=PASS' in log and '"status":"CANCELLED"' in log
assert 'Using explicit static ownership' in log
unchanged_project(cancel_project, cancel_before)
run('baseline-reopen', [*launcher, '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'forge.dbg')])
assert protected == {p: digest(p) for p in protected}
unchanged_project(project, before)
assert not any(p.name.startswith('.') for p in case.iterdir()), 'temporary output residue'
(case / 'controls-acceptance.json').write_text(json.dumps({'status': 'STATIC_SCOPE_CONTROLS_PASS',
    'target': baseline['target'], 'role': baseline['role'], 'exports': 9, 'cancelledExports': 1,
    'protected': protected, 'controls': receipts}, indent=4) + '\n')
print('lexical-statics-controls=PASS')

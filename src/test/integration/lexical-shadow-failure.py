#!/usr/bin/env python3
"""Actual decompiler failure and copy cancellation with persisted lexical scopes."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

case, ghidra = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
repository = Path(__file__).resolve().parents[3]
harness = repository / 'src/test/integration'
baseline = json.loads((case / 'acceptance.json').read_text())
commands = []


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def run(label, command):
    command = list(map(str, command))
    commands.append({'label': label, 'argv': command})
    (case / 'failure-commands.json').write_text(json.dumps(commands, indent=4) + '\n')
    with (case / (label + '.log')).open('w') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)


protected = {str(p): digest(p) for p in [case / 'stripped', case / 'reference', case / 'forge.dbg', case / 'forge.dbg.c']}
project = case / 'project'
before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
launcher = [ghidra / 'support/analyzeHeadless', project, 'Lexical', '-process', 'stripped',
    '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts']
output = case / 'failed.dbg'
pair = None
for iteration in ['first', 'repeat']:
    run('failure-' + iteration, [*launcher, '-postScript', 'LexicalDecompilerFailureExport.java', output])
    log = (case / ('failure-' + iteration + '.log')).read_text()
    assert 'lexical-decompiler-failure=PASS' in log
    assert 'Low-level Error: Flow exceeded maximum allowable instructions' in log
    current = [digest(output), digest(Path(str(output) + '.c'))]
    assert pair is None or pair == current
    pair = current
run('failed-elf', ['readelf', '-hSWn', output])
for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
    run('failed-' + view, ['readelf', '--debug-dump=' + view, output])
    assert 'Warning:' not in (case / ('failed-' + view + '.log')).read_text()
text = (case / 'failed-info.log').read_text()
assert 'DW_TAG_lexical_block' not in text
entries = re.split(r'(?m)(?=^ <\d+><[0-9a-f]+>:)', text)
function = next(i for i, entry in enumerate(entries) if 'DW_TAG_subprogram' in entry and re.search(r'DW_AT_name\s+: .*scoped$', entry, re.M))
assert re.match(r' <1>', entries[function]) and re.match(r' <1>', entries[function + 1]), 'failed function has children'
assert all('DW_AT_' + attr not in entries[function] for attr in ['type', 'decl_line', 'decl_file'])
assert 'DW_AT_low_pc' in entries[function] and 'DW_AT_high_pc' in entries[function]
source = Path(str(output) + '.c').read_text()
assert 'Flow exceeded maximum allowable instructions' in source
run('failed-llvm', ['llvm-dwarfdump', '--verify', output])
assert 'No errors.' in (case / 'failed-llvm.log').read_text()
run('failed-strict', ['python3', harness / 'check-dwarfdump.py', output,
    case / 'failed-dwarfdump.log', '--original', case / 'stripped'])
run('failed-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, baseline['target'], 'failed', output])
assert 'lexical-shadow-gdb=failed PASS' in (case / 'failed-gdb.log').read_text()
run('failed-diagnostics', ['python3', harness / 'check-lexical-gdb-log.py', case, 'failed', baseline['target']])
# Only a newly created fixture copy is enlarged; the actual original stays untouched.
cancel_case = Path(tempfile.mkdtemp(prefix='cancellation-', dir=case))
padded = cancel_case / 'input.elf'
shutil.copyfile(case / 'stripped', padded)
with padded.open('r+b') as stream:
    stream.truncate(128 * 1024 * 1024)
padded_digest = digest(padded)
cancel_project = cancel_case / 'project'
cancel_project.mkdir()
rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if baseline['role'] == 'pie-rebased' else []
run('scope-cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'CancelLexical',
    '-import', padded, '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120',
    '-scriptPath', harness / 'ghidra_scripts', *rebase, '-postScript', 'PrepareLexicalShadow.java',
    case / 'labels.json', case / 'compiler-storage.json', cancel_case / 'prepared.json'])
assert 'lexical-shadow-preparation=PASS' in (case / 'scope-cancel-import.log').read_text()
run('scope-copy-cancel', [ghidra / 'support/analyzeHeadless', cancel_project, 'CancelLexical',
    '-process', 'input.elf', '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts',
    '-postScript', 'CancelDuringElfCopy.java', padded, case / 'forge.dbg'])
log = (case / 'scope-copy-cancel.log').read_text()
assert 'production-copy-cancellation=PASS' in log and '"status":"CANCELLED"' in log
assert 'Using explicitly saved lexical ownership for scoped' in log
assert not re.search(r'"status":"(?:SUCCESS|PARTIAL|FATAL)"|OutOfMemoryError|SIGSEGV|access violation', log)
assert digest(padded) == padded_digest
assert not any(p.name.startswith('.') for p in case.iterdir()), 'temporary publication residue'
assert protected == {p: digest(Path(p)) for p in protected}
after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
allowed = {str(project / 'Lexical.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
assert changed <= allowed, changed
(case / 'failure-acceptance.json').write_text(json.dumps({'status': 'LEXICAL_FAILURE_PASS',
    'target': baseline['target'], 'role': baseline['role'], 'exports': 2, 'failedPair': pair,
    'nativeFailure': 'Flow exceeded maximum allowable instructions', 'copyCancellation': True,
    'protected': protected, 'paddedInputSha256': padded_digest}, indent=4) + '\n')
print('lexical-shadow-failure=PASS')

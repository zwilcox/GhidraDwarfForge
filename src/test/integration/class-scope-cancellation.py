#!/usr/bin/env python3
"""Cancel the real exporter after class emission while preserving its prior output pair."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

case, ghidra = (Path(value).resolve(strict=True) for value in sys.argv[1:])
harness = Path(__file__).resolve().parent
baseline = json.loads((case / 'acceptance.json').read_text())


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


protected = {str(p): digest(p) for p in [case / 'reference', case / 'stripped', case / 'forge.dbg', case / 'forge.dbg.c']}
project = case / 'project'
before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
work = Path(tempfile.mkdtemp(prefix='class-cancel-', dir=case))
padded = work / 'input'
shutil.copyfile(case / 'reference', padded)
with padded.open('r+b') as stream:
    stream.truncate(128 * 1024 * 1024)
protected[str(padded)] = digest(padded)
cancel_project = work / 'project'
cancel_project.mkdir()
control = baseline.get('bindingControl')
binding = control or ('explicit' if baseline.get('explicitBinding') else 'inferred')
rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if baseline['role'] == 'pie-rebased' else []
command = list(map(str, [ghidra / 'support/analyzeHeadless', cancel_project, 'CancelClass',
    '-import', padded, '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120',
    '-scriptPath', harness / 'ghidra_scripts', *rebase, '-postScript',
    'PrepareObjectParameter.java', work / 'prepared.json', binding]))
(work / 'import-command.json').write_text(json.dumps(command, indent=4) + '\n')
with (work / 'import.log').open('w') as log:
    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
assert 'object-parameter-preparation=PASS' in (work / 'import.log').read_text()
cancel_before = {str(p): digest(p) for p in cancel_project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
command = list(map(str, [ghidra / 'support/analyzeHeadless', cancel_project, 'CancelClass', '-process', 'input',
    '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts', '-postScript',
    'CancelDuringElfCopy.java', padded, case / 'forge.dbg']))
(work / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
with (work / 'cancel.log').open('w') as log:
    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
text = (work / 'cancel.log').read_text()
assert 'production-copy-cancellation=PASS' in text and '"status":"CANCELLED"' in text
if control:
    assert ('saved class type identity is stale' if control == 'stale' else
        'current method object types contradict the class layout') in text
assert protected == {name: digest(Path(name)) for name in protected}
after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
assert changed <= {str(project / 'Object.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
cancel_after = {str(p): digest(p) for p in cancel_project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
changed = {name for name in cancel_before.keys() | cancel_after.keys() if cancel_before.get(name) != cancel_after.get(name)}
assert changed <= {str(cancel_project / 'CancelClass.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
assert not any(p.name.startswith('.') for p in case.iterdir()), 'temporary output residue'
(case / 'cancellation-acceptance.json').write_text(json.dumps({'status': 'CLASS_COPY_CANCELLATION_PASS',
    'target': baseline['target'], 'role': baseline['role'], 'bindingControl': control,
    'protected': protected, 'log': str(work / 'cancel.log')}, indent=4) + '\n')
print('class-scope-cancellation=PASS')

#!/usr/bin/env python3
"""Seed private saved-program annotations and prove independent read-only reopens."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def snapshot(root):
    return {str(path.relative_to(root)): digest(path) for path in root.rglob('*')
        if path.is_file() and not path.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('case', type=Path, help='successful compiler-reference case directory')
    args = parser.parse_args()
    ghidra, case = args.ghidra.resolve(strict=True), args.case.resolve(strict=True)
    reference = json.loads((case / 'result.json').read_text())
    assert reference['status'] == 'PASS_COMPILER_REFERENCE'
    for name, expected in reference['protectedSha256'].items():
        assert digest(Path(name)) == expected, name
    root = Path(tempfile.mkdtemp(prefix='curation-', dir=case))
    project = root / 'project'
    project.mkdir()
    scripts = root / 'scripts'
    scripts.mkdir()
    source = Path(__file__).with_name('ghidra_scripts') / 'PrepareAnalystAnnotations.java'
    shutil.copy2(source, scripts / source.name)
    protected = {str(path): digest(path) for path in (source, Path(__file__), case / 'reference',
        case / 'stripped', case / 'labels.json')}
    commands = []

    def run(label, extra):
        command = [str(ghidra / 'support/analyzeHeadless'), str(project), 'Annotations',
            *map(str, extra), '-scriptPath', str(scripts), '-postScript', source.name,
            'setup' if label == 'import' else 'read', str(case / 'labels.json'), str(root / (label + '.json'))]
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=240)
        assert result.returncode == 0, label
        text = (root / (label + '.log')).read_text()
        assert 'analyst-annotations-preparation=PASS comments=50 equates=13' in text, label
        assert 'error: cannot find symbol' not in text and 'ERROR REPORT SCRIPT ERROR' not in text, label

    run('import', ['-import', case / 'stripped', '-analysisTimeoutPerFile', '120'])
    states = [snapshot(project)]
    for name in ('read1', 'read2'):
        run(name, ['-process', 'stripped', '-readOnly', '-noanalysis'])
        states.append(snapshot(project))
    assert (root / 'read1.json').read_bytes() == (root / 'read2.json').read_bytes()
    initial = json.loads((root / 'import.json').read_text())
    current = json.loads((root / 'read1.json').read_text())
    assert initial == current, 'saved annotations changed after post-script analysis'
    assert len(current['comments']) == 50 and len(current['equates']) == 13
    gap = [row for row in current['comments'] if row['text'].startswith('FORGE_ANNOTATION:body-gap:')]
    assert len(gap) == 5 and all(row['function'] is None for row in gap)
    interior = [row for row in current['comments'] if row['text'].startswith('FORGE_ANNOTATION:interior:')]
    assert len(interior) == 5 and all(not row['codeUnitStart'] for row in interior)
    assert len(current['functionRanges']) >= 2
    shared = [row for row in current['equates'] if row.get('displayName') == 'ANNOTATION_SHARED_DISPLAY']
    assert len(shared) == 2 and {row['storedValue'] for row in shared} == {'19', '23'}
    assert all(row['enumBytes'] == 1 and row['references'] for row in shared)
    assert any(row.get('helperFailure') == 'java.lang.NumberFormatException' for row in current['equates'])
    changes = []
    allowed = {'Annotations.rep/idata/~index.bak', 'Annotations.rep/idata/~journal.bak'}
    for before, after in zip(states, states[1:]):
        changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
        assert set(changed) <= allowed, changed
        changes.append(changed)
    assert not changes[1], 'second read-only reopen changed project files'
    assert protected == {path: digest(Path(path)) for path in protected}
    for index, state in enumerate(states):
        (root / ('project-' + str(index) + '.json')).write_text(json.dumps(state, indent=4) + '\n')
    receipt = {'status': 'PASS_SAVED_ANNOTATIONS', 'target': reference['target'], 'role': reference['role'],
        'protectedSha256': protected, 'projectChanges': changes, 'comments': 50, 'equates': 13,
        'readbackSha256': digest(root / 'read1.json'),
        'limits': 'Saved Ghidra annotation fixture only. No production annotation emission or genuine decompiler-failure claim. Dynamic-only equates and explicit local/type collision curation remain subsequent fixture work.'}
    (root / 'result.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print('analyst-annotations-prepare=PASS ' + str(root))


if __name__ == '__main__':
    main()

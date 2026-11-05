#!/usr/bin/env python3
"""Compare the packaged inventory with independent saved-program annotation readback."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('curation', type=Path)
    args = parser.parse_args()
    ghidra, curation = args.ghidra.resolve(strict=True), args.curation.resolve(strict=True)
    spec = importlib.util.spec_from_file_location('preparation', Path(__file__).with_name('analyst-annotations-prepare.py'))
    preparation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preparation)
    digest, snapshot = preparation.digest, preparation.snapshot
    saved = json.loads((curation / 'result.json').read_text())
    assert saved['status'] == 'PASS_SAVED_ANNOTATIONS'
    expected = json.loads((curation / 'read1.json').read_text())
    for path in ('reference', 'stripped', 'labels.json'):
        assert digest(curation.parent / path) == saved['protectedSha256'][str(curation.parent / path)]
    jar = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    source = Path(__file__).with_name('ghidra_scripts') / 'VerifyAnnotationInventory.java'
    protected = {str(path): digest(path) for path in [jar, source, Path(__file__), curation / 'read1.json',
        curation.parent / 'reference', curation.parent / 'stripped']}
    root = Path(tempfile.mkdtemp(prefix='inventory-', dir=curation))
    print('annotation-inventory-results=' + str(root), flush=True)
    scripts = root / 'scripts'
    scripts.mkdir()
    shutil.copy2(source, scripts / source.name)
    states = [snapshot(curation / 'project')]
    commands = []
    for phase in ('read1', 'read2'):
        command = [str(ghidra / 'support/analyzeHeadless'), str(curation / 'project'), 'Annotations',
            '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', str(scripts),
            '-postScript', source.name, str(root / (phase + '.json'))]
        commands.append(command)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (phase + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=240)
        text = (root / (phase + '.log')).read_text()
        assert result.returncode == 0 and 'annotation-inventory=PASS' in text, phase
        assert 'ERROR REPORT SCRIPT ERROR' not in text and 'error: cannot find symbol' not in text
        states.append(snapshot(curation / 'project'))
    assert states[0] == states[1] == states[2], 'inventory extraction changed the saved project'
    assert (root / 'read1.json').read_bytes() == (root / 'read2.json').read_bytes()
    actual = json.loads((root / 'read1.json').read_text())
    assert Path(unquote(urlsplit(actual['origin']).path)).resolve() == jar.resolve()
    key = lambda row: (row['space'], row['offset'], row['category'])
    fields = ('space', 'offset', 'category', 'text')
    expected_comments = sorted(({field: row[field] for field in fields} for row in expected['comments']), key=key)
    fixture_comments = sorted((row for row in actual['comments'] if row['text'].startswith('FORGE_ANNOTATION:')), key=key)
    assert fixture_comments == expected_comments and len(fixture_comments) == 50
    assert actual['commentAddresses'] == expected['scannedCommentAddresses']
    fields = ('storedName', 'storedValue', 'storedBits', 'references')
    expected_equates = [{field: row[field] for field in fields} for row in expected['equates']]
    reference_key = lambda row: (row['space'], row['offset'], row['operand'], row['dynamicHash'])
    for rows in (expected_equates, actual['equates']):
        for row in rows:
            row['references'].sort(key=reference_key)
        rows.sort(key=lambda row: row['storedName'])
    assert actual['equates'] == expected_equates and len(actual['equates']) == 14
    assert actual['cancellationPoints'] > actual['records'] > 64
    assert protected == {path: digest(Path(path)) for path in protected}
    for index, state in enumerate(states):
        (root / ('project-' + str(index) + '.json')).write_text(json.dumps(state, indent=4) + '\n')
    receipt = {'status': 'PASS_PACKAGED_ANNOTATION_INVENTORY', 'target': saved['target'], 'role': saved['role'],
        'protectedSha256': protected, 'projectUnchanged': True, 'observations': actual,
        'readbackSha256': digest(root / 'read1.json'),
        'limits': 'Packaged raw extraction only. Display-name/type validation, token association, source emission and debugger constants are not established here.'}
    (root / 'result.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print('annotation-inventory=PASS ' + saved['target'] + ' ' + saved['role'])


if __name__ == '__main__':
    main()

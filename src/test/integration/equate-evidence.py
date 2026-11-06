#!/usr/bin/env python3
"""Check packaged equate interpretation against independent saved-program readback."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*')
        if p.is_file() and not p.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('curation', type=Path)
    args = parser.parse_args()
    ghidra, curation = args.ghidra.resolve(strict=True), args.curation.resolve(strict=True)
    expected = json.loads((curation / 'read1.json').read_text())
    root = Path(tempfile.mkdtemp(prefix='equate-evidence-', dir=curation))
    print('equate-evidence-results=' + str(root), flush=True)
    scripts = root / 'scripts'
    scripts.mkdir()
    script = Path(__file__).with_name('ghidra_scripts') / 'VerifyEquateEvidence.java'
    shutil.copy2(script, scripts / script.name)
    jar = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p): digest(p) for p in [script, Path(__file__), jar,
        curation / 'read1.json', curation.parent / 'stripped', curation.parent / 'reference']}
    states = [snapshot(curation / 'project')]
    commands = []
    for phase in ('read1', 'read2'):
        command = list(map(str, [ghidra / 'support/analyzeHeadless', curation / 'project', 'Annotations',
            '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', scripts,
            '-postScript', script.name, root / (phase + '.json')]))
        commands.append(command)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (phase + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
        text = (root / (phase + '.log')).read_text()
        assert 'equate-evidence=PASS' in text and 'ERROR REPORT SCRIPT ERROR' not in text
        states.append(snapshot(curation / 'project'))
    assert states[0] == states[1] == states[2]
    assert (root / 'read1.json').read_bytes() == (root / 'read2.json').read_bytes()
    result = json.loads((root / 'read1.json').read_text())
    assert Path(unquote(urlsplit(result['origin']).path)).resolve() == jar
    actual = {row['storedName']: row for row in result['equates']}
    assert len(actual) == len(expected['equates']) == 14
    for row in expected['equates']:
        observed = actual[row['storedName']]
        assert observed['storedValue'] == row['storedValue']
        if 'enumBytes' in row:
            enum = observed['enumeration']
            assert enum['status'] == 'RESOLVED'
            assert row['displayName'] in enum['memberNames']
            assert enum['value'] == {'bits': row['enumBytes'] * 8, 'signed': row['enumSigned'],
                'value': int(row['storedValue'])}
        fields = ['space', 'offset', 'operand', 'dynamicHash']
        assert [{key: ref[key] for key in fields} for ref in observed['references']] == row['references']
    dynamic, = actual['ANNOTATION_DYNAMIC_ONLY']['references']
    assert dynamic['scalar']['status'] == 'NOT_REQUESTED'
    assert dynamic['dynamic']['value'] == {'bits': expected['resolvedDynamicEquate']['bytes'] * 8,
        'signed': False, 'value': int(expected['resolvedDynamicEquate']['value'])}
    assert protected == {p: digest(Path(p)) for p in protected}
    for i, state in enumerate(states):
        (root / ('project-' + str(i) + '.json')).write_text(json.dumps(state, indent=4) + '\n')
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_PACKAGED_EQUATE_EVIDENCE',
        'observations': result, 'protected': protected, 'readbackSha256': digest(root / 'read1.json'),
        'projectUnchanged': True, 'scope': 'Evidence interpretation only; no emitted debugger constants yet.'}, indent=4) + '\n')
    print('equate-evidence=PASS')


if __name__ == '__main__':
    main()

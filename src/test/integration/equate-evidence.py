#!/usr/bin/env python3
"""Check packaged equate interpretation against independent saved-program readback."""
import argparse
import hashlib
import json
import re
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


def alias_base(name):
    units = name.encode('utf-16-be', errors='surrogatepass')
    payload = b'GhidraDwarfForge:equate-name:v1\0' + (len(units) // 2).to_bytes(8, 'big') + units
    stem = ''.join(chr(int.from_bytes(units[i:i + 2], 'big')) for i in range(0, min(len(units), 48), 2))
    stem = re.sub('[^A-Za-z0-9_]', '_', stem)
    return 'forge_equate_' + stem + '_' + hashlib.sha256(payload).hexdigest()[:20]


def verify_names(result):
    evidence = {row['storedName']: row for row in result['equates']}
    names = set()
    assert len(result['constants']) == len(evidence)
    for entry in result['constants']:
        row = evidence[entry['storedName']]
        raw = int(row['storedValue'])
        views = {'stored': {'bits': 64, 'signed': True, 'value': raw},
            'bits': {'bits': 64, 'signed': False, 'value': raw}}
        if row['enumeration']['value'] is not None:
            views['enum'] = row['enumeration']['value']
        for ref in row['references']:
            for kind in ('scalar', 'dynamic'):
                value = ref[kind]['value']
                if value is not None:
                    key = ('dynamic_bits' if kind == 'dynamic' else 'operand_' + ('s' if value['signed'] else 'u'))
                    views[key + str(value['bits'])] = value
        if entry['directReason'] == 'DIRECT_TYPED_VALUE':
            assert row['enumeration']['memberNames'] == ['ANNOTATION_NEGATIVE']
            views['typed'] = row['enumeration']['value']
        assert {c['view']: c['value'] for c in entry['constants']} == views
        for constant in entry['constants']:
            expected = 'ANNOTATION_NEGATIVE' if constant['direct'] else alias_base(entry['storedName']) + '_' + constant['view']
            assert constant['name'] == expected
            assert expected not in names
            names.add(expected)
    assert result['constantCount'] == len(names) and result['directCount'] == 1
    assert result['identityControls'] == [alias_base(s) for s in ('\ud800', '\ud801', '\ufffd', 'é', 'e\u0301')]


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
    (root / 'project-0.json').write_text(json.dumps(states[0], indent=4) + '\n')
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
        (root / ('project-' + str(len(states) - 1) + '.json')).write_text(json.dumps(states[-1], indent=4) + '\n')
    assert states[0] == states[1] == states[2]
    assert (root / 'read1.json').read_bytes() == (root / 'read2.json').read_bytes()
    result = json.loads((root / 'read1.json').read_text())
    verify_names(result)
    assert Path(unquote(urlsplit(result['origin']).path)).resolve() == jar.resolve()
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
        'projectUnchanged': True, 'scope': 'Evidence interpretation and constant name planning; no emitted debugger constants yet.'}, indent=4) + '\n')
    print('equate-evidence=PASS')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Exercise installed default export, stored comments, real types and atomic limit failures."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*')
        if p.is_file() and not p.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'curation', 'consumer', 'producer'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--placement-control', type=Path,
        help='successful controlled placement export for exact unannotated GDB warning comparison')
    args = parser.parse_args()
    ghidra, curation = args.ghidra.resolve(strict=True), args.curation.resolve(strict=True)
    reference = curation.parent
    harness = Path(__file__).resolve().parent
    saved = json.loads((curation / 'read1.json').read_text())
    receipt = json.loads((curation / 'result.json').read_text())
    assert receipt['status'] == 'PASS_SAVED_ANNOTATIONS'
    root = Path(tempfile.mkdtemp(prefix='default-export-', dir=curation))
    print('annotation-default-export-results=' + str(root), flush=True)
    original_project = snapshot(curation / 'project')
    project = root / 'project'
    shutil.copytree(curation / 'project', project)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    protected_paths = [reference / 'stripped', reference / 'reference', reference / 'labels.json',
        curation / 'read1.json', args.consumer, args.producer, module / 'lib/GhidraDwarfForge.jar',
        module / 'ghidra_scripts/GhidraDwarfForge.java', Path(__file__),
        harness / 'annotation-default-gdb.py', harness / 'annotation-default-gdb.sh']
    protected = {str(p): digest(p) for p in protected_paths}
    output = root / 'forge.dbg'
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        assert result.returncode == 0, (label, result.returncode)
        return (root / (label + '.log')).read_text()

    command = [ghidra / 'support/analyzeHeadless', project, 'Annotations',
        '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', module / 'ghidra_scripts',
        '-postScript', 'GhidraDwarfForge.java', '--input', reference / 'stripped', '--output', output,
        '--libdwarf', args.consumer, '--libdwarfp', args.producer]
    generations, states = [], [snapshot(project)]
    for phase in ('read1', 'read2'):
        log = run(phase, command)
        assert 'GhidraDwarfForge symbol export PASS' in log
        assert 'ERROR REPORT SCRIPT ERROR' not in log
        generations.append({name: digest(root / name) for name in ('forge.dbg', 'forge.dbg.c')})
        states.append(snapshot(project))
    assert generations[0] == generations[1]
    changed = [n for n in states[0].keys() | states[1].keys() if states[0].get(n) != states[1].get(n)]
    assert set(changed) <= {'Annotations.rep/idata/~index.bak', 'Annotations.rep/idata/~journal.bak'}
    assert states[1] == states[2]
    for i, state in enumerate(states):
        (root / ('project-' + str(i) + '.json')).write_text(json.dumps(state, indent=4) + '\n')
    rows = (root / 'forge.dbg.c').read_text().splitlines()
    expected = {'Ghidra listing comment ' + r['category'] + ' at ' + r['space'] + ':0x' + r['offset']: r['text']
        for r in saved['comments']}
    seen, inserted = set(), set()
    for index, row in enumerate(rows):
        if not row.startswith('/* Ghidra listing comment '):
            continue
        heading = json.loads('"' + row[3:-3].replace('"', '\\"') + '"')
        key = heading.rsplit(' [', 1)[0]
        if key not in expected:
            continue
        assert key not in seen
        seen.add(key)
        count = expected[key].count('\n') + 1
        payload = ''.join(json.loads('"' + text[3:-3].replace('"', '\\"') + '"')
            for text in rows[index + 1:index + 1 + count])
        assert payload == expected[key], key
        inserted.update(range(index + 1, index + count + 2))
    assert seen == expected.keys() and len(seen) == 50
    for view in ('info', 'abbrev', 'aranges', 'decodedline'):
        text = run(view, ['readelf', '--debug-dump=' + view, output])
        assert not re.search(r'(?im)(warning:|error:)', text)
    run('identity', ['readelf', '-hSWn', reference / 'stripped', output])
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', output])
    run('strict', ['python3', harness / 'check-dwarfdump.py', output, root / 'dwarfdump.log',
        '--original', reference / 'stripped'])
    raw = [(int(m[2], 16), int(m[1])) for m in re.finditer(r'(?m)^\S+\s+(\d+)\s+(0x[0-9a-fA-F]+)\b',
        (root / 'decodedline.log').read_text())]
    assert raw and all(line not in inserted for _, line in raw)
    (root / 'comment-lines.json').write_text(json.dumps(sorted(inserted)) + '\n')
    gdb = run('gdb', ['bash', harness / 'annotation-default-gdb.sh', root, reference, receipt['target']])
    assert 'annotation-default-gdb=PASS' in gdb
    warnings = re.findall(r'(?m)^warning:.*$', gdb)
    compiler_warnings = re.findall(r'(?m)^warning:.*$', (reference / 'gdb.stdout').read_text() +
        (reference / 'gdb.stderr').read_text())
    control_warnings = []
    if args.placement_control:
        control = args.placement_control.resolve(strict=True)
        prior = json.loads((control / 'result.json').read_text())
        assert prior['status'] == 'PASS_SAVED_COMMENT_PLACEMENT'
        assert prior['protected'][str(reference / 'stripped')] == digest(reference / 'stripped')
        assert prior['generations'][-1]['baseline.dbg'] == digest(control / 'baseline.dbg')
        control_warnings = re.findall(r'(?m)^warning:.*$', (control / 'baseline-gdb.log').read_text())
    assert warnings == (control_warnings if args.placement_control else compiler_warnings), warnings
    failures = {
        'records': ('--annotation-record-limit=0', 'record'),
        'text': ('--annotation-text-limit=0', 'text'),
        'source': ('--annotation-source-limit=1', 'budget'),
        'invalid': ('--annotation-source-limit=-1', 'decimal integer'),
    }
    for label, (option, message) in failures.items():
        log = run('limit-' + label, command + [option])
        assert 'GhidraDwarfForge symbol export PASS' not in log
        assert 'FATAL' in log and message in log
        assert generations[1] == {name: digest(root / name) for name in generations[1]}
    assert original_project == snapshot(curation / 'project')
    assert states[-1] == snapshot(project)
    assert protected == {p: digest(Path(p)) for p in protected}
    result = {'status': 'PASS_INSTALLED_DEFAULT_COMMENTS', 'target': receipt['target'],
        'role': receipt['role'], 'comments': len(seen), 'rawLineRows': len(raw),
        'generations': generations, 'protected': protected, 'limitFailures': list(failures),
        'originalProjectUnchanged': True, 'firstReopenBackupChanges': changed,
        'warnings': warnings, 'compilerWarnings': compiler_warnings,
        'placementControl': str(args.placement_control) if args.placement_control else None}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('annotation-default-export=PASS ' + receipt['target'])


if __name__ == '__main__':
    main()

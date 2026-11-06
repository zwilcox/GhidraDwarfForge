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
    parser.add_argument('--equate-evidence', type=Path, help='independently validated saved-equate planner observations')
    parser.add_argument('--source-context', choices=['off', 'assembly', 'pcode', 'both'], default='off')
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
        harness / 'annotation-default-gdb.py', harness / 'annotation-default-gdb.sh',
        harness / 'ghidra_scripts/CancelDuringAnnotations.java']
    protected = {str(p): digest(p) for p in protected_paths}
    if args.equate_evidence:
        protected[str(args.equate_evidence.resolve())] = digest(args.equate_evidence)
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
    if args.source_context != 'off':
        command += ['--source-context=' + args.source_context]
    generations, states = [], [snapshot(project)]
    for phase in ('read1', 'read2'):
        log = run(phase, command)
        assert 'GhidraDwarfForge symbol export PASS' in log
        assert 'ERROR REPORT SCRIPT ERROR' not in log
        script_origin, = re.findall(r'(?m)^INFO  SCRIPT: (.+GhidraDwarfForge\.java) \(HeadlessAnalyzer\)', log)
        assert Path(script_origin).resolve() == (module / 'ghidra_scripts/GhidraDwarfForge.java').resolve(), script_origin
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
    context_lines = set()
    if args.source_context != 'off':
        for index, row in enumerate(rows):
            if not row.startswith('/* Ghidra instruction context '):
                continue
            end = index
            while end < len(rows) and rows[end].startswith('/* ') and rows[end].endswith(' */'):
                context_lines.add(end + 1)
                end += 1
        assert context_lines, 'fixture did not exercise optional context'
        inserted.update(context_lines)
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
    equate_count = 0
    if args.equate_evidence:
        observations = json.loads(args.equate_evidence.read_text())
        constants = [c for e in observations['constants'] for c in e['constants']]
        assert len(constants) == 35
        heading = '/* Ghidra equate (synthetic lookup; no storage or lifetime) */'
        start = rows.index(heading)
        assert rows.count(heading) == len(saved['equates']) == 14
        decoded = ''.join(json.loads('"' + row[3:-3].replace('"', '\\"') + '"')
            for row in rows[start:] if row != heading)
        for entry in observations['constants']:
            assert 'Stored name: ' + entry['storedName'] + '\n' in decoded
            assert 'Direct lookup: ' + entry['directReason'] + '\n' in decoded
            for constant in entry['constants']:
                value = constant['value']
                number = value['value'] if value['signed'] else value['value'] & ((1 << value['bits']) - 1)
                text = ('Lookup ' + constant['name'] + ' [' + constant['view'] + '; ' +
                    ('signed ' if value['signed'] else 'unsigned ') + str(value['bits']) + ' bits] = ' + str(number) + '\n')
                assert text in decoded, text
        def value_text(value):
            number = value['value'] if value['signed'] else value['value'] & ((1 << value['bits']) - 1)
            return ('signed ' if value['signed'] else 'unsigned ') + str(value['bits']) + ' bits = ' + str(number)

        def resolution_text(resolution):
            value = resolution.get('value')
            return resolution['status'] + (' [' + value_text(value) + ']' if value is not None else '')

        for equate in observations['equates']:
            enum = equate['enumeration']
            if enum.get('value') is not None:
                assert 'Enum value: ' + value_text(enum['value']) + '\n' in decoded
            for observation in equate['references']:
                expected = ('Reference ' + observation['space'] + ':0x' + observation['offset'] +
                    ' operand=' + str(observation['operand']) + ' dynamicHash=0x' + format(int(observation['dynamicHash']), 'x') + '\n' +
                    'Operand evidence: ' + resolution_text(observation['scalar']) +
                    '; high-p-code evidence: ' + resolution_text(observation['dynamic']) + '\n')
                assert expected in decoded, expected
        inserted.update(range(start + 1, len(rows) + 1))
        (root / 'equate-expected.json').write_text(json.dumps(constants, indent=4) + '\n')
        equate_count = len(constants)
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
    cancellation_stages = 0
    if args.equate_evidence:
        scripts = root / 'scripts'
        scripts.mkdir()
        shutil.copy2(harness / 'ghidra_scripts/CancelDuringAnnotations.java', scripts)
        cancel = run('cancellation', [ghidra / 'support/analyzeHeadless', project, 'Annotations',
            '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath',
            str(scripts) + ';' + str(module / 'ghidra_scripts'), '-postScript', 'CancelDuringAnnotations.java',
            reference / 'stripped', output, args.consumer, args.producer, args.source_context])
        expected_stages = 7 if args.source_context == 'off' else 11
        assert 'annotation-cancellation-recovery=PASS stages=' + str(expected_stages) in cancel
        assert cancel.count('annotation-cancellation-stage=PASS ') == expected_stages
        reports = [json.loads(m[1]) for m in re.finditer(r'GhidraDwarfForge report: (\{.*\}) \(GhidraScript\)', cancel)]
        assert [r['status'] for r in reports[:-1]] == ['CANCELLED'] * expected_stages
        assert reports[-1]['status'] in ('SUCCESS', 'PARTIAL') and 'FATAL' not in cancel
        assert generations[1] == {name: digest(root / name) for name in generations[1]}
        cancellation_stages = expected_stages
    assert original_project == snapshot(curation / 'project')
    assert states[-1] == snapshot(project)
    assert protected == {p: digest(Path(p)) for p in protected}
    result = {'status': 'PASS_INSTALLED_DEFAULT_COMMENTS', 'target': receipt['target'],
        'role': receipt['role'], 'comments': len(seen), 'rawLineRows': len(raw),
        'equateConstants': equate_count, 'cancellationStages': cancellation_stages,
        'sourceContext': args.source_context, 'contextRows': len(context_lines),
        'generations': generations, 'protected': protected, 'limitFailures': list(failures),
        'originalProjectUnchanged': True, 'firstReopenBackupChanges': changed,
        'warnings': warnings, 'compilerWarnings': compiler_warnings,
        'placementControl': str(args.placement_control) if args.placement_control else None}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('annotation-default-export=PASS ' + receipt['target'])


if __name__ == '__main__':
    main()

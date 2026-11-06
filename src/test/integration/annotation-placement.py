#!/usr/bin/env python3
"""Validate saved comments, actual native source association and controlled exported sidecars."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def inspect(case, saved):
    observed = json.loads((case / 'forge.dbg.placement.json').read_text())
    baseline, composed = observed['baseline'], observed['composed']
    original = bytes(n & 255 for n in baseline['utf8'])
    source = bytes(n & 255 for n in composed['utf8'])
    assert source == (case / 'forge.dbg.c').read_bytes()
    assert b'FORGE_ANNOTATION:' not in original
    rows = source.splitlines(keepends=True)
    inserted = set(observed['annotationLines'])
    assert b''.join(row for number, row in enumerate(rows, 1) if number not in inserted) == original
    inverse = {number: number - sum(extra < number for extra in inserted)
        for number in range(1, len(rows) + 1) if number not in inserted}
    for old, new in zip(baseline['functions'], composed['functions'], strict=True):
        assert dict(new, startLine=inverse[new['startLine']], endLine=inverse[new['endLine']]) == old
    for old, new in zip(baseline['mappedLines'], composed['mappedLines'], strict=True):
        assert dict(new, line=inverse[new['line']]) == old
    for old, new in zip(baseline['functionTokens'], composed['functionTokens'], strict=True):
        assert dict(new, lines=[dict(row, line=inverse[row['line']]) for row in new['lines']]) == old
    fixture = [row for row in observed['placements'] if row['text'].startswith('FORGE_ANNOTATION:')]
    key = lambda row: (row['space'], row['offset'], row['category'])
    fields = ('space', 'offset', 'category', 'text')
    assert sorted(({field: row[field] for field in fields} for row in fixture), key=key) == sorted(
        ({field: row[field] for field in fields} for row in saved['comments']), key=key)
    assert len(fixture) == 50
    for row in fixture:
        role = row['text'].split(':')[1]
        if role in ('overlay', 'external', 'register', 'stack'):
            assert row['reason'] == 'NON_DEFAULT_SPACE' and row['beforeLine'] == 0
        if role in ('data', 'unmapped', 'body-gap', 'failed-function'):
            assert row['beforeLine'] == 0 and row['elfInstruction'] is None
    linked = [row for row in observed['placements'] if row['beforeLine']]
    positive = [row for row in linked if row['text'].startswith('FORGE_TOKEN_POSITIVE:')]
    assert len(positive) == 2 and {row['category'] for row in positive} == {'EOL', 'PRE'}
    assert len({row['elfInstruction'] for row in positive}) == 1
    for row in linked:
        assert row['reason'] == 'TOKEN_LINE'
        assert any(token['line'] == row['beforeLine'] and row['elfInstruction'] in token['addresses']
            for function in baseline['functionTokens'] for token in function['lines'])
    # Decode the actual displayed payload independently of the renderer. Quotes
    # need JSON quoting here because the C-comment field need not escape them.
    decoded = []
    for number in sorted(inserted):
        line = rows[number - 1].decode('utf-8')
        assert line.startswith('/* ') and line.endswith(' */\n')
        decoded.append(json.loads('"' + line[3:-4].replace('"', '\\"') + '"'))
    expected_payloads = {
        'Ghidra listing comment ' + row['category'] + ' at ' + row['space'] + ':0x' + row['offset'] +
            ' [' + row['reason'] + ']': row['text'] for row in observed['placements']}
    assert len(expected_payloads) == len(observed['placements'])
    payloads = []
    seen = set()
    index = 0
    while index < len(decoded):
        heading = decoded[index]
        index += 1
        if heading == 'Ghidra listing comment encoding':
            assert decoded[index].startswith('Payloads preserve stored text:')
            index += 1
            continue
        assert heading in expected_payloads and heading not in seen
        seen.add(heading)
        expected = expected_payloads[heading]
        count = expected.count('\n') + 1
        payload = ''.join(decoded[index:index + count])
        assert payload == expected
        payloads.append(payload)
        index += count
    assert seen == expected_payloads.keys()
    assert sorted(payloads) == sorted(row['text'] for row in observed['placements'])
    raw_lines = [(int(match[2], 16), int(match[1])) for match in re.finditer(
        r'(?m)^\S+\s+(\d+)\s+(0x[0-9a-fA-F]+)\b', (case / 'decodedline.log').read_text())]
    assert raw_lines and all(line not in inserted for _, line in raw_lines)
    mapped = {(pc, row['line']) for row in composed['mappedLines'] for pc in row['addresses']}
    assert set(raw_lines) <= mapped
    failure, = [row for row in composed['functions'] if row['name'] == 'annotation_failure']
    assert not failure['decompiled'] and 'maximum allowable instructions' in failure['failureDiagnostic']
    assert len(observed['nativeFailures']) == 1
    spec = importlib.util.spec_from_file_location('emission', Path(__file__).with_name('emission-evidence.py'))
    emission = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(emission)
    dies = emission.dies((case / 'info.log').read_text())
    failed_die, = [die for die in dies.values() if die['name'] == 'annotation_failure' and die['tag'] == 'DW_TAG_subprogram']
    assert not {'decl_file', 'decl_line', 'type'} & failed_die['attributes'].keys()
    assert not failed_die['children']
    return {'fixtureComments': 50, 'allComments': len(payloads), 'placedAtTokenLine': len(linked),
        'catalogComments': len(payloads) - len(linked), 'insertedRows': len(inserted),
        'rawExecutableRows': len(raw_lines), 'nativeFailure': failure['failureDiagnostic']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('curation', type=Path)
    parser.add_argument('consumer', type=Path)
    parser.add_argument('producer', type=Path)
    args = parser.parse_args()
    ghidra, curation = args.ghidra.resolve(strict=True), args.curation.resolve(strict=True)
    harness = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('preparation', harness / 'analyst-annotations-prepare.py')
    preparation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preparation)
    digest, snapshot = preparation.digest, preparation.snapshot
    saved = json.loads((curation / 'result.json').read_text())
    assert saved['status'] == 'PASS_SAVED_ANNOTATIONS'
    root = Path(tempfile.mkdtemp(prefix='placement-', dir=curation))
    print('annotation-placement-results=' + str(root), flush=True)
    scripts = root / 'scripts'
    scripts.mkdir()
    script = harness / 'ghidra_scripts/ExportAnnotationPlacement.java'
    shutil.copy2(script, scripts / script.name)
    seed = harness / 'ghidra_scripts/SeedAnnotationTokenComments.java'
    shutil.copy2(seed, scripts / seed.name)
    original, labels = curation.parent / 'stripped', curation.parent / 'labels.json'
    jar = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(path): digest(path) for path in [original, labels, jar, script, seed, Path(__file__),
        harness / 'annotation-placement-gdb.py', harness / 'annotation-placement-gdb.sh',
        args.consumer, args.producer, curation / 'read1.json', curation.parent / 'reference',
        curation.parent / 'gdb.stdout', harness / 'emission-evidence.py']}
    assert digest(original) == saved['protectedSha256'][str(original)]
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)

    original_project = snapshot(curation / 'project')
    project = root / 'project'
    shutil.copytree(curation / 'project', project)
    run('seed', [ghidra / 'support/analyzeHeadless', project, 'Annotations',
        '-process', 'stripped', '-noanalysis', '-scriptPath', scripts,
        '-postScript', seed.name, root / 'seed.json'])
    assert 'annotation-token-seed=PASS' in (root / 'seed.log').read_text()
    states, generations = [snapshot(project)], []
    for phase in ('read1', 'read2'):
        run(phase, [ghidra / 'support/analyzeHeadless', project, 'Annotations',
            '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', scripts,
            '-postScript', script.name, labels, original, root / 'forge.dbg', args.consumer, args.producer])
        log = (root / (phase + '.log')).read_text()
        assert 'annotation-placement=PASS' in log and 'ERROR REPORT SCRIPT ERROR' not in log, phase
        states.append(snapshot(project))
        generations.append({name: digest(root / name) for name in ['forge.dbg', 'forge.dbg.c', 'forge.dbg.placement.json',
            'baseline.dbg', 'baseline.dbg.c']})
    changed = [name for name in states[0].keys() | states[1].keys() if states[0].get(name) != states[1].get(name)]
    assert set(changed) <= {'Annotations.rep/idata/~index.bak', 'Annotations.rep/idata/~journal.bak'}, changed
    assert states[1] == states[2]
    assert original_project == snapshot(curation / 'project')
    assert generations[0] == generations[1], 'independent saved-project export changed output'
    for view in ['info', 'abbrev', 'aranges', 'decodedline']:
        run(view, ['readelf', '--debug-dump=' + view, root / 'forge.dbg'])
        assert not re.search(r'(?im)(warning:|error:)', (root / (view + '.log')).read_text())
    run('identity', ['readelf', '-hSWn', original, root / 'forge.dbg'])
    run('llvm', ['llvm-dwarfdump', '--verify', root / 'forge.dbg'])
    assert 'No errors.' in (root / 'llvm.log').read_text()
    run('strict', ['python3', harness / 'check-dwarfdump.py', root / 'forge.dbg', root / 'dwarfdump.log', '--original', original])
    for view in ['info', 'abbrev', 'aranges', 'decodedline']:
        run('baseline-' + view, ['readelf', '--debug-dump=' + view, root / 'baseline.dbg'])
        assert not re.search(r'(?im)(warning:|error:)', (root / ('baseline-' + view + '.log')).read_text())
    run('baseline-identity', ['readelf', '-hSWn', root / 'baseline.dbg'])
    run('baseline-llvm', ['llvm-dwarfdump', '--verify', root / 'baseline.dbg'])
    assert 'No errors.' in (root / 'baseline-llvm.log').read_text()
    run('baseline-strict', ['python3', harness / 'check-dwarfdump.py', root / 'baseline.dbg',
        root / 'baseline-dwarfdump.log', '--original', original])
    checked = inspect(root, json.loads((curation / 'read1.json').read_text()))
    run('gdb', ['bash', harness / 'annotation-placement-gdb.sh', root, curation.parent, saved['target']])
    assert 'annotation-placement-gdb=PASS' in (root / 'gdb.log').read_text()
    debugger = json.loads((root / 'gdb-observation.json').read_text())
    assert debugger['status'] == 'PASS'
    run('baseline-gdb', ['bash', harness / 'annotation-placement-gdb.sh', root, curation.parent, saved['target'], 'baseline'])
    assert 'annotation-placement-gdb=PASS' in (root / 'baseline-gdb.log').read_text()
    warnings = re.findall(r'(?m)^warning:.*$', (root / 'gdb.log').read_text())
    baseline_warnings = re.findall(r'(?m)^warning:.*$', (root / 'baseline-gdb.log').read_text())
    assert warnings == baseline_warnings, (warnings, baseline_warnings)
    compiler_warnings = re.findall(r'(?m)^warning:.*$', (curation.parent / 'gdb.stdout').read_text() +
        (curation.parent / 'gdb.stderr').read_text())
    for warning in warnings:
        if warning in compiler_warnings:
            continue
        missing = re.fullmatch(r"warning: GDB can't find the start of the function at (0x[0-9a-f]+)\.", warning)
        assert missing and saved['target'].startswith('mips32'), warning
        reference_labels = json.loads(labels.read_text())
        assert reference_labels['annotation_gap_begin']['address'] <= int(missing[1], 16) < reference_labels['annotation_gap_end']['address']
    assert protected == {path: digest(Path(path)) for path in protected}
    result = {'status': 'PASS_SAVED_COMMENT_PLACEMENT', 'target': saved['target'], 'role': saved['role'],
        'checks': checked, 'debugger': debugger, 'baselineMatchedWarnings': warnings, 'compilerWarnings': compiler_warnings,
        'protected': protected,
        'generations': generations, 'originalProjectUnchanged': True, 'firstReopenBackupChanges': changed,
        'limits': 'Controlled production API composition/export with real native failure and GDB source lookup. Default GUI/headless entry point, types/variables and debugger equates are not established here.'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('annotation-placement=PASS ' + saved['target'] + ' ' + saved['role'])


if __name__ == '__main__':
    main()

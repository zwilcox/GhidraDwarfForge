#!/usr/bin/env python3
"""Real Ghidra rebase/curation/rename exports, raw DWARF, runtime and CLI comparison."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def union(ranges):
    result = []
    for start, end in sorted(ranges):
        if result and start <= result[-1][1]:
            result[-1][1] = max(result[-1][1], end)
        else:
            result.append([start, end])
    return result


def location_lists(text):
    result, offset, rows = {}, None, []
    for line in text.splitlines():
        match = re.fullmatch(r'\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)(?:\s+.*)?', line)
        if match:
            current, start, end = (int(value, 16) for value in match.groups())
            if offset is None:
                offset = current
            assert start < end
            rows.append([start, end])
        elif '<End of list>' in line:
            assert offset is not None and offset not in result
            result[offset], offset, rows = union(rows), None, []
    assert offset is None
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('lexical_case', type=Path)
    args = parser.parse_args()
    ghidra, case = args.ghidra.resolve(strict=True), args.lexical_case.resolve(strict=True)
    harness = Path(__file__).resolve().parent
    accepted = json.loads((case / 'acceptance.json').read_text())
    assert accepted['status'] == 'LEXICAL_SHADOW_PASS' and not accepted['calls'] and not accepted['discontiguous']
    target = accepted['target']
    work = Path(tempfile.mkdtemp(prefix='coverage-curation-', dir=case))
    print('coverage-curation-results=' + str(work), flush=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    protected = {str(path): digest(path) for path in [case / name for name in
        ['stripped', 'reference', 'forge.dbg', 'forge.dbg.c', 'labels.json', 'compiler-storage.json', 'prepared.json']] +
        [module / 'lib/GhidraDwarfForge.jar', module / 'ghidra_scripts/GhidraDwarfForge.java', Path(__file__),
         harness / 'ghidra_scripts/CoverageCurationComparison.java', harness / 'coverage-curation-gdb.py']}
    project = case / 'project'
    project_before = {str(path): digest(path) for path in project.rglob('*') if path.is_file() and not path.name.endswith('.lock')}
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (work / (label + '.log')).open('w') as output:
            subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=300)

    run('export', [ghidra / 'support/analyzeHeadless', project, 'Lexical', '-process', 'stripped', '-readOnly', '-noanalysis',
        '-scriptPath', harness / 'ghidra_scripts', '-postScript', 'CoverageCurationComparison.java', case / 'stripped',
        case / 'labels.json', work / 'exports'])
    log = (work / 'export.log').read_text()
    assert 'coverage-curation-export=PASS phases=4' in log
    reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in log.splitlines() if 'GhidraDwarfForge report: ' in line]
    assert len(reports) == 4
    labels = json.loads((case / 'labels.json').read_text())
    spec = importlib.util.spec_from_file_location('emission_oracle', harness / 'emission-evidence.py')
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    phases = ['before', 'rebased', 'curated', 'renamed']
    by_phase = dict(zip(phases, reports, strict=True))
    raw_inner = {}
    expected_warnings = Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in
        (case / 'compiler-gdb.log').read_text().splitlines() if re.match(r'\s*(warning:|error:)', line, re.I))
    for phase, report in by_phase.items():
        sidecar = work / 'exports' / (phase + '.dbg')
        assert report['schemaVersion'] == 2 and report['coverage']['definitionVersion'] == 2
        assert report['status'] in ['SUCCESS', 'PARTIAL'] and report['validation'] == {'status': 'NOT_RUN'}
        for role, path in [('input', case / 'stripped'), ('output', sidecar), ('source', Path(str(sidecar) + '.c'))]:
            assert report['artifacts'][role + 'Path'] == str(path) and report['artifacts'][role + 'Sha256'] == digest(path)
        (work / (phase + '.json')).write_text(json.dumps(report, separators=(',', ':')) + '\n')
        for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
            run(phase + '-' + view, ['readelf', '--debug-dump=' + view, sidecar])
            assert 'Warning:' not in (work / (phase + '-' + view + '.log')).read_text()
        run(phase + '-elf', ['readelf', '-hSWn', sidecar])
        run(phase + '-llvm', ['llvm-dwarfdump', '--verify', sidecar])
        assert 'No errors.' in (work / (phase + '-llvm.log')).read_text()
        run(phase + '-strict', ['python3', harness / 'check-dwarfdump.py', sidecar, work / (phase + '-dwarfdump.log'),
            '--original', case / 'stripped'])
        entries = oracle.dies((work / (phase + '-info.log')).read_text())
        inner = [node for node in entries.values() if node['tag'] == 'DW_TAG_lexical_block' and
            node['attributes'].get('low_pc') == hex(labels['inner_begin'])]
        assert len(inner) == 1
        assert int(inner[0]['attributes']['high_pc']) == labels['inner_end'] - labels['inner_begin']
        variables = [node for node in inner[0]['children'] if node['tag'] == 'DW_TAG_variable' and node['name'] == 'shadow']
        assert len(variables) == 1
        location = variables[0]['attributes'].get('location')
        if phase in ('before', 'rebased'):
            offset = re.fullmatch(r'(0x[0-9a-f]+) \(location list\)', location)
            assert offset
            raw_inner[phase] = location_lists((work / (phase + '-loc.log')).read_text())[int(offset[1], 16)]
            assert raw_inner[phase] and all(labels['inner_live'] <= start < end <= labels['inner_end'] for start, end in raw_inner[phase])
        else:
            assert location is None, 'curated unsupported definition fabricated a location'
            raw_inner[phase] = []
        row, = [v for v in report['coverage']['variables'] if v['function'] == hex(labels['scoped']) and v['block'] == 'inner']
        assert row['displayName'] == 'shadow' and row['internalName'] == ('edited_inner' if phase == 'renamed' else 'shadow_1')
        assert row['location']['locatedRanges'] == [[hex(start), hex(end)] for start, end in raw_inner[phase]]
        assert row['location']['knownScopeRanges'] == [[hex(labels['inner_begin']), hex(labels['inner_end'])]]
        assert row['location']['coveredScopeBytes'] == str(sum(end - start for start, end in raw_inner[phase]))
        run(phase + '-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, target, phase, sidecar, harness / 'coverage-curation-gdb.py'])
        assert 'coverage-curation-gdb=' + phase + ' PASS' in (work / (phase + '-gdb.log')).read_text()
        warnings = Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in (work / (phase + '-gdb.log')).read_text().splitlines()
            if re.match(r'\s*(warning:|error:)', line, re.I))
        assert warnings == expected_warnings
    assert raw_inner['before'] == raw_inner['rebased']
    java = os.environ.get('JAVA_BIN') or str(Path(os.environ['JAVA_HOME']) / 'bin/java')
    launcher = module / 'support/ghidra-dwarf-forge-report'
    for phase, previous in [('rebased', 'before'), ('curated', 'rebased'), ('renamed', 'curated')]:
        run(phase + '-compare', [launcher, '--ghidra-dir=' + str(ghidra), '--extension-dir=' + str(module), '--java=' + java,
            '--report=' + str(work / (phase + '.json')), '--before=' + str(work / (previous + '.json'))])
    rebase_changes = [line for line in (work / 'rebased-compare.log').read_text().splitlines() if '\t' + hex(labels['scoped']) + '\t' in line]
    assert not rebase_changes, rebase_changes
    lost = [line for line in (work / 'curated-compare.log').read_text().splitlines()
        if line.startswith('VARIABLE_COMMON_SCOPE_COVERAGE_LOST\t' + hex(labels['scoped']) + '\t') and 'block="inner"' in line]
    expected = {f'[0x{start:x},0x{end:x})' for start, end in raw_inner['rebased']}
    assert {line.rsplit('; ', 1)[-1] for line in lost} == expected, (lost, expected)
    renamed = (work / 'renamed-compare.log').read_text()
    assert 'VARIABLE_BINDING_REMOVED' in renamed and 'VARIABLE_BINDING_ADDED' in renamed and 'edited_inner' in renamed
    assert 'does not prove declaration lineage' in renamed and 'no declaration identity inferred' in renamed
    assert protected == {name: digest(Path(name)) for name in protected}
    project_after = {str(path): digest(path) for path in project.rglob('*') if path.is_file() and not path.name.endswith('.lock')}
    changed = {name for name in project_before.keys() | project_after.keys() if project_before.get(name) != project_after.get(name)}
    assert changed <= {str(project / 'Lexical.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
    result = {'status': 'PASS', 'target': target, 'role': accepted['role'], 'phases': phases, 'rawInnerLocations': raw_inner,
        'protected': protected, 'projectBackupChanges': sorted(changed), 'scope': 'real in-memory Ghidra rebase, saved use-site edit and rename; production exports, independent raw DWARF, native/QEMU GDB and CLI comparison'}
    (work / 'acceptance.json').write_text(json.dumps(result, indent=4) + '\n')
    print('coverage-curation=PASS', flush=True)


if __name__ == '__main__':
    main()

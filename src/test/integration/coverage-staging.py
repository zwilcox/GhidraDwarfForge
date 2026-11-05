#!/usr/bin/env python3
"""Exercise the installed production report boundary using a validated lexical fixture."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('lexical_case', type=Path)
    args = parser.parse_args()
    ghidra, case = args.ghidra.resolve(strict=True), args.lexical_case.resolve(strict=True)
    harness = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('report_claims', harness / 'export-report-claims.py')
    claims = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(claims)
    baseline = json.loads((case / 'acceptance.json').read_text())
    assert baseline['status'] == 'LEXICAL_SHADOW_PASS'
    target = baseline['target']
    work = Path(tempfile.mkdtemp(prefix='coverage-staging-', dir=case))
    print('coverage-staging-results=' + str(work), flush=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    protected_paths = [case / name for name in ('stripped', 'reference', 'forge.dbg', 'forge.dbg.c', 'compiler-gdb.log')]
    protected_paths += [module / 'lib/GhidraDwarfForge.jar', module / 'ghidra_scripts/GhidraDwarfForge.java',
        harness / 'ghidra_scripts/CoverageStagingControls.java', Path(__file__)]
    protected = {str(p): digest(p) for p in protected_paths}
    project = case / 'project'
    before = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
    commands = []

    def run(label, command, timeout=240):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (work / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=timeout)

    run('export', [ghidra / 'support/analyzeHeadless', project, 'Lexical', '-process', 'stripped',
        '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts',
        '-postScript', 'CoverageStagingControls.java', case / 'stripped', work / 'outputs'])
    log = (work / 'export.log').read_text()
    assert 'coverage-staging-controls=PASS controls=16' in log
    markers = [line.split('coverage-staging-control=PASS ', 1)[1].split(' (GhidraScript)')[0]
        for line in log.splitlines() if 'coverage-staging-control=PASS ' in line]
    assert len(markers) == len(set(markers)) == 16
    expected = {f'mode={mode} phase={phase} outcome={outcome}'
        for mode in ('pair', 'companion') for phase in ('capture', 'assembly', 'writer', 'reader')
        for outcome in ('FATAL', 'CANCELLED')}
    assert {marker.split(' polls=')[0] for marker in markers} == expected
    reports = [claims.DECODER.raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in log.splitlines() if 'GhidraDwarfForge report: ' in line]
    statuses = Counter(report['status'] for report in reports)
    assert len(reports) == 20 and statuses['FATAL'] == statuses['CANCELLED'] == 8
    for index, report in enumerate(reports):
        assert report['schemaVersion'] == 2 and report['validation'] == {'status': 'NOT_RUN'}
        if report['status'] in ('FATAL', 'CANCELLED'):
            assert report['coverage'] is None and report['artifacts'] is None and report['failure']
        else:
            claims.claims(report)
            for kind in ('input', 'output', 'source'):
                path = Path(report['artifacts'][kind + 'Path'])
                assert path.is_absolute() and digest(path) == report['artifacts'][kind + 'Sha256']
                assert not path.name.endswith('.staged')
        (work / f'report-{index:02}.json').write_text(json.dumps(report, separators=(',', ':')) + '\n')
    shutil.copyfile(case / 'compiler-gdb.log', work / 'compiler-gdb.log')
    for mode in ('pair', 'companion'):
        output = work / 'outputs' / mode / 'forge.dbg'
        run(mode + '-elf', ['readelf', '-hSWn', output])
        for view in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc'):
            run(mode + '-' + view, ['readelf', '--debug-dump=' + view, output])
            assert 'Warning:' not in (work / (mode + '-' + view + '.log')).read_text()
        run(mode + '-llvm', ['llvm-dwarfdump', '--verify', output])
        assert 'No errors.' in (work / (mode + '-llvm.log')).read_text()
        run(mode + '-strict', ['python3', harness / 'check-dwarfdump.py', output,
            work / (mode + '-dwarfdump.log'), '--original', case / 'stripped'])
        role = work.name + '-' + mode
        run(mode + '-gdb', ['bash', harness / 'lexical-shadow-gdb.sh', case, target, role, output])
        assert 'lexical-shadow-gdb=' + role + ' PASS' in (work / (mode + '-gdb.log')).read_text()
        run(mode + '-gdb-diagnostics', ['python3', harness / 'check-lexical-gdb-log.py', work, mode, target])
    assert protected == {p: digest(Path(p)) for p in protected}
    after = {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    assert changed <= {str(project / 'Lexical.rep/idata' / name) for name in ('~index.bak', '~journal.bak')}
    receipt = {'status': 'COVERAGE_STAGING_PASS', 'target': target, 'controls': markers,
        'reportStatuses': dict(statuses), 'protected': protected, 'projectBackupChanges': sorted(changed),
        'scope': 'real production capture/assembly/write/read cancellation and injected failures; pair and companion preservation/retry; validators and GDB'}
    (work / 'acceptance.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print('coverage-staging=PASS', flush=True)


if __name__ == '__main__':
    main()

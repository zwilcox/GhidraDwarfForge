#!/usr/bin/env python3
"""Validate inferred labels and saved lexical memory locals using a compiler-oracle fixture."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(project):
    return {str(p): digest(p) for p in project.rglob('*') if p.is_file() and not p.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--controls-only', action='store_true')
    args = parser.parse_args()
    baseline, ghidra = args.case.resolve(strict=True), args.ghidra.resolve(strict=True)
    accepted = json.loads((baseline / 'acceptance.json').read_text())
    assert accepted['status'] == 'LEXICAL_STATICS_PASS'
    assert all(digest(Path(p)) == value for p, value in accepted['protected'].items())
    harness = Path(__file__).resolve().parent
    repository = harness.parents[2]
    results = repository / 'build/test-results/recovered-statics'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=accepted['target'] + '-' + accepted['role'] + '-', dir=results))
    print('recovered-statics-results=' + str(case), flush=True)
    for name in ['reference', 'stripped', 'labels.json', 'compiler-objects.json', 'compiler-gdb.log']:
        shutil.copy2(baseline / name, case / name)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p): digest(p) for p in [module, baseline / 'stripped', baseline / 'reference',
        case / 'stripped', case / 'reference', case / 'labels.json', case / 'compiler-objects.json']}
    project = baseline / 'project'
    before = snapshot(project)
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=240)
        return (case / (label + '.log')).read_text()

    rows = []
    modes = ['inferred-stale', 'inferred-namespace', 'inferred-overlap', 'inferred-curated', 'memory-stale', 'memory-failed'] \
        if args.controls_only else ['inferred', 'memory']
    for mode in modes:
        output = case / (mode + '.dbg')
        pair = None
        for iteration in ['first', 'repeat']:
            export = ['-postScript', 'StaticDecompilerFailureExport.java', output] if mode == 'memory-failed' else [
                '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(output)]
            preparation = 'memory' if mode == 'memory-failed' else mode
            log = run(mode + '-' + iteration, [ghidra / 'support/analyzeHeadless', project, 'Statics',
                '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts',
                '-postScript', 'PrepareRecoveredStatics.java', preparation, *export])
            assert 'static-recovery-preparation=' + preparation + ' PASS' in log
            if mode == 'memory-failed':
                assert 'static-decompiler-failure=PASS' in log and 'Flow exceeded maximum allowable instructions' in log
            else:
                assert 'GhidraDwarfForge symbol export PASS' in log
            if mode == 'inferred':
                assert 'Using decompiler-recovered static type for other_statics::shadow' in log
            if mode == 'inferred-curated':
                assert 'Using decompiler-recovered static type for other_statics::shadow' not in log
            if mode == 'inferred-stale':
                assert 'Omitted explicit static binding' in log
            if mode == 'memory-stale':
                assert 'rejected lexical scope' in log
            current = [digest(output), digest(Path(str(output) + '.c'))]
            assert pair is None or current == pair
            pair = current
        for view in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
            assert 'Warning:' not in run(mode + '-' + view, ['readelf', '--debug-dump=' + view, output])
        run(mode + '-elf', ['readelf', '-hSWn', output])
        run(mode + '-scope', ['python3', harness / 'check-lexical-statics.py', case, mode])
        assert 'No errors.' in run(mode + '-llvm', ['llvm-dwarfdump', '--verify', output])
        run(mode + '-strict', ['python3', harness / 'check-dwarfdump.py', output,
            case / (mode + '-dwarfdump.log'), '--original', case / 'stripped'])
        log = run(mode + '-gdb', ['bash', harness / 'lexical-statics-gdb.sh', case, accepted['target'], mode, output])
        assert 'lexical-statics-gdb=' + mode + ' PASS' in log

        def warnings(text):
            return Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in text.splitlines()
                if re.match(r'\s*(warning:|error:)', line, re.I))

        assert warnings(log) == warnings((case / 'compiler-gdb.log').read_text())
        rows.append({'mode': mode, 'pair': pair, 'observations': json.loads((case / (mode + '-observations.json')).read_text())})
        protected.update({str(p): digest(p) for p in [output, Path(str(output) + '.c')]})
    if args.controls_only:
        padded = case / 'padded'
        shutil.copy2(case / 'stripped', padded)
        with padded.open('r+b') as stream:
            stream.truncate(128 * 1024 * 1024)
        protected[str(padded)] = digest(padded)
        cancel_project = case / 'cancel-project'
        cancel_project.mkdir()
        rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if accepted['role'] == 'pie-rebased' else []
        run('cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'Statics', '-import', padded,
            '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', harness / 'ghidra_scripts',
            *rebase, '-postScript', 'PrepareLexicalStatics.java', case / 'labels.json', case / 'compiler-objects.json', case / 'prepared.json'])
        cancel_before = snapshot(cancel_project)
        log = run('cancel-export', [ghidra / 'support/analyzeHeadless', cancel_project, 'Statics', '-process', 'padded',
            '-readOnly', '-noanalysis', '-scriptPath', harness / 'ghidra_scripts',
            '-postScript', 'PrepareRecoveredStatics.java', 'memory',
            '-postScript', 'CancelDuringElfCopy.java', padded, case / 'memory-failed.dbg'])
        assert 'production-copy-cancellation=PASS' in log and '"status":"CANCELLED"' in log
        cancel_after = snapshot(cancel_project)
        cancel_changed = {p for p in cancel_before.keys() | cancel_after.keys() if cancel_before.get(p) != cancel_after.get(p)}
        assert cancel_changed <= {str(cancel_project / 'Statics.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
        assert not any(p.name.startswith('.') for p in case.iterdir()), 'temporary publication residue'
    after = snapshot(project)
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    assert changed <= {str(project / 'Statics.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}, changed
    assert protected == {p: digest(Path(p)) for p in protected}
    result = {'status': 'RECOVERED_STATICS_CONTROLS_PASS' if args.controls_only else 'RECOVERED_STATICS_POSITIVE_PASS',
        'target': accepted['target'], 'role': accepted['role'],
        'protected': protected, 'baseline': str(baseline), 'cases': rows, 'projectBackupChanges': sorted(changed),
        'cancelledExports': int(args.controls_only), 'remaining': 'complete matrix review and hosted acceptance'}
    (case / 'acceptance.json').write_text(json.dumps(result, indent=4) + '\n')
    print('recovered-statics-export=PASS', flush=True)


if __name__ == '__main__':
    main()

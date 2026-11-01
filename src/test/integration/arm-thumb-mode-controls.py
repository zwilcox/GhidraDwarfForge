#!/usr/bin/env python3
"""Compose ARM/Thumb mode cues with real decompiler failure and copy cancellation."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('facts', source / 'dynamic-parameter-storage-check.py')
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def snapshot(project):
    return {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}

def unchanged(project, before):
    after = snapshot(project)
    changes = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    assert changes <= {'ThumbModes.rep/idata/~index.bak', 'ThumbModes.rep/idata/~journal.bak'}, changes
    return sorted(changes)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('base', type=Path)
    parser.add_argument('--output', type=Path, default=repository / 'build/test-results/arm-thumb-controls')
    args = parser.parse_args()
    ghidra, base = args.ghidra.resolve(strict=True), args.base.resolve(strict=True)
    assert json.loads((base / 'result.json').read_text())['status'] == 'PASS'
    args.output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=args.output.resolve()))
    print(case, flush=True)
    installed = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    (case / 'empty-debug').mkdir()
    for leaf in ('thumb.stripped', 'thumb.reference', 'labels.json', 'compiler-calls.json', 'compiler-from-arm.json'):
        shutil.copy2(base / leaf, case / leaf)
    shutil.copytree(base / 'project', case / 'project')
    protected = [p for p in base.rglob('*') if p.is_file()] + [p for p in installed.rglob('*') if p.is_file()]
    protected += [case / leaf for leaf in ('thumb.stripped', 'thumb.reference', 'labels.json')]
    protected += [Path(__file__), source / 'arm-thumb-mode-runtime.sh', source / 'arm-thumb-mode-gdb.py',
        source / 'check-dwarfdump.py', source / 'ghidra_scripts/PrepareArmThumbMode.java',
        source / 'ghidra_scripts/AbiDecompilerFailureExport.java', source / 'ghidra_scripts/CancelDuringElfCopy.java']
    before = {str(p): digest(p) for p in protected}
    (case / 'protected-before.json').write_text(json.dumps(before, indent=4) + '\n')

    def run(label, argv):
        argv = list(map(str, argv))
        (case / (label + '.command.json')).write_text(json.dumps(argv, indent=4) + '\n')
        result = subprocess.run(argv, capture_output=True, timeout=240)
        (case / (label + '.log')).write_bytes(result.stdout)
        (case / (label + '.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, (case, label, result.returncode, result.stderr)
        if Path(argv[0]).name != 'analyzeHeadless':
            assert not result.stderr, (label, result.stderr)
        return result.stdout.decode()

    project_before = snapshot(case / 'project')
    hashes = None
    for iteration in ('first', 'repeat'):
        text = run('failure-' + iteration, [ghidra / 'support/analyzeHeadless', case / 'project', 'ThumbModes',
            '-process', 'thumb.stripped', '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts',
            '-postScript', 'AbiDecompilerFailureExport.java', case / 'thumb.dbg', 'recovered_arm_after'])
        assert 'abi-decompiler-failure=PASS' in text and 'REPORT SCRIPT ERROR' not in text
        assert 'Flow exceeded maximum allowable instructions' in text
        current = [digest(case / leaf) for leaf in ('thumb.dbg', 'thumb.dbg.c')]
        assert hashes is None or current == hashes
        hashes = current
    assert 'Flow exceeded maximum allowable instructions' in (case / 'thumb.dbg.c').read_text()
    info = run('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'thumb.dbg'])
    dies = facts.die_records(info)
    index, die = next((i, d) for i, d in enumerate(dies) if d['tag'] == 'DW_TAG_subprogram' and facts.die_name(d) == 'recovered_arm_after')
    assert 'DW_AT_decl_line' not in die['attrs'] and 'DW_AT_type' not in die['attrs']
    assert 'DW_AT_low_pc' in die['attrs']
    assert dies[index + 1]['depth'] <= die['depth'], 'failed function has fabricated variable children'
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', case / 'thumb.dbg'])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'thumb.dbg', case / 'strict-check.log',
        '--original', case / 'thumb.stripped'])
    vdso = re.compile(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index')
    for phase in ('calls', 'from-arm'):
        run('gdb-' + phase, ['bash', source / 'arm-thumb-mode-runtime.sh', case, 'forge', phase])
        result = json.loads((case / ('forge-' + phase + '.json')).read_text())
        assert result['status'] == 'PASS' and result['exitCode'] == 0
        lines = (case / ('forge-' + phase + '.stderr')).read_text().splitlines()
        original = (base / ('compiler-' + phase + '.stderr')).read_text().splitlines()
        assert all(vdso.fullmatch(line) for line in lines + original)
        assert not (Counter(vdso.sub('<vdso>', line) for line in lines) - Counter(vdso.sub('<vdso>', line) for line in original))
        assert (case / ('forge-' + phase + '.qemu.status')).read_text() == 'exit=0\n'
        assert not (case / ('forge-' + phase + '.qemu.stderr')).read_bytes()
    project_changes = unchanged(case / 'project', project_before)
    padded = case / 'padded'
    shutil.copy2(case / 'thumb.stripped', padded)
    with padded.open('r+b') as stream:
        stream.truncate(128 * 1024 * 1024)
    before[str(padded)] = digest(padded)
    cancel_project = case / 'cancel-project'
    cancel_project.mkdir()
    labels = json.loads((case / 'labels.json').read_text())
    prepare = [hex(labels[n]['code']) for n in ('thumb_add', 'arm_call', 'main', 'thumb_sink', 'thumb_pointer', 'arm_after')]
    if labels['role'] == 'pie-rebased':
        prepare.append('0x200000')
    text = run('cancel-import', [ghidra / 'support/analyzeHeadless', cancel_project, 'ThumbModes', '-import', padded,
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', source / 'ghidra_scripts',
        '-postScript', 'PrepareArmThumbMode.java', *prepare])
    assert 'ARM_THUMB_PREP=' in text and 'REPORT SCRIPT ERROR' not in text
    cancel_before = snapshot(cancel_project)
    text = run('cancel-export', [ghidra / 'support/analyzeHeadless', cancel_project, 'ThumbModes', '-process', padded.name,
        '-readOnly', '-noanalysis', '-scriptPath', source / 'ghidra_scripts', '-postScript',
        'CancelDuringElfCopy.java', padded, case / 'thumb.dbg'])
    assert 'production-copy-cancellation=PASS' in text and '"status":"CANCELLED"' in text
    assert hashes == [digest(case / leaf) for leaf in ('thumb.dbg', 'thumb.dbg.c')]
    cancel_changes = unchanged(cancel_project, cancel_before)
    assert before == {p: digest(Path(p)) for p in before}
    assert not any(p.name.startswith('.') for p in case.iterdir())
    result = {'status': 'PASS', 'base': str(base), 'role': labels['role'], 'sectionless': labels.get('sectionless', False),
        'failureExports': 2, 'cancelledExports': 1, 'failureArtifactHashes': hashes,
        'projectBackupChanges': project_changes, 'cancelProjectBackupChanges': cancel_changes,
        'protectedFiles': before, 'packageJarSha256': digest(installed / 'lib/GhidraDwarfForge.jar')}
    (case / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('arm-thumb-mode-controls=PASS ' + str(case))

if __name__ == '__main__':
    main()

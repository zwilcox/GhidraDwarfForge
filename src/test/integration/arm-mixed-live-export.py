#!/usr/bin/env python3
"""Validate real mixed-mode exports before closing a freshly analyzed program."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mixed_reference', source / 'arm-mixed-mode-reference.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def main(ghidra, baseline):
    ghidra, baseline = ghidra.resolve(strict=True), baseline.resolve(strict=True)
    accepted = json.loads((baseline / 'result.json').read_text())
    assert accepted['status'] == 'PASS_PRODUCTION_BASIC'
    case = Path(tempfile.mkdtemp(prefix='live.', dir=baseline))
    print(case, flush=True)
    names = ['mixed.stripped', 'mixed.reference', 'labels.json']
    names += [name for name in ('mixed.driver', 'mixed.sectioned') if (baseline / name).is_file()]
    for name in names:
        shutil.copy2(baseline / name, case / name)
    labels = json.loads((case / 'labels.json').read_text())
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    for path, expected in accepted['protectedHashes'].items():
        if module in Path(path).parents:
            assert reference.digest(Path(path)) == expected
    protected = [*(case / name for name in names), *(baseline / name for name in names),
        Path(__file__), source / 'arm-mixed-mode-reference.py', source / 'arm-mixed-mode-gdb.py',
        source / 'arm-mixed-mode-runtime.sh', source / 'qemu-socket.sh', source / 'arm-mixed-inventory.py',
        source / 'arm-thumb-mode-check.py', source / 'sectionless-alias-check.py',
        source / 'arm-mixed-range-check.py', source / 'dynamic-parameter-storage-check.py',
        source / 'retained-function-aliases-export.py', source / 'ghidra_scripts/PrepareArmMixedBody.java',
        source / 'ghidra_scripts/RepeatLiveAbiExport.java', *module.rglob('*')]
    before = {str(p): reference.digest(p) for p in protected if p.is_file()}

    def run(label, command):
        command = [str(v) for v in command]
        (case / (label + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
        (case / (label + '.stdout')).write_bytes(result.stdout)
        (case / (label + '.stderr')).write_bytes(result.stderr)
        assert result.returncode == 0, (label, result.returncode)
        return result.stdout.decode()

    project = case / 'project'
    project.mkdir()
    prepare = reference.prepare_arguments(labels)
    log = run('live-export', [ghidra / 'support/analyzeHeadless', project, 'Live', '-import',
        case / 'mixed.stripped', '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120',
        '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareArmMixedBody.java', *prepare,
        '-postScript', 'RepeatLiveAbiExport.java', case / 'curated.dbg'])
    assert 'REPORT SCRIPT ERROR' not in log and 'live-abi-export-repeat=PASS' in log
    assert log.count('GhidraDwarfForge symbol export PASS') == 2
    model = reference.inventory.transcript(case / 'live-export.stdout', 'ARM_MIXED_MODEL=')
    assert model == accepted['model'], 'fresh analyzed listing differs from saved-program reference'
    program = {str(p): reference.digest(p) for p in project.rglob('*') if p.is_file()}
    artifact_hashes = [reference.digest(case / name) for name in ('curated.dbg', 'curated.dbg.c')]
    emitted = reference.inventory.elf(case / 'curated.dbg')
    baseline_elf = reference.inventory.elf(baseline / 'curated.dbg')
    assert emitted['symbols'] == baseline_elf['symbols'], 'live symbol inventory differs'
    if labels['sectionless']:
        run('raw-inventory', ['python3', source / 'arm-mixed-inventory.py', case])
        assert not (case / 'raw-inventory.stderr').read_bytes()
    if labels.get('split', False):
        run('split-ranges', ['python3', source / 'arm-mixed-range-check.py', case])
        assert not (case / 'split-ranges.stderr').read_bytes()
    results = {}
    vdso = re.compile(r'^warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index\n', re.M)
    for variant in ('compiler', 'curated'):
        for phase in ('instructions', 'next', 'step', 'address', 'calls'):
            label = variant + ('' if phase == 'instructions' else '-' + phase) + '-gdb'
            run(label, ['bash', source / 'arm-mixed-mode-runtime.sh', case, variant, phase])
            result = json.loads((case / (label + '.json')).read_text())
            assert result['status'] == 'PASS' and result['exitCodes'] == [0]
            stderr = (case / (label + '.stderr')).read_text()
            warnings = vdso.findall(stderr)
            assert len(warnings) == 1 and vdso.sub('', stderr) == ''
            assert stderr == (case / 'compiler-gdb.stderr').read_text()
            results[label] = result
    run('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', case / 'curated.dbg'])
    assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', case / 'curated.dbg'])
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'curated.dbg', case / 'strict.log',
        '--original', case / 'mixed.stripped'])
    for label in ('gnu', 'llvm', 'strict'):
        assert not (case / (label + '.stderr')).read_bytes()
    assert before == {p: reference.digest(Path(p)) for p in before}
    assert program == {str(p): reference.digest(p) for p in project.rglob('*') if p.is_file()}
    assert artifact_hashes == [reference.digest(case / name) for name in ('curated.dbg', 'curated.dbg.c')]
    (case / 'result.json').write_text(json.dumps({'status': 'PASS', 'role': labels['role'],
        'sectionless': labels['sectionless'], 'liveExports': 2, 'protectedHashes': before,
        'artifactSha256': artifact_hashes, 'model': model, 'results': results}, indent=4) + '\n')
    print('arm-mixed-live-export=PASS', case, flush=True)


if __name__ == '__main__':
    main(*(Path(arg) for arg in sys.argv[1:]))

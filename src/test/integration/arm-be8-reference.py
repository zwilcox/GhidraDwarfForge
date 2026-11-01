#!/usr/bin/env python3
"""Reproduce the packaged BE8 scalar checkpoint; broader ABI acceptance is separate."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

repository = Path(__file__).resolve().parents[3]
source = repository / 'src/test/integration'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--little-endian', action='store_true', help='paired ARM little-endian regression')
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    output = repository / 'build/test-results/arm-be8-reference'
    output.mkdir(parents=True, exist_ok=True)
    data_order = 'little' if args.little_endian else 'big'
    case = Path(tempfile.mkdtemp(prefix='scalar.' + data_order + '.', dir=output))
    print(case, flush=True)

    def run(label, command, cwd=repository):
        command = [str(value) for value in command]
        (case / (label + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        with (case / (label + '.stdout')).open('wb') as out, (case / (label + '.stderr')).open('wb') as err:
            result = subprocess.run(command, stdout=out, stderr=err, cwd=cwd, timeout=240)
        assert result.returncode == 0, (label, result.returncode)
        return (case / (label + '.stdout')).read_text()

    def clean(label):
        assert not (case / (label + '.stderr')).read_bytes(), label

    fixture = repository / 'src/test/fixtures/arm-be8'
    protected = [Path(__file__), fixture / 'start.S', fixture / 'probe.c',
        source / 'arm-be8-runtime.sh', source / 'arm-be8-gdb.py', source / 'qemu-socket.sh',
        source / 'ghidra_scripts/PrepareArmBe8.java', source / 'check-dwarfdump.py']
    protected += [p for p in (ghidra / 'Ghidra/Extensions/GhidraDwarfForge').rglob('*') if p.is_file()]
    before = {str(path): digest(path) for path in protected}
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    objcopy = os.environ.get('ARM32_OBJCOPY', 'arm-linux-gnueabihf-objcopy')
    run('compile', [compiler, '-mlittle-endian' if args.little_endian else '-mbig-endian', '-march=armv7-a', '-marm', '-mfpu=vfpv3-d16',
        '-mfloat-abi=hard', '-O0', '-g3', '-gdwarf-5', '-fno-pic', '-fno-pie', '-nostdlib',
        '-nostartfiles', '-static', '-no-pie', *([] if args.little_endian else ['-Wl,--be8']), '-Wl,--build-id=none', '-Wl,-e,_start',
        fixture / 'start.S', fixture / 'probe.c', '-o', case / 'be8.reference'])
    clean('compile')
    run('strip', [objcopy, '--strip-all', case / 'be8.reference', case / 'be8.stripped'])
    clean('strip')
    symbols = run('symbols', ['readelf', '-Ws', case / 'be8.reference'])
    # The prologue and every checked PC are source-known. A toolchain change
    # that changes this layout needs a separately audited oracle, not widening.
    assert re.search(r'\b000100b8\s+52\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+be8_probe\b', symbols)
    assert re.search(r'\b000110ec\s+4\s+OBJECT\s+GLOBAL\s+DEFAULT\s+\d+\s+be8_global\b', symbols)
    before.update({str(case / name): digest(case / name) for name in ('be8.reference', 'be8.stripped')})
    project = case / 'project'
    project.mkdir()
    headless = ghidra / 'support/analyzeHeadless'
    text = run('import', [headless, project, 'Be8', '-import', case / 'be8.stripped',
        '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120'])
    assert 'REPORT: Import succeeded' in text
    text = run('prepare', [headless, project, 'Be8', '-process', 'be8.stripped', '-noanalysis',
        '-scriptPath', source / 'ghidra_scripts', '-postScript', 'PrepareArmBe8.java', '0x100b8', '0x110ec', data_order])
    assert 'REPORT SCRIPT ERROR' not in text
    model = json.JSONDecoder().raw_decode(text.split('ARM_BE8_MODEL=', 1)[1])[0]
    assert model['parameterStorage'] == model['returnStorage'] == 'r0:4'
    program_before = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    export = [headless, project, 'Be8', '-process', 'be8.stripped', '-noanalysis', '-readOnly',
        '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(case / 'curated.dbg')]
    text = run('export', export)
    assert 'GhidraDwarfForge symbol export PASS' in text and 'REPORT SCRIPT ERROR' not in text
    artifacts = {name: digest(case / name) for name in ('curated.dbg', 'curated.dbg.c')}
    text = run('repeat', export)
    assert 'GhidraDwarfForge symbol export PASS' in text and 'REPORT SCRIPT ERROR' not in text
    assert artifacts == {name: digest(case / name) for name in artifacts}
    program_after = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    changed = sorted(name for name in program_before.keys() | program_after.keys()
        if program_before.get(name) != program_after.get(name))
    assert set(changed) <= {'Be8.rep/idata/~index.bak', 'Be8.rep/idata/~journal.bak'}, changed
    for artifact in ('be8.reference', 'curated.dbg'):
        run(artifact + '-gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', case / artifact])
        clean(artifact + '-gnu')
        run(artifact + '-llvm', ['llvm-dwarfdump', '--verify', case / artifact])
        clean(artifact + '-llvm')
        run(artifact + '-strict', ['python3', source / 'check-dwarfdump.py', case / artifact,
            case / (artifact + '.strict.log'), '--original', case / 'be8.stripped'])
        clean(artifact + '-strict')
    results = {}
    warning = None
    for variant in ('compiler', 'curated'):
        for phase in ('instructions', 'next', 'step'):
            label = variant + '-' + phase
            # Deliberately load absolute symbols while outside the artifact directory.
            run(label, ['bash', source / 'arm-be8-runtime.sh', case, variant, phase, data_order], cwd='/tmp')
            result = json.loads((case / (label + '-gdb.json')).read_text())
            assert result['status'] == 'PASS_SCALAR_CHECKPOINT' and result['exits'] == [0]
            stderr = (case / (label + '.stderr')).read_text()
            assert re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index\n', stderr)
            if warning is None:
                warning = stderr
            assert stderr == warning
            results[label] = result
    reference = results['compiler-instructions']
    curated = results['curated-instructions']
    assert reference['static'] == curated['static']
    assert len(reference['observations']) == len(curated['observations']) == 13
    for expected, actual, model_row in zip(reference['observations'], curated['observations'], model['instructions']):
        for key in ('offset', 'r0', 'codeBytes', 'instruction'):
            assert expected[key] == actual[key]
        assert model_row['offset'] == actual['offset'] and model_row['bytes'] == actual['codeBytes']
    assert all(digest(Path(path)) == value for path, value in before.items())
    (case / 'result.json').write_text(json.dumps({'status': 'PASS_SCALAR_CHECKPOINT',
        'fullAbiAcceptance': False, 'model': model, 'artifacts': artifacts, 'protectedHashes': before,
        'programBefore': program_before, 'programAfter': program_after, 'rotatedProjectBackups': changed,
        'results': results}, indent=4) + '\n')
    print('arm-be8-scalar-checkpoint=PASS', flush=True)


if __name__ == '__main__':
    main()

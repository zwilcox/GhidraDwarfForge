#!/usr/bin/env python3
"""Native PowerShell/headless producer, deterministic pairs/companions and cancellation."""
import argparse
import hashlib
import json
import platform
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, log, expected=0):
    command = list(map(str, command))
    log.with_suffix('.command.json').write_text(json.dumps(command, indent=4) + '\n', encoding='utf-8')
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=360)
    log.write_bytes(result.stdout)
    text = result.stdout.decode('utf-8', errors='replace')
    assert result.returncode == expected, text[-6000:]
    assert 'Traceback' not in text, text[-6000:]
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--powershell', default='pwsh')
    parser.add_argument('--readelf', default='readelf')
    parser.add_argument('--llvm', default='llvm-dwarfdump')
    args = parser.parse_args()
    assert platform.system() == 'Windows', 'this harness proves native Windows production'
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    prior = json.loads((args.reference / 'result.json').read_text(encoding='utf-8'))
    assert prior['status'] == 'PASS_FORMATTER_COMPILER_INPUTS'
    scripts = Path(__file__).resolve().parent / 'ghidra_scripts'
    fixture = scripts.parent.parent / 'fixtures/formatter-values.c'
    assert digest(fixture) == prior['fixtureSha256']
    ghidra = args.ghidra.resolve()
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    wrapper = module / 'support/ghidra-dwarf-forge-headless.ps1'
    headless = ghidra / 'support/analyzeHeadless.bat'
    protected = {str(path): digest(path) for path in [wrapper, module / 'lib/GhidraDwarfForge.jar',
        module / 'ghidra_scripts/GhidraDwarfForge.java', scripts / 'ApplyFormatterFixture.java',
        scripts / 'CancelDuringFormatters.java']}
    outputs = []
    for record in prior['artifacts']:
        role = record['role']
        assert role in ('exec', 'pie')
        work = root / role
        work.mkdir()
        for name, expected in record['sha256'].items():
            assert Path(name).name == name
            source = args.reference / role / name
            assert digest(source) == expected
            shutil.copy2(source, work / name)
        original, reference = work / 'original', work / 'compiler-reference'
        project = work / 'project'
        project.mkdir()
        selection = work / 'selection.json'
        text = run([headless, project, 'Formatters', '-import', original, '-analysisTimeoutPerFile', '120',
            '-scriptPath', scripts, '-postScript', 'ApplyFormatterFixture.java', selection,
            work / 'compiler-symbols.json', original], work / 'prepare.log')
        assert 'formatter-fixture=PASS' in text, text[-6000:]
        sidecar = work / 'original with spaces.dbg'
        source = Path(str(sidecar) + '.c')
        companion = work / ('forge_formatters_' + hashlib.sha256(sidecar.name.encode()).hexdigest() + '.py')
        compression = 'none' if role == 'exec' else 'zlib'
        common = [args.powershell, '-NoLogo', '-NoProfile', '-File', wrapper, '-GhidraDirectory', ghidra,
            '-ProjectDirectory', project, '-ProjectName', 'Formatters', '-Program', 'original',
            '-OriginalElf', original, '-Output', sidecar, '-CompressDebugSections', compression]
        selection_hash = digest(selection)
        pair = [sidecar, source]
        artifacts = [*pair, companion, Path(str(sidecar) + '.gdb.py'), Path(str(sidecar) + '.unwind.json')]

        def export(label, enabled):
            command = common + (['-Formatters', selection, '-GdbLoader', '-SynthesizeUnwind', 'strict'] if enabled else [])
            text = run(command, work / (label + '.log'))
            assert 'GhidraDwarfForge symbol export PASS' in text and 'verified packaged libraries' in text
            assert digest(selection) == selection_hash and digest(original) == record['sha256']['original']
            return [digest(path) for path in (artifacts if enabled else pair)]

        baseline = export('default-before', False)
        assert not companion.exists()
        enabled = export('enabled', True)
        assert export('repeat', True) == enabled
        assert export('default-after', False) == baseline
        assert export('restored', True) == enabled and enabled[1] == baseline[1]
        text = run([headless, project, 'Formatters', '-process', 'original', '-readOnly', '-noanalysis',
            '-scriptPath', scripts, '-postScript', 'CancelDuringFormatters.java', original, sidecar,
            selection, compression, 'all'], work / 'cancel.log')
        assert 'formatter-cancellation-recovery=PASS' in text
        invalid = work / 'invalid-selection.json'
        invalid.write_text('{"schema":1,"types":[{"key":"missing","mode":"flags"}]}', encoding='utf-8')
        text = run(common + ['-Formatters', invalid], work / 'invalid.log', expected=10)
        assert 'formatter selection requires an emitted' in text
        for mode in ('info', 'abbrev', 'aranges', 'decodedline'):
            text = run([args.readelf, '-h', '-S', '--debug-dump=' + mode, sidecar], work / (mode + '.log'))
            assert 'warning:' not in text.lower() and 'error:' not in text.lower()
        run([args.llvm, '--verify', sidecar], work / 'llvm.log')
        assert [digest(path) for path in artifacts] == enabled
        assert digest(original) == record['sha256']['original'] and digest(reference) == record['sha256']['compiler-reference']
        assert not list(work.glob('.forge-*')) and not list(work.glob('.*.staged'))
        outputs.append({'role': role, 'compression': compression, 'sidecar': sidecar.name, 'companion': companion.name,
            'sha256': {path.name: digest(path) for path in [original, reference, selection, *artifacts]},
            'defaultSha256': baseline})
    assert protected == {path: digest(Path(path)) for path in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_WINDOWS_FORMATTER_PRODUCER',
        'host': platform.system(), 'packagedNatives': True, 'artifacts': outputs, 'protectedSha256': protected,
        'strictValidation': 'DEFERRED_TO_LINUX_CONSUMER', 'debuggers': 'DEFERRED_TO_LINUX_CONSUMER'}, indent=4) + '\n', encoding='utf-8')
    print('formatter-windows=PASS native Windows producer; consumers pending')


if __name__ == '__main__':
    main()

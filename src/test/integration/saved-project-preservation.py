#!/usr/bin/env python3
"""Real saved ELF wrapper exports must preserve every project file and timestamp."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {str(p.relative_to(root)): [digest(p), p.stat().st_mtime_ns]
        for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    supplied = args.input.resolve(strict=True)
    before_input = digest(supplied)
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    windows = os.name == 'nt'
    launcher = ghidra / ('support/analyzeHeadless.bat' if windows else 'support/analyzeHeadless')
    wrapper = module / ('support/ghidra-dwarf-forge-headless.ps1' if windows else 'support/ghidra-dwarf-forge-headless')
    environment = dict(os.environ, XDG_CONFIG_HOME=str(root / 'settings'))
    if os.environ.get('TMPDIR'):
        environment['JAVA_TOOL_OPTIONS'] = os.environ.get('JAVA_TOOL_OPTIONS', '') + \
            ' -Djava.io.tmpdir="' + os.environ['TMPDIR'] + '"'
    commands = []

    def run(argv, log):
        commands.append(list(map(str, argv)))
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with log.open('w') as stream:
            subprocess.run(commands[-1], stdout=stream, stderr=subprocess.STDOUT,
                check=True, timeout=240, env=environment)
        return log.read_text(errors='replace')

    reports = []
    for folder in ('root', 'nested'):
        case = root / folder
        project = case / 'project'
        project.mkdir(parents=True)
        original = case / 'input.elf'
        shutil.copy2(supplied, original)
        project_selection = 'Preserved' if folder == 'root' else 'Preserved/nested'
        text = run([launcher, project, project_selection, '-import', original, '-loader', 'ElfLoader',
            '-analysisTimeoutPerFile', '120', '-scriptPath', HERE / 'ghidra_scripts',
            '-postScript', 'PrepareProjectPreservation.java'], case / 'prepare.log')
        assert 'SAVED_PROJECT_PREPARED=PASS' in text and 'SCRIPT ERROR' not in text, text
        before = inventory(project)
        # Without these files the historical writable opener's cleanup is not exercised.
        assert any(k.endswith('~index.bak') for k in before), 'fixture lacks index backup'
        (case / 'project-before.json').write_text(json.dumps(before, indent=4) + '\n')
        output = case / 'input.dbg'
        first = None
        for index in range(2):
            program = ('input.elf' if index == 0 else '/input.elf') if folder == 'root' else '/nested/input.elf'
            if windows:
                command = ['pwsh', '-NoLogo', '-NoProfile', '-File', wrapper, '-GhidraDirectory', ghidra,
                    '-ProjectDirectory', project, '-ProjectName', 'Preserved', '-Program', program,
                    '-Input', original, '-Output', output]
            else:
                command = ['bash', wrapper, '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
                    '--project-name=Preserved', '--program=' + program, '--input=' + str(original),
                    '--output=' + str(output)]
            text = run(command, case / ('export-' + str(index) + '.log'))
            assert 'GhidraDwarfForge symbol export PASS' in text, text
            after = inventory(project)
            changed = sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k))
            assert not changed, 'saved project changed: ' + repr(changed)
            current = [digest(output), digest(Path(str(output) + '.c'))]
            assert first is None or first == current, 'saved export is not deterministic'
            first = current
            assert 'preserved_entry' in Path(str(output) + '.c').read_text(), 'curated function missing'
            assert digest(original) == before_input, 'original executable changed'
        reports.append({'folder': folder, 'filesPreserved': len(before), 'exports': 2, 'outputsSha256': first})
    assert digest(supplied) == before_input
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_SAVED_PROJECT_PRESERVATION',
        'inputSha256': before_input, 'cases': reports}, indent=4) + '\n')
    print('saved-project-preservation=PASS')


if __name__ == '__main__':
    main()

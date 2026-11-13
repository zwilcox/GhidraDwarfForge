#!/usr/bin/env python3
"""Audit imported vtable storage before designing persistent byte evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--models', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=('x86_64', 'aarch64'), default=['x86_64', 'aarch64'])
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    settings = root / 'settings'
    settings.mkdir()
    temporary = Path(os.environ.get('TMPDIR', str(root / 'tmp'))).resolve()
    temporary.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'TMPDIR': str(temporary),
        'JAVA_TOOL_OPTIONS': f'-Duser.home={settings} -Djava.io.tmpdir={temporary}'}
    observations = []
    for target in args.targets:
        for role in ('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'):
            label = target + '-' + role
            model = args.models.resolve() / label
            case = root / label
            case.mkdir()
            project = case / 'project'
            project.mkdir()
            binary = case / 'runtime.elf'
            shutil.copy2(model / 'runtime.elf', binary)
            original = binary.read_bytes()
            command = list(map(str, [args.ghidra.resolve() / 'support/analyzeHeadless', project, 'Vtables',
                '-import', binary, '-noanalysis', '-deleteProject', '-scriptPath', HERE,
                '-postScript', 'ProbeVtableStorage.java', model / 'vtables.json', case / 'observation.json']))
            (case / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
            with (case / 'headless.log').open('w') as log:
                subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=180, check=True)
            assert 'vtable-storage-observation=PASS' in (case / 'headless.log').read_text()
            observed = json.loads((case / 'observation.json').read_text())
            for before, after in zip(observed['before'], observed['after'], strict=True):
                data = bytes.fromhex(before['originalBytes'])
                assert original[before['fileOffset']:before['fileOffset'] + len(data)] == data
                assert before['originalBytes'] == after['originalBytes'] and before['fileOffset'] == after['fileOffset']
                assert before['loadedBytes'] == after['loadedBytes'], 'selected profile changed loaded bytes during rebase'
                assert after['address'] - before['address'] == 0x200000
                assert before['relocations'] == after['relocations']
            assert binary.read_bytes() == original
            observations.append({'target': target, 'role': role, 'inputSha256': hashlib.sha256(original).hexdigest(),
                'loadedBytesChangeOnRebase': [a['name'] for a, b in zip(observed['before'], observed['after'])
                    if a['loadedBytes'] != b['loadedBytes']],
                'loadedBytesDifferFromFile': [a['name'] for a in observed['before'] if a['loadedBytes'] != a['originalBytes']],
                'tables': len(observed['before'])})
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_STORAGE_OBSERVATION', 'cases': observations}, indent=4) + '\n')
    print('vtable-storage=PASS', root)


if __name__ == '__main__':
    main()

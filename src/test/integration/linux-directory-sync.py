#!/usr/bin/env python3
"""Isolate the production directory calls and retain an independent C oracle."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    root = args.results.absolute()
    root.mkdir(parents=True, exist_ok=False)
    provenance = root / 'provenance'
    provenance.mkdir()
    source = ROOT / 'src/test/java/ghidradwarfforge/output/LinuxDirectorySyncSmoke.java'
    contract = ROOT / 'src/test/native/linux-directory-contract.c'
    files = [args.jar.resolve(), args.ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar',
             args.ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar', source, contract,
             Path(__file__), ROOT / 'src/main/java/ghidradwarfforge/output/LinuxDirectorySync.java']
    digests = {}
    for path in files:
        digests[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        shutil.copyfile(path, provenance / path.name)
        assert hashlib.sha256((provenance / path.name).read_bytes()).hexdigest() == digests[str(path)]
    (provenance / 'origin.json').write_text(json.dumps(digests, indent=4) + '\n')
    commands = []

    def run(label, command, version=False):
        command = list(map(str, command))
        result = subprocess.run(command, capture_output=True, timeout=45)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'label': label, 'argv': command, 'exit': result.returncode})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert result.returncode == 0, (label, result.stderr)
        assert version or not result.stderr, (label, result.stderr)
        return result

    observer = root / 'native-contract'
    run('compile-native', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                          provenance / contract.name, '-o', observer])
    run('native-contract', [observer])
    java = os.environ.get('JAVA', 'java')
    assert b'version "21.' in run('java-version', [java, '-version'], version=True).stderr
    classes = root / 'classes'
    classes.mkdir()
    dependencies = os.pathsep.join(str(provenance / name) for name in
                                   ('GhidraDwarfForge.jar', 'jna-5.14.0.jar', 'gson-2.9.0.jar'))
    run('compile-probe', ['javac', '--release', '21', '-cp', dependencies, '-d', classes,
                          provenance / source.name])
    result = run('probe', [java, '-cp', str(classes) + os.pathsep + dependencies,
                           'ghidradwarfforge.output.LinuxDirectorySyncSmoke', observer, root / 'owned'])
    assert b'linux-directory-sync=PASS' in result.stdout
    assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest for path, digest in digests.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS',
        'observed': json.loads((root / 'owned/java.json').read_text()),
        'checks': (root / 'owned/result.txt').read_text().strip(),
        'scope': 'native directory/mount identity and fsync; not filesystem admission or power-loss testing'}, indent=4) + '\n')
    print('linux-directory-sync-harness=PASS')


if __name__ == '__main__':
    main()

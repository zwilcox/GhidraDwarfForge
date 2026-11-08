#!/usr/bin/env python3
"""Exercise real Linux native filename bytes and locale refusal with Java 21."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    root = args.results.absolute()
    root.mkdir(parents=True, exist_ok=False)
    provenance = root / 'provenance'
    provenance.mkdir()
    repo = Path(__file__).resolve().parents[3]
    files = [args.jar.resolve(), Path(__file__),
             repo / 'src/main/java/ghidradwarfforge/output/DebuglinkBasename.java',
             repo / 'src/test/java/ghidradwarfforge/output/DebuglinkBasenameSmoke.java']
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    hashes = {str(p): sha(p) for p in files}
    for path in files:
        shutil.copyfile(path, provenance / path.name)
        assert sha(provenance / path.name) == hashes[str(path)]
    (provenance / 'origin.json').write_text(json.dumps(hashes, indent=4) + '\n')
    commands = []

    def run(label, argv, env=None):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=30, env=env)
        (root / (label + '.stdout')).write_bytes(result.stdout)
        (root / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'label': label, 'argv': list(map(str, argv)), 'exit': result.returncode,
                         'locale': None if env is None else env.get('LC_ALL')})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert result.returncode == 0, (label, result.stderr)
        return result

    classes = root / 'classes'
    classes.mkdir()
    run('compile', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', provenance / args.jar.name,
                    '-d', classes, provenance / 'DebuglinkBasenameSmoke.java'])
    java = os.environ.get('JAVA', 'java')
    assert b'version "21.' in run('java-version', [java, '-version']).stderr
    prefix = [java, '-cp', os.pathsep.join(map(str, [classes, provenance / args.jar.name])),
              'ghidradwarfforge.output.DebuglinkBasenameSmoke']
    env = {**os.environ, 'LC_ALL': 'C.UTF-8'}
    assert b'debuglink-basename=PASS' in run('policy', prefix, env).stdout
    owned = root / 'native-bytes'
    owned.mkdir()
    raw = os.fsencode(owned)
    paths = [raw + b'/shadow\xff.dbg', raw + '/shadow\ufffd.dbg'.encode('utf-8')]
    expected = [b'invalid native bytes must not select the printable alias', b'literal replacement character filename']
    for path, data in zip(paths, expected):
        with open(path, 'xb') as stream:
            stream.write(data)
    assert b'accepted=1 rejected=1' in run('raw-native-bytes', [*prefix, 'raw-paths', owned], env).stdout
    retained = []
    for index, (path, data) in enumerate(zip(paths, expected)):
        with open(path, 'rb') as stream:
            assert stream.read() == data
        # Artifact uploaders decode names as text. Preserve these owned bytes
        # under unambiguous portable names after completing the raw-path test.
        destination = owned / ('native-case-' + str(index))
        os.rename(path, os.fsencode(destination))
        retained.append({'nativePathHex': path.hex(), 'retained': str(destination), 'sha256': sha(destination)})
    refused = run('non-utf8-locale', [*prefix, 'non-utf8'], {**os.environ, 'LC_ALL': 'C'})
    assert b'debuglink-native-encoding=REJECTED' in refused.stdout
    assert all(sha(Path(path)) == digest for path, digest in hashes.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'policy': 'Linux UTF-8 and portable ASCII',
        'nativeByteAliases': retained, 'sourceHashes': hashes,
        'scope': 'encoding/rejection only; actual candidate/GDB behavior is in attachment-elf-controller'}, indent=4) + '\n')
    print('debuglink-basename-native=PASS raw-byte-alias locale-refusal Java21')


if __name__ == '__main__':
    main()

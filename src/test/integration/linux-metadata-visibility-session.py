#!/usr/bin/env python3
"""Isolated Java21 visibility lifecycle tests; optional explicit sudo on owned fixtures."""

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
    parser.add_argument('--privileged', action='store_true',
                        help='also explicitly invoke sudo -n on the isolated owned-fixture test')
    args = parser.parse_args()
    results = args.results.resolve()
    results.mkdir(parents=True, exist_ok=False)
    provenance = results / 'provenance'
    provenance.mkdir()
    source = ROOT / 'src/test/java/ghidradwarfforge/output/LinuxMetadataVisibilitySmoke.java'
    mount_source = ROOT / 'src/test/java/ghidradwarfforge/output/LinuxAttachmentMountSmoke.java'
    host_source = ROOT / 'src/test/java/ghidradwarfforge/output/LinuxAttachmentHostSmoke.java'
    contract = ROOT / 'src/test/native/linux-metadata-contract.c'
    inputs = [args.jar.resolve(), args.ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar',
              args.ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar',
              source, contract, Path(__file__), mount_source, host_source,
              *[ROOT / f'src/main/java/ghidradwarfforge/output/{name}.java' for name in
                ['LinuxMetadataVisibility', 'LinuxFileMetadata', 'LinuxDirectorySync', 'LinuxAttachmentMount',
                 'LinuxAttachmentHost', 'LinuxAtomicRename', 'AttachmentOperation', 'AttachmentPaths']]]
    hashes = {}
    for path in inputs:
        hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        shutil.copyfile(path, provenance / path.name)
        assert hashlib.sha256((provenance / path.name).read_bytes()).hexdigest() == hashes[str(path)]
    (provenance / 'origin.json').write_text(json.dumps(hashes, indent=4) + '\n')
    commands = []

    def run(label, command):
        command = list(map(str, command))
        outcome = subprocess.run(command, capture_output=True, timeout=90)
        (results / f'{label}.stdout').write_bytes(outcome.stdout)
        (results / f'{label}.stderr').write_bytes(outcome.stderr)
        commands.append({'label': label, 'argv': command, 'exit': outcome.returncode})
        (results / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert outcome.returncode == 0, (label, outcome.stderr.decode(errors='replace'))
        return outcome

    run('compile-contract', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                             provenance / contract.name, '-o', results / 'contract'])
    run('native-contract', [results / 'contract'])
    classes = results / 'classes'
    classes.mkdir()
    dependencies = os.pathsep.join(str(provenance / path.name) for path in inputs[:3])
    run('compile-java', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', dependencies,
                        '-d', classes, provenance / source.name, provenance / mount_source.name, provenance / host_source.name])
    java = Path(shutil.which(os.environ.get('JAVA', 'java'))).resolve()
    assert b'version "21.' in run('java-version', [java, '-version']).stderr
    prefix = [java, '-cp', str(classes) + os.pathsep + dependencies,
              'ghidradwarfforge.output.LinuxMetadataVisibilitySmoke']
    mount = run('mount-binding', [*prefix[:-1], 'ghidradwarfforge.output.LinuxAttachmentMountSmoke',
                                  results / 'mount λ directory'])
    fields = dict(line.split('=', 1) for line in mount.stdout.decode().splitlines())
    native = os.stat(results / 'mount λ directory')
    assert fields['identity'].split('@')[0] == f'{os.major(native.st_dev)}:{os.minor(native.st_dev)}:{native.st_ino}'
    findmnt = run('findmnt', ['findmnt', '-n', '-T', results / 'mount λ directory', '-o', 'ID,MAJ:MIN,FSTYPE'])
    mount_id, device, fs_type = findmnt.stdout.decode().split()
    assert fields['identity'].split('@')[1] == mount_id
    assert fields['mountRecord'].split()[2] == device and fs_type == 'ext4'
    run('unprivileged', [*prefix, 'unprivileged', results / 'unprivileged'])
    host_prefix = [*prefix[:-1], 'ghidradwarfforge.output.LinuxAttachmentHostSmoke']
    run('host-unprivileged', [*host_prefix, 'unprivileged', results / 'host-unprivileged'])
    if args.privileged:
        run('privileged', ['sudo', '-n', *prefix, 'privileged', results / 'privileged'])
        run('host-privileged', ['sudo', '-n', *host_prefix, 'privileged', results / 'host-privileged'])
    for path in inputs:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == hashes[str(path)]
    result = {'unprivileged': 'PASS', 'privileged': 'PASS' if args.privileged else 'NOT_RUN',
              'scope': 'isolated session; not full host or public attachment acceptance'}
    (results / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()

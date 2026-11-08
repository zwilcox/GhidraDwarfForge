#!/usr/bin/env python3
"""Installer identity refusals using explicit mutations of owned x86-64 test copies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('configuration', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--java', required=True)
    parser.add_argument('--classpath', required=True)
    parser.add_argument('--host', choices=('model', 'linux'), default='model')
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    config = json.loads(args.configuration.read_text())
    protected = {p: digest(p) for p in config['files'].values()}
    original = Path(config['files']['original']).read_bytes()
    assert original[:6] == b'\x7fELF\x02\x01', 'this mutation oracle requires ELF64 little-endian'
    marker = struct.pack('<III', 4, len(config['buildId']) // 2, 3) + b'GNU\0'
    abi_marker = struct.pack('<III', 4, 16, 1) + b'GNU\0'
    prefix = [args.java, '--enable-native-access=ALL-UNNAMED', '-Djava.io.tmpdir=' + str(root),
        '-Djna.tmpdir=' + str(root), '-Dforge.test.buildId.host=' + args.host, '-cp', args.classpath,
        'ghidradwarfforge.output.BuildIdInstallationProbe']
    checks = []

    def fixture(name, mutation=None):
        owned = root / name
        owned.mkdir()
        selected = json.loads(json.dumps(config))
        for key, value in config['files'].items():
            path = owned / (key + '-' + Path(value).name)
            shutil.copy2(value, path)
            selected['files'][key] = str(path)
        if mutation:
            for key in ['original', 'sidecar']:
                path = Path(selected['files'][key])
                data = bytearray(path.read_bytes())
                assert data.count(marker) == 1
                offset = data.index(marker)
                if mutation == 'different-original':
                    data[9] ^= 1  # EI_PAD: changes bytes without inventing a new build ID.
                elif mutation == 'absent':
                    data[offset + 12:offset + 16] = b'XXX\0'
                elif mutation == 'malformed':
                    data[offset + 4:offset + 8] = struct.pack('<I', 0)
                elif mutation == 'ambiguous':
                    assert data.count(abi_marker) == 1
                    abi_offset = data.index(abi_marker)
                    data[abi_offset + 8:abi_offset + 12] = struct.pack('<I', 3)
                else:
                    raise AssertionError(mutation)
                path.write_bytes(data)
            # These are explicitly artificial negative-control pairs, not producer exports.
            report = Path(selected['files']['report'])
            value = json.loads(report.read_text())
            value['artifacts']['inputSha256'] = digest(selected['files']['original'])
            value['artifacts']['outputSha256'] = digest(selected['files']['sidecar'])
            report.write_text(json.dumps(value) + '\n')
        path = owned / 'configuration.json'
        path.write_text(json.dumps(selected, indent=4) + '\n')
        return path, selected

    def run(name, selected, debug, action='install', error=None):
        command = prefix + [str(selected), str(debug), action]
        (root / (name + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
        (root / (name + '.log')).write_text(completed.stdout)
        assert completed.returncode == (1 if error else 0), (name, completed.stdout[-4000:])
        if error:
            assert error in completed.stdout, (name, completed.stdout[-4000:])
        checks.append({'name': name, 'exit': completed.returncode, 'expectedError': error})

    for mutation, error in [('absent', 'original has no build ID'), ('malformed', 'GNU build-ID size'),
            ('ambiguous', 'conflicting GNU build IDs')]:
        path, selected = fixture(mutation, mutation)
        debug = root / (mutation + '-debug')
        debug.mkdir()
        before = {p: digest(p) for p in selected['files'].values()}
        run(mutation, path, debug, error=error)
        assert not list(debug.iterdir())
        assert before == {p: digest(p) for p in before}

    debug = root / 'collision-debug'
    debug.mkdir()
    baseline, selected = fixture('baseline')
    run('baseline', baseline, debug)
    before = {str(p): (digest(p), p.stat().st_ino) for p in debug.rglob('*') if p.is_file()}
    collision, selected = fixture('different-original', 'different-original')
    run('different-original', collision, debug, 'update', error='different original bytes')
    assert before == {str(p): (digest(p), p.stat().st_ino) for p in debug.rglob('*') if p.is_file()}

    for kind in ['hardlink', 'selected-alias']:
        path, selected = fixture(kind)
        if kind == 'hardlink':
            os.link(selected['files']['original'], path.parent / 'original-hardlink')
            error = 'hardlink'
        else:
            selected['files']['source'] = selected['files']['sidecar']
            path.write_text(json.dumps(selected) + '\n')
            error = 'alias'
        debug = root / (kind + '-debug')
        debug.mkdir()
        run(kind, path, debug, error=error)
        assert not list(debug.iterdir())

    for index, invalid in enumerate(['', 'ABCDEF', 'abc', '../escape', 'aa/bb', '00' * 125]):
        value = dict(config, buildId=invalid)
        path = root / ('invalid-id-' + str(index) + '.json')
        path.write_text(json.dumps(value) + '\n')
        debug = root / ('invalid-id-' + str(index))
        debug.mkdir()
        run('invalid-id-' + str(index), path, debug, 'recover', error='build ID must be canonical')
        assert not list(debug.iterdir())

    assert protected == {p: digest(p) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'host': args.host, 'checks': checks,
        'protectedInputs': protected, 'scope': 'Artificial identity mutation/refusal controls; unchanged production export as positive baseline.'}, indent=4) + '\n')
    print('build-id-identity=PASS checks=' + str(len(checks)))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Run production-host installation checks on two explicitly selected floating-export runs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('none_run', type=Path)
    parser.add_argument('zlib_run', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', required=True, choices=('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'))
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--test-classes', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    ghidra, jar, tests = args.ghidra.resolve(), args.jar.resolve(), args.test_classes.resolve()
    scripts = Path(__file__).resolve().parent
    classpath = os.pathsep.join([str(jar), str(tests), str(ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar'),
        str(ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar')])
    commands, results = [], []
    protected = {str(jar): digest(jar)}
    java = None

    def run(name, command):
        commands.append({'name': name, 'command': command})
        (output / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (output / (name + '.log')).open('w') as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=900)
        commands[-1]['exit'] = completed.returncode
        (output / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert completed.returncode == 0, name + ': inspect retained log'

    for role in ['exec', 'pie']:
        configs, fixtures = [], []
        for compression, selected_run in [('none', args.none_run), ('zlib', args.zlib_run)]:
            fixture = selected_run.resolve() / args.target / role
            fixtures.append(fixture)
            command_path = fixture / 'derived-validation/original.command.json'
            command = json.loads(command_path.read_text())
            assert len(command) == 16 and command[5] == 'ghidradwarfforge.output.AttachmentValidatorProbe'
            assert Path(command[4].split(os.pathsep)[0]).resolve() == jar
            java = command[0]
            value = {'files': dict(zip(['report', 'original', 'sidecar', 'source'], command[6:10])),
                'tools': dict(zip(['helper', 'readelf', 'llvm', 'strict', 'configuration'], command[10:15]))}
            observed = json.loads((fixture / 'derived-validation/original.json').read_text())
            # The original binding's observation must agree with the actual note parser below.
            assert observed['schemaVersion'] == 2
            notes = subprocess.check_output(['readelf', '-n', value['files']['original']], text=True)
            ids = {line.split('Build ID: ', 1)[1].strip() for line in notes.splitlines() if 'Build ID: ' in line}
            assert len(ids) == 1
            value['buildId'] = ids.pop()
            for path in value['files'].values():
                protected[path] = digest(path)
            owned = output / (compression + '-' + role + '-inputs')
            owned.mkdir()
            for key, path in list(value['files'].items()):
                copy = owned / (key + '-' + Path(path).name)
                shutil.copy2(path, copy)
                if args.target == 'x86_64':
                    os.chmod(copy, 0o750 if key == 'original' else 0o640)
                    os.setxattr(copy, 'user.forge-build-id-test', b'CI-visible-metadata-preservation')
                    subprocess.run(['setfacl', '-m', 'u:65534:r--', str(copy)], check=True)
                value['files'][key] = str(copy)
            path = output / (compression + '-' + role + '.json')
            path.write_text(json.dumps(value, indent=4) + '\n')
            configs.append(path)
        assert all(digest(p) == expected for p, expected in protected.items())
        destination = output / role
        command = ['python3', str(scripts / 'build-id-installation.py'), *map(str, configs), str(destination),
            '--java', java, '--classpath', classpath, '--host', 'linux',
            '--labels', str(fixtures[0] / 'labels.txt'), '--target', args.target]
        if args.target == 'x86_64' and role == 'exec':
            command.append('--controls')
        run(role, command)
        results.append(str(destination / 'result.json'))
        if args.target == 'x86_64':
            # Verify metadata independently of the Java host's preservation hash.
            def metadata(path):
                observed = path.stat()
                return {'mode': stat.S_IMODE(observed.st_mode), 'uid': observed.st_uid, 'gid': observed.st_gid,
                    'mtimeNs': observed.st_mtime_ns,
                    'xattrs': {key: os.getxattr(path, key).hex() for key in sorted(os.listxattr(path))}}
            config = json.loads(configs[0].read_text())
            installed = json.loads((destination / 'install.log').read_text())
            source = Path(installed['source'])
            generation = source.parent.parent
            comparisons = []
            for key, copies in [('sidecar', [generation / 'export.dbg', generation / 'installed.debug', Path(installed['registration'])]),
                    ('source', [generation / 'export.source', source]), ('report', [generation / 'export.json'])]:
                expected = metadata(Path(config['files'][key]))
                assert 'system.posix_acl_access' in expected['xattrs'] and 'user.forge-build-id-test' in expected['xattrs']
                for copy in copies:
                    assert metadata(copy) == expected
                    comparisons.append({'path': str(copy), 'metadata': expected})
            (output / (role + '-metadata.json')).write_text(json.dumps(comparisons, indent=4) + '\n')
            if role == 'exec':
                run('identity', ['python3', str(scripts / 'build-id-identity.py'), str(configs[0]), str(output / 'identity'),
                    '--java', java, '--classpath', classpath, '--host', 'linux'])
                results.append(str(output / 'identity/result.json'))
                run('command', ['python3', str(scripts / 'build-id-command.py'), *map(str, configs), str(output / 'command'),
                    '--java', java, '--ghidra', str(ghidra), '--jar', str(jar), '--labels', str(fixtures[0] / 'labels.txt'),
                    '--launcher', str(ghidra / 'Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-build-id')])
                results.append(str(output / 'command/result.json'))
    assert protected == {p: digest(p) for p in protected}
    (output / 'result.json').write_text(json.dumps({'status': 'PASS_BUILD_ID_LINUX_MATRIX', 'target': args.target,
        'results': {p: digest(p) for p in results}, 'protectedInputs': protected}, indent=4) + '\n')
    print('build-id-matrix=PASS target=' + args.target)


if __name__ == '__main__':
    main()

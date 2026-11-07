#!/usr/bin/env python3
"""Exercise the real Linux build-ID launcher, requests, cancellation and GDB setup."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('configuration', type=Path)
    parser.add_argument('updated_configuration', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--java', required=True)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--jar', required=True, type=Path)
    parser.add_argument('--labels', required=True, type=Path)
    parser.add_argument('--launcher', type=Path)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    configs = [json.loads(p.read_text()) for p in [args.configuration, args.updated_configuration]]
    protected = {p: digest(p) for c in configs for p in c['files'].values()}
    scripts = Path(__file__).resolve().parent
    launcher = args.launcher.resolve() if args.launcher else scripts.parents[2] / 'support/ghidra-dwarf-forge-build-id'
    extension = root / 'extension'
    (extension / 'lib').mkdir(parents=True)
    shutil.copy2(args.jar, extension / 'lib/GhidraDwarfForge.jar')
    launcher_prefix = [str(launcher), '--java=' + args.java, '--ghidra-dir=' + str(args.ghidra.resolve()),
        '--extension-dir=' + str(extension)]
    classpath = os.pathsep.join([str(extension / 'lib/GhidraDwarfForge.jar'),
        str(args.ghidra.resolve() / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar'),
        str(args.ghidra.resolve() / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar')])
    helper_prefix = [args.java, '--enable-native-access=ALL-UNNAMED', '-cp', classpath, 'ghidradwarfforge.output.BuildIdHelper']
    environment = dict(os.environ, JAVA_TOOL_OPTIONS='-Djna.tmpdir=' + str(root) + ' -Djava.io.tmpdir=' + str(root))
    checks, consumers = [], []

    def selected(action, debug, config=None):
        value = {'schema': 'forge-build-id-request-v1', 'action': action, 'root': str(debug)}
        if action in ['install', 'update']:
            value.update(files=config['files'], tools=config['tools'])
        else:
            value['buildId'] = configs[0]['buildId']
        return value

    def request(name, value):
        path = root / (name + '.json')
        path.write_text(json.dumps(value, ensure_ascii=False, indent=4) + '\n')
        return path

    def command(path, extra=()):
        return launcher_prefix + ['--request=' + str(path), '--request-sha256=' + digest(path), *extra]

    def record(name, command, result, expected=0, outcome=None, error=None):
        (root / (name + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        (root / (name + '.stdout')).write_text(result.stdout)
        (root / (name + '.stderr')).write_text(result.stderr)
        assert result.returncode == expected, (name, result.returncode, result.stdout[-3000:], result.stderr[-1000:])
        responses = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        assert responses, (name, result.stdout)
        last = responses[-1]
        if outcome:
            assert last['outcome'] == outcome, (name, last)
        if error:
            assert error in last['error'], (name, last)
        assert all(value['modifiesOriginal'] is False for value in responses)
        checks.append({'name': name, 'exit': result.returncode, 'outcome': last['outcome']})
        return last

    def run(name, command, expected=0, outcome=None, error=None):
        completed = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=240)
        return record(name, command, completed, expected, outcome, error)

    debug = root / "debug root λ 'quote' $literal"
    debug.mkdir()
    baseline = selected('install', debug, configs[0])
    first = request('request λ "literal"', baseline)
    run('preview', command(first, ['--preview']), outcome='PREVIEW_NOT_VALIDATED')
    encoded = base64.b64encode(str(first).encode()).decode()
    run('encoded-preview', helper_prefix + ['--request-utf8-base64', encoded,
        '--request-sha256', digest(first), '--preview'], outcome='PREVIEW_NOT_VALIDATED')
    run('wrong-sha', launcher_prefix + ['--request=' + str(first), '--request-sha256=' + '0' * 64],
        expected=1, outcome='FAILED', error='selected SHA-256')
    run('duplicate-option', helper_prefix + ['--request', str(first), '--request-utf8-base64', encoded,
        '--request-sha256', digest(first)], expected=1, outcome='FAILED', error='duplicate')
    malformed = [
        ('unknown-field', dict(baseline, unexpected='value'), 'unknown or missing'),
        ('unknown-action', dict(baseline, action='erase'), 'unknown build-ID action'),
        ('relative-root', dict(baseline, root='relative'), 'must be absolute'),
        ('alias', dict(baseline, tools=dict(baseline['tools'], helper=str(first))), 'alias'),
    ]
    # The aliased helper must be the request being read, not a different request.
    for name, value, error in malformed:
        path = request(name, value)
        if name == 'alias':
            value['tools']['helper'] = str(path)
            path = request(name, value)
        run(name, command(path), expected=1, outcome='FAILED', error=error)
    duplicate = root / 'duplicate.json'
    duplicate.write_text('{"schema":"duplicate",' + first.read_text().lstrip()[1:])
    run('duplicate-record', command(duplicate), expected=1, outcome='FAILED', error='duplicate')
    oversized = root / 'oversized.json'
    oversized.write_bytes(b' ' * (1024 * 1024 + 1))
    run('oversized', command(oversized), expected=1, outcome='FAILED', error='exceeds 1 MiB')
    separator = root / 'root:separator'
    separator.mkdir()
    run('separator-root', command(request('separator-root', dict(baseline, root=str(separator)))),
        expected=1, outcome='FAILED', error='search-path separator')
    assert not list(separator.iterdir()) and not list(debug.iterdir())

    def gdb(name, installed, extra_configs=()):
        binary = root / (name + '.original')
        shutil.copy2(configs[0]['files']['original'], binary)
        options = ['set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set auto-solib-add off',
            'set filename-display absolute', installed['gdbSetupCommand'], 'file ' + json.dumps(str(binary)),
            "python assert gdb.find_pc_line(int(gdb.parse_and_eval('&fp_float'))).symtab.fullname() == " + repr(installed['source'])]
        invocation = ['gdb-multiarch', '-nx', '-q', '-batch']
        for option in options:
            invocation += ['-ex', option]
        invocation += ['-x', str(scripts / 'floating-registers-gdb.py')]
        env = dict(os.environ, DEBUGINFOD_URLS='', FORGE_FP_TARGET='x86_64', FORGE_FP_LABELS=str(args.labels.resolve()),
            FORGE_FP_MODE='forge', FORGE_FP_BASELINE='0', FORGE_FP_REMOTE='')
        hidden = []
        try:
            for path in sorted({Path(c['files'][k]) for c in [*configs, *extra_configs] for k in ['sidecar', 'source']}):
                moved = path.with_name(path.name + '.command-oracle-hidden')
                assert not moved.exists()
                path.rename(moved)
                hidden.append((path, moved))
            result = subprocess.run(invocation, env=env, capture_output=True, text=True, timeout=90)
            (root / (name + '.gdb.command.json')).write_text(json.dumps(invocation, indent=4) + '\n')
            text = result.stdout + result.stderr
            (root / (name + '.gdb.log')).write_text(text)
            assert result.returncode == 0 and 'floating-registers-gdb=forge PASS' in text, text[-4000:]
            assert 'Traceback' not in text and 'Python Exception' not in text
            assert digest(binary) == digest(configs[0]['files']['original'])
            consumers.append({'name': name, 'oldExportsAbsent': True, 'setup': installed['gdbSetupCommand']})
        finally:
            for path, moved in reversed(hidden):
                assert not path.exists()
                moved.rename(path)

    installed = run('install', command(first), outcome='INSTALLED')
    gdb('installed', installed)
    run('idempotent', command(first), outcome='ALREADY_INSTALLED')
    run('implicit-update', command(request('implicit-update', selected('install', debug, configs[1]))),
        expected=1, outcome='FAILED', error='explicit update')
    updated = run('update', command(request('update', selected('update', debug, configs[1]))), outcome='UPDATED')
    assert installed['source'] != updated['source'] and Path(installed['source']).exists()
    gdb('updated', updated)
    run('remove', command(request('remove', selected('remove', debug))), outcome='REMOVED')
    assert not Path(installed['registration']).exists() and Path(updated['source']).exists()
    run('recover', command(request('recover', selected('recover', debug))), outcome='UNCHANGED')

    # Read-only files must remain read-only through initial install and refresh.
    # Exercise both plain modes and ACL/user attributes: chmod-before-xattr and
    # reopening an already sealed stage for writing caused distinct regressions.
    metadata_checks = []

    def metadata(path):
        info = path.stat()
        return {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid,
            'mtimeNs': info.st_mtime_ns,
            'xattrs': {name: os.getxattr(path, name).hex() for name in sorted(os.listxattr(path))}}

    for with_attributes in [False, True]:
        for mode in [0o444, 0o555]:
            name = 'readonly-' + oct(mode) + ('-acl' if with_attributes else '-plain')
            owned = root / name
            owned.mkdir()
            readonly_configs = json.loads(json.dumps(configs))
            for index, config in enumerate(readonly_configs):
                inputs = owned / ('inputs-' + str(index))
                inputs.mkdir()
                for key, selected_path in list(config['files'].items()):
                    copy = inputs / Path(selected_path).name
                    shutil.copy2(selected_path, copy)
                    config['files'][key] = str(copy)
                sidecar = Path(config['files']['sidecar'])
                sidecar.chmod(0o600)
                for attribute in os.listxattr(sidecar):
                    os.removexattr(sidecar, attribute)
                if with_attributes:
                    os.setxattr(sidecar, 'user.forge-readonly', b'read-only metadata regression')
                    subprocess.run(['setfacl', '-m', 'u:65534:r--', str(sidecar)], check=True)
                # New export metadata intentionally differs. Refresh must retain
                # the installed registration's access metadata, not replace it.
                sidecar.chmod(mode if index == 0 else 0o640)
            before = {p: {'sha256': digest(p), 'metadata': metadata(Path(p))}
                for config in readonly_configs for p in config['files'].values()}
            expected = metadata(Path(readonly_configs[0]['files']['sidecar']))
            assert bool(expected['xattrs']) == with_attributes
            debug = owned / 'debug'
            debug.mkdir()
            result = run(name + '-install', command(request(name + '-install',
                selected('install', debug, readonly_configs[0]))), outcome='INSTALLED')
            assert metadata(Path(result['registration'])) == expected
            gdb(name + '-installed', result, readonly_configs)
            result = run(name + '-update', command(request(name + '-update',
                selected('update', debug, readonly_configs[1]))), outcome='UPDATED')
            assert metadata(Path(result['registration'])) == expected
            gdb(name + '-updated', result, readonly_configs)
            assert before == {p: {'sha256': digest(p), 'metadata': metadata(Path(p))} for p in before}
            metadata_checks.append({'name': name, 'registration': result['registration'],
                'preservedMetadata': expected, 'protectedInputs': before})

    # Each cancellation starts only after an actual selected validator has begun.
    for mode in ['stdin', 'file']:
        owned = root / ('cancel-' + mode)
        owned.mkdir()
        marker = owned / 'started'
        delayed = owned / 'delayed-readelf'
        delayed.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nimport time\nPath(' + repr(str(marker)) + ').touch()\ntime.sleep(60)\n')
        delayed.chmod(0o755)
        debug = owned / 'debug'
        debug.mkdir()
        config = json.loads(json.dumps(configs[0]))
        config['tools']['readelf'] = str(delayed)
        path = request('cancel-' + mode, selected('install', debug, config))
        stop = owned / 'stop'
        stop.touch()
        invocation = command(path, ['--cancel-on-stdin'] if mode == 'stdin' else ['--cancel-file=' + str(stop)])
        process = subprocess.Popen(invocation, env=environment, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            deadline = time.monotonic() + 45
            while not marker.exists():
                assert process.poll() is None and time.monotonic() < deadline, 'validator never started'
                time.sleep(0.05)
            if mode == 'stdin':
                process.stdin.write('cancel\n')
                process.stdin.flush()
            else:
                stop.write_text('cancel\n')
            stdout, stderr = process.communicate(timeout=30)
            completed = subprocess.CompletedProcess(invocation, process.returncode, stdout, stderr)
            record('cancel-' + mode, invocation, completed, expected=130, outcome='CANCELLED')
            assert not list((debug / '.build-id').glob('*/*.debug'))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=10)

    assert protected == {p: digest(p) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_LINUX_COMMAND', 'checks': checks,
        'consumers': consumers, 'metadataChecks': metadata_checks, 'protectedInputs': protected,
        'jarSha256': digest(extension / 'lib/GhidraDwarfForge.jar'),
        'scope': 'Production Linux launcher/helper/ext4 adapter with real validators and GDB; Windows unverified.'}, indent=4) + '\n')
    print('build-id-command=PASS checks=' + str(len(checks)) + ' GDB=' + str(len(consumers)))


if __name__ == '__main__':
    main()

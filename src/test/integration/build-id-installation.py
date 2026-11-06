#!/usr/bin/env python3
"""Real build-ID transaction/validator tests with an explicitly test-only Linux metadata host."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('configuration', type=Path)
    parser.add_argument('updated_configuration', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--java', required=True)
    parser.add_argument('--classpath', required=True)
    parser.add_argument('--controls', action='store_true')
    parser.add_argument('--host', choices=('model', 'linux'), default='model')
    parser.add_argument('--labels', type=Path)
    parser.add_argument('--target', choices=('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'))
    args = parser.parse_args()
    assert bool(args.labels) == bool(args.target)
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    configs = [p.resolve(strict=True) for p in (args.configuration, args.updated_configuration)]
    values = [json.loads(p.read_text()) for p in configs]
    original = Path(values[0]['files']['original'])
    assert digest(original) == digest(values[1]['files']['original'])
    assert values[0]['buildId'] == values[1]['buildId']
    assert digest(values[0]['files']['sidecar']) != digest(values[1]['files']['sidecar'])
    protected = {path: digest(path) for value in values for path in value['files'].values()}
    build_id = values[0]['buildId']
    prefix = [args.java, '--enable-native-access=ALL-UNNAMED', '-Djava.io.tmpdir=' + str(root),
        '-Djna.tmpdir=' + str(root), '-Dforge.test.buildId.host=' + args.host, '-cp', args.classpath]
    commands, checks, consumers = [], [], []
    script_root = Path(__file__).resolve().parent

    def run(name, config, debug, action, properties=(), expected=0, contains=None):
        command = prefix + ['-Dforge.test.buildId.' + value for value in properties] + [
            'ghidradwarfforge.output.BuildIdInstallationProbe', str(config), str(debug), action]
        row = {'name': name, 'command': command}
        commands.append(row)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
        row['exit'] = completed.returncode
        (root / (name + '.log')).write_text(completed.stdout)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert completed.returncode == expected, (name, completed.returncode, completed.stdout[-5000:])
        if contains:
            assert contains in completed.stdout, (name, completed.stdout[-5000:])
        result = json.loads(completed.stdout) if expected == 0 else None
        checks.append({'name': name, 'exit': completed.returncode, 'outcome': result['outcome'] if result else None})
        return result

    def fresh(name):
        directory = root / name
        directory.mkdir()
        return directory

    def registration(debug):
        return debug / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')

    def state_file(debug):
        return debug / '.forge-build-id/v1' / build_id / 'state.json'

    def snapshot(debug):
        return {str(p.relative_to(debug)): (digest(p), p.stat().st_ino)
            for p in debug.rglob('*') if p.is_file()}

    def gdb(name, debug, source=None):
        binary = root / (name + '.original')
        shutil.copy2(original, binary)
        options = ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
            'set auto-solib-add off', 'set disable-randomization off',
            'set filename-display absolute', 'set debug-file-directory ' + str(debug),
            'file ' + json.dumps(str(binary))]
        if source is None:
            options += ["python assert gdb.lookup_global_symbol('fp_float') is None", 'echo NO_INSTALLED_SYMBOLS_PASS\\n']
            command = ['gdb-multiarch', '-nx', '-q', '-batch']
            for option in options:
                command += ['-ex', option]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
            text = completed.stdout + completed.stderr
            (root / (name + '.gdb.log')).write_text(text)
            assert completed.returncode == 0 and 'NO_INSTALLED_SYMBOLS_PASS' in text
            consumers.append({'name': name, 'kind': 'missing-registration'})
            return
        options.append("python assert gdb.find_pc_line(int(gdb.parse_and_eval('&fp_float'))).symtab.fullname() == " + repr(source))
        command = ['gdb-multiarch', '-nx', '-q', '-batch']
        for option in options:
            command += ['-ex', option]
        environment = dict(os.environ, DEBUGINFOD_URLS='', FORGE_FP_TARGET=args.target,
            FORGE_FP_LABELS=str(args.labels.resolve()), FORGE_FP_MODE='forge', FORGE_FP_BASELINE='0', FORGE_FP_REMOTE='')
        command += ['-x', str(script_root / 'floating-registers-gdb.py')]
        hidden = []
        try:
            for path in sorted({Path(v['files'][key]) for v in values for key in ['source', 'sidecar']}):
                temporary = path.with_name(path.name + '.build-id-oracle-hidden')
                assert not temporary.exists()
                path.rename(temporary)
                hidden.append((path, temporary))
            if args.target != 'x86_64':
                profiles = {'aarch64': ('qemu-aarch64-static', '/usr/aarch64-linux-gnu'),
                    'arm32': ('qemu-arm-static', os.environ.get('FORGE_ARM32_SYSROOT', '/usr/arm-linux-gnueabihf')),
                    'mips32be': ('qemu-mips-static', '/usr/mips-linux-gnu'),
                    'mips32le': ('qemu-mipsel-static', '/usr/mipsel-linux-gnu')}
                emulator, sysroot = profiles[args.target]
                command[4:4] = ['-ex', 'set sysroot ' + sysroot]
                body = '''set -euo pipefail
source "$1"
trap qemu_socket_cleanup EXIT
qemu_socket_start "$2" "$3" "$4" "$5"
export FORGE_FP_REMOTE="$qemu_socket_path"
shift 5
"$@"
qemu_socket_wait
'''
                command = ['bash', '-c', body, 'build-id-gdb', str(script_root / 'qemu-socket.sh'),
                    str(root / (name + '.qemu')), emulator, sysroot, str(binary), *command]
            (root / (name + '.gdb.command.json')).write_text(json.dumps(command, indent=4) + '\n')
            completed = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=120)
            text = completed.stdout + completed.stderr
            (root / (name + '.gdb.log')).write_text(text)
            assert completed.returncode == 0 and 'floating-registers-gdb=forge PASS' in text, text[-5000:]
            assert 'Traceback' not in text and 'Python Exception' not in text
            assert digest(binary) == digest(original)
            consumers.append({'name': name, 'kind': 'fresh-GDB-discovery-and-values', 'retainedSource': source,
                'oldExportsAbsent': True, 'target': args.target})
        finally:
            for path, temporary in reversed(hidden):
                assert not path.exists()
                temporary.rename(path)

    debug = fresh('lifecycle')
    if args.labels:
        gdb('empty', debug)
    installed = run('install', configs[0], debug, 'install')
    assert installed['outcome'] == 'INSTALLED'
    first = Path(installed['source'])
    first_bytes = first.read_bytes()
    before = snapshot(debug)
    noop = run('idempotent', configs[0], debug, 'install')
    assert noop['outcome'] == 'ALREADY_INSTALLED' and before == snapshot(debug)
    if args.labels:
        gdb('installed', debug, installed['source'])
    run('implicit-update-refused', configs[1], debug, 'install', expected=1, contains='explicit update is required')
    assert before == snapshot(debug)
    updated = run('update', configs[1], debug, 'update')
    assert updated['outcome'] == 'UPDATED' and updated['source'] != installed['source']
    assert first.read_bytes() == first_bytes
    updated_bytes = Path(updated['source']).read_bytes()
    assert updated_bytes == Path(values[1]['files']['source']).read_bytes()
    if args.labels:
        gdb('updated', debug, updated['source'])
    removed = run('remove', configs[1], debug, 'remove')
    assert removed['outcome'] == 'REMOVED' and not registration(debug).exists()
    assert first.read_bytes() == first_bytes and Path(updated['source']).read_bytes() == updated_bytes
    if args.labels:
        gdb('removed', debug)
    assert run('settled-recovery', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'
    assert run('reinstall', configs[0], debug, 'install')['outcome'] == 'INSTALLED'

    if args.controls:
        for mode in ['install', 'update', 'remove']:
            boundaries = ['PREPARED', 'BEFORE_PUBLICATION', 'PUBLISHED', 'COMMITTED']
            if mode != 'remove':
                boundaries.insert(0, 'GENERATION_SEALED')
            for boundary in boundaries:
                name = mode + '-crash-' + boundary.lower()
                debug = fresh(name)
                previous = None
                if mode != 'install':
                    previous = run(name + '-baseline', configs[0], debug, 'install')
                prior = digest(registration(debug)) if previous else None
                config = configs[1] if mode == 'update' else configs[0]
                run(name, config, debug, mode, ['crash=' + boundary], expected=73)
                if boundary == 'GENERATION_SEALED':
                    expected = 'UNCHANGED'
                elif boundary in ['PREPARED', 'BEFORE_PUBLICATION']:
                    expected = 'RECOVERED_ABORT'
                elif boundary == 'PUBLISHED':
                    expected = 'RECOVERED_COMMIT'
                else:
                    expected = 'UNCHANGED'
                recovered = run(name + '-recovery', config, debug, 'recover')
                assert recovered['outcome'] == expected
                applied = boundary in ['PUBLISHED', 'COMMITTED']
                if not applied:
                    assert (digest(registration(debug)) if registration(debug).exists() else None) == prior
                elif mode == 'remove':
                    assert not registration(debug).exists()
                else:
                    assert registration(debug).exists() and digest(registration(debug)) != prior
                if previous:
                    assert Path(previous['source']).read_bytes() == first_bytes
                assert run(name + '-recovery-repeat', config, debug, 'recover')['outcome'] == 'UNCHANGED'

        for mode in ['install', 'update', 'remove']:
            for boundary in ['PREPARED', 'PUBLISHED']:
                name = mode + '-cancel-' + boundary.lower()
                debug = fresh(name)
                if mode != 'install':
                    run(name + '-baseline', configs[0], debug, 'install')
                config = configs[1] if mode == 'update' else configs[0]
                before_publication = boundary == 'PREPARED'
                run(name, config, debug, mode, ['cancel=' + boundary], expected=1 if before_publication else 0,
                    contains='CancellationException' if before_publication else None)
                assert run(name + '-recovery', config, debug, 'recover')['outcome'] == (
                    'RECOVERED_ABORT' if before_publication else 'UNCHANGED')
            name = mode + '-sync-failure'
            debug = fresh(name)
            if mode != 'install':
                run(name + '-baseline', configs[0], debug, 'install')
            config = configs[1] if mode == 'update' else configs[0]
            run(name, config, debug, mode, ['failPublicationSync=true'], expected=1, contains='injected publication sync failure')
            assert run(name + '-recovery', config, debug, 'recover')['outcome'] == 'RECOVERED_COMMIT'

        debug = fresh('foreign-registration')
        leaf = registration(debug)
        leaf.parent.mkdir(parents=True)
        leaf.write_bytes(b'foreign debug artifact\n')
        saved = leaf.read_bytes()
        run('foreign-refused', configs[0], debug, 'install', expected=1, contains='registration is foreign')
        assert leaf.read_bytes() == saved
        for kind in ['source', 'sidecar', 'evidence', 'manifest', 'validator-log']:
            name = 'tampered-' + kind
            debug = fresh(name)
            installed = run(name + '-baseline', configs[0], debug, 'install')
            generation = Path(installed['source']).parent.parent
            paths = {'source': Path(installed['source']), 'sidecar': generation / 'installed.debug',
                'evidence': generation / 'validation.json', 'manifest': generation / 'generation.json'}
            paths['validator-log'] = next(p for p in generation.rglob('tool.stdout') if p.is_file())
            path = paths[kind]
            data = path.read_bytes()
            stamp = path.stat()
            path.write_bytes(data + b'changed')
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            registered = digest(registration(debug))
            run(name, configs[0], debug, 'remove', expected=1, contains='no longer matches')
            assert digest(registration(debug)) == registered
            path.write_bytes(data)
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            assert run(name + '-restored', configs[0], debug, 'remove')['outcome'] == 'REMOVED'
        debug = fresh('locking')
        installed = run('locking-baseline', configs[0], debug, 'install')
        lock = state_file(debug).with_name('lock')
        before = snapshot(debug)
        with lock.open('r+b') as held:
            fcntl.lockf(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            run('locking-refused', configs[1], debug, 'update', expected=1, contains='installation is busy')
        assert before == snapshot(debug)
        assert run('locking-released', configs[1], debug, 'update')['outcome'] == 'UPDATED'

        debug = fresh('moved-root')
        run('moved-root-baseline', configs[0], debug, 'install')
        moved = debug.with_name('moved-root-renamed')
        before = snapshot(debug)
        debug.rename(moved)
        try:
            run('moved-root-refused', configs[0], moved, 'recover', expected=1, contains='debug root moved')
            assert snapshot(moved) == before
        finally:
            moved.rename(debug)
        assert run('moved-root-restored', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'

        debug = fresh('linked-directory')
        elsewhere = fresh('linked-directory-destination')
        (debug / '.build-id').symlink_to(elsewhere, target_is_directory=True)
        run('linked-directory-refused', configs[0], debug, 'install', expected=1, contains='non-link directory')
        assert not list(elsewhere.iterdir())

        debug = fresh('registration-aliases')
        run('registration-aliases-baseline', configs[0], debug, 'install')
        leaf = registration(debug)
        saved = leaf.with_name('saved.debug')
        leaf.rename(saved)
        leaf.symlink_to(saved)
        run('registration-symlink-refused', configs[0], debug, 'remove', expected=1)
        assert leaf.is_symlink()
        leaf.unlink()
        saved.rename(leaf)
        os.link(leaf, saved)
        run('registration-hardlink-refused', configs[0], debug, 'remove', expected=1)
        assert leaf.stat().st_nlink == 2
        saved.unlink()
        assert run('registration-aliases-restored', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'

        debug = fresh('record-controls')
        run('record-controls-baseline', configs[0], debug, 'install')
        record = state_file(debug)
        saved = record.read_bytes()
        stamp = record.stat()
        original_state = json.loads(saved)
        malformed = {
            'duplicate': (b'{"schema":"duplicate",' + saved.lstrip()[1:], 'duplicate build-ID record member'),
            'unknown': (json.dumps(dict(original_state, unexpected='value')).encode(), 'unknown or missing'),
            'escape': (json.dumps(dict(original_state, operationId='../outside')).encode(), 'installation UUID'),
        }
        for kind, (data, message) in malformed.items():
            record.write_bytes(data)
            before = snapshot(debug)
            run('record-' + kind + '-refused', configs[0], debug, 'recover', expected=1, contains=message)
            assert before == snapshot(debug)
        record.write_bytes(saved)
        os.utime(record, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        assert run('record-controls-restored', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'

        debug = fresh('recovery-conflict')
        run('recovery-conflict-baseline', configs[0], debug, 'install')
        run('recovery-conflict-crash', configs[1], debug, 'update', ['crash=PREPARED'], expected=73)
        leaf = registration(debug)
        saved = leaf.read_bytes()
        stamp = leaf.stat()
        leaf.write_bytes(b'foreign bytes after interrupted update\n')
        before = snapshot(debug)
        run('recovery-conflict-refused', configs[0], debug, 'recover', expected=1, contains='neither prepared state')
        assert before == snapshot(debug)
        leaf.write_bytes(saved)
        os.utime(leaf, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        assert run('recovery-conflict-restored', configs[0], debug, 'recover')['outcome'] == 'RECOVERED_ABORT'

        debug = fresh('transaction-directory')
        run('transaction-directory-crash', configs[0], debug, 'install', ['crash=PREPARED'], expected=73)
        record = json.loads(state_file(debug).read_text())
        transaction = state_file(debug).parent / 'transactions' / record['operationId']
        saved = transaction.with_name('saved-transaction')
        transaction.rename(saved)
        transaction.mkdir()
        for path in saved.iterdir():
            path.rename(transaction / path.name)
        before = snapshot(debug)
        run('transaction-directory-refused', configs[0], debug, 'recover', expected=1, contains='transaction directory changed')
        assert before == snapshot(debug)
        for path in transaction.iterdir():
            path.rename(saved / path.name)
        transaction.rmdir()
        saved.rename(transaction)
        assert run('transaction-directory-restored', configs[0], debug, 'recover')['outcome'] == 'RECOVERED_ABORT'

        debug = fresh('retained-export')
        installed = run('retained-export-baseline', configs[0], debug, 'install')
        generation = Path(installed['source']).parent.parent
        retained = json.loads(configs[0].read_text())
        for key, name in [('sidecar', 'export.dbg'), ('source', 'export.source'), ('report', 'export.json')]:
            retained['files'][key] = str(generation / name)
        config = root / 'retained-export.json'
        config.write_text(json.dumps(retained, indent=4) + '\n')
        destination = fresh('retained-export-reinstalled')
        hidden = []
        try:
            for key in ['sidecar', 'source', 'report']:
                path = Path(values[0]['files'][key])
                temporary = path.with_name(path.name + '.retained-export-hidden')
                assert not temporary.exists()
                path.rename(temporary)
                hidden.append((path, temporary))
            assert run('retained-export-reinstall', config, destination, 'install')['outcome'] == 'INSTALLED'
        finally:
            for path, temporary in reversed(hidden):
                assert not path.exists()
                temporary.rename(path)

    assert protected == {path: digest(path) for path in protected}
    result = {'status': 'PASS_BUILD_ID_TRANSACTION_' + args.host.upper() + '_HOST', 'checks': checks, 'consumers': consumers,
        'protectedInputs': protected, 'host': args.host,
        'scope': 'Production install/update/remove/recovery and structural validators; '
            'real Linux atomic rename, fsync and OS locks. ' + (
                'Test-only metadata adapter. ' if args.host == 'model' else
                'Production Linux ext4 host: ordinary permissions/ownership/mtime, visible user xattrs and access ACLs; '
                'no hidden-metadata or power-loss claim. ') +
            'Public launcher and full consumer acceptance remain required.'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print('build-id-installation=PASS checks=' + str(len(checks)) + ' consumers=' + str(len(consumers)), flush=True)


if __name__ == '__main__':
    main()

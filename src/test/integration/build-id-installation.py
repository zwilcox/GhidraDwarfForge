#!/usr/bin/env python3
"""Real build-ID transaction/validator tests with an explicitly test-only Linux metadata host."""
import argparse
import copy
from contextlib import nullcontext
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zlib
from integration_coverage import Collection


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
    jars = [Path(path) for path in args.classpath.split(os.pathsep)
        if Path(path).name == 'GhidraDwarfForge.jar']
    if os.environ.get('FORGE_INTEGRATION_COVERAGE_OUTPUT') and len(jars) != 1:
        raise ValueError('coverage requires one production JAR in the probe classpath')
    coverage = Collection('build-id-installation', jars[0] if jars else None, 'native-java',
        test_classes=('ghidradwarfforge.output.BuildIdInstallationProbe',
            'ghidradwarfforge.output.AttachmentElfTransactionProbe',
            'ghidradwarfforge.output.AttachmentReceiptStoreSmoke'))
    commands, checks, consumers = [], [], []
    script_root = Path(__file__).resolve().parent

    def run(name, config, debug, action, properties=(), expected=0, contains=None):
        command = prefix + ['-Dforge.test.buildId.' + value for value in properties] + [
            'ghidradwarfforge.output.BuildIdInstallationProbe', str(config), str(debug), action]
        row = {'name': name, 'command': command}
        commands.append(row)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        forced_halt = any(value.startswith('crash=') for value in properties)
        if forced_halt:
            assert expected == 73, 'forced-halt control must verify its exit status'
        session = nullcontext(command) if forced_halt else coverage.session(command, name)
        with session as measured:
            row['executedCommand'] = measured
            completed = subprocess.run(measured, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
            row['exit'] = completed.returncode
            (root / (name + '.log')).write_text(completed.stdout)
            (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
            assert completed.returncode == expected, (name, completed.returncode, completed.stdout[-5000:])
            if contains:
                assert contains in completed.stdout, (name, completed.stdout[-5000:])
            result = json.loads(completed.stdout) if expected == 0 else None
            checks.append({'name': name, 'exit': completed.returncode, 'outcome': result['outcome'] if result else None})
            if forced_halt:
                coverage.record_forced_halt(name, completed.returncode)
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

    def metadata_snapshot(debug):
        return {str(p.relative_to(debug)): (p.stat().st_mode, p.stat().st_uid,
            p.stat().st_gid, p.stat().st_mtime_ns, p.stat().st_nlink)
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
        debug = fresh('empty-recovery')
        assert run('empty-recovery', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'
        assert not registration(debug).exists() and not state_file(debug).exists()
        before = snapshot(debug)
        run('empty-update-refused', configs[1], debug, 'update', expected=1,
            contains='no managed installation exists to update')
        assert before == snapshot(debug)
        run('empty-remove-refused', configs[0], debug, 'remove', expected=1,
            contains='no managed installation exists to remove')
        assert before == snapshot(debug)
        debug = fresh('invalid-build-ids')
        for index, invalid in enumerate(['', 'ABCDEF', 'gg', 'abc', 'ab' * 125, '../outside']):
            config = copy.deepcopy(values[0])
            config['buildId'] = invalid
            config_path = root / ('invalid-build-id-' + str(index) + '.json')
            config_path.write_text(json.dumps(config, indent=4) + '\n')
            run('invalid-build-id-' + str(index), config_path, debug, 'recover', expected=1,
                contains='build ID must be canonical lowercase hex')
            assert not list(debug.iterdir()), 'invalid ID created installation paths'
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
        # Mutate a record emitted by a real, validated installation. A refusal
        # must preserve the registration, retained generations and record itself;
        # restoring that record must still permit ordinary recovery below.
        for field, replacement, message in [
                ('schema', 'foreign-state-v1', 'installation record contract differs'),
                ('buildId', '00', 'installation record contract differs'),
                ('hostContract', 'foreign-host', 'installation record contract differs'),
                ('durability', 'foreign-durability', 'installation record contract differs'),
                ('originalSha256', 'a' * 63, 'invalid installation content hash'),
                ('originalSha256', 'A' * 64, 'invalid installation content hash'),
                ('operationId', '00000000-0000-0000-0000-00000000000A', 'noncanonical installation UUID'),
                ('phase', 'PUBLISHING', 'unknown installation phase'),
                ('mode', 'REPLACE', 'invalid installation transition'),
                ('mode', 'UPDATE', 'invalid installation transition'),
                ('mode', 'REMOVE', 'invalid installation transition'),
                ('before', original_state['after'], 'invalid installation transition'),
                ('after', None, 'invalid installation transition'),
                ('directories', {}, 'recorded installation directories changed')]:
            changed = copy.deepcopy(original_state)
            changed[field] = replacement
            label = field + '-' + str(len(malformed))
            malformed[label] = (json.dumps(changed).encode(), message)
        for field in ['before', 'after']:
            changed = copy.deepcopy(original_state)
            del changed[field]
            malformed['missing-' + field] = (json.dumps(changed).encode(), 'unknown or missing')
        for mode, after in [('UPDATE', None), ('REMOVE', original_state['after'])]:
            changed = copy.deepcopy(original_state)
            changed.update(mode=mode, before=original_state['after'], after=after)
            malformed[mode.lower() + '-invalid-after'] = (json.dumps(changed).encode(),
                'invalid installation transition')
        changed = copy.deepcopy(original_state)
        changed['after']['generation'] = '00000000-0000-0000-0000-000000000000'
        assert changed['after']['generation'] != changed['operationId']
        malformed['wrong-generation'] = (json.dumps(changed).encode(), 'prepared generation differs from operation')
        for kind, (data, message) in malformed.items():
            record.write_bytes(data)
            before = snapshot(debug)
            metadata = metadata_snapshot(debug)
            run('record-' + kind + '-refused', configs[0], debug, 'recover', expected=1, contains=message)
            assert before == snapshot(debug)
            assert metadata == metadata_snapshot(debug)
        record.write_bytes(saved)
        os.utime(record, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
        assert run('record-controls-restored', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'

        debug = fresh('generation-controls')
        installed = run('generation-controls-baseline', configs[0], debug, 'install')
        generation = Path(installed['source']).parent.parent
        manifest_path, record = generation / 'generation.json', state_file(debug)
        saved_manifest, saved_record = manifest_path.read_bytes(), record.read_bytes()
        manifest_stamp, record_stamp = manifest_path.stat(), record.stat()
        manifest, state = json.loads(saved_manifest), json.loads(saved_record)
        malformed = {}
        for field, replacement, message in [
                ('schema', 'foreign-generation-v1', 'generation identity differs'),
                ('buildId', '00', 'generation identity differs'),
                ('originalSha256', '0' * 64, 'generation original differs from installation state'),
                ('contentKey', '0' * 64, 'generation key differs from retained inputs'),
                ('sourceName', 'nested/source.c', 'retained source must be a leaf'),
                ('sourceName', '../outside.c', 'normalized relative path'),
                ('directories', {}, 'generation directories changed')]:
            changed = copy.deepcopy(manifest)
            assert changed[field] != replacement
            changed[field] = replacement
            malformed[field + '-' + str(len(malformed))] = (changed, message)
        for name in ['export.json', 'export.dbg', 'export.source', 'installed.debug',
                'validation.json', 'source/' + manifest['sourceName']]:
            changed = copy.deepcopy(manifest)
            del changed['files'][name]
            malformed['missing-' + name.replace('/', '-')] = (changed, 'generation inventory is incomplete')
        changed = copy.deepcopy(manifest)
        changed['files']['unlisted.debug'] = changed['files']['installed.debug']
        malformed['extra-file'] = (changed, 'generation file inventory changed')
        changed = copy.deepcopy(manifest)
        # The supported 65,536-part policy has separate exported/retained
        # inventories plus overhead. This bounded JSON crosses its file-count
        # limit without creating a large filesystem tree or hitting byte limits.
        changed['files'].update(('excess-' + str(index), None) for index in range(132000))
        malformed['oversized-inventory'] = (changed, 'generation inventory is incomplete')

        def bind_manifest(changed):
            # Rebind only the changed record's content digest, count and CRC.
            # Preserve the real inode and supported metadata, including mtime,
            # so recovery must inspect semantics beyond the outer file hash.
            data = (json.dumps(changed, indent=4) + '\n').encode()
            manifest_path.write_bytes(data)
            os.utime(manifest_path, ns=(manifest_stamp.st_atime_ns, manifest_stamp.st_mtime_ns))
            rebound = copy.deepcopy(state)
            rebound['after']['manifest'].update(sha256=hashlib.sha256(data).hexdigest(),
                bytes=str(len(data)), crc32=str(zlib.crc32(data)))
            record.write_text(json.dumps(rebound, indent=4) + '\n')
            return rebound

        def reject_generation(name, message):
            before, metadata = snapshot(debug), metadata_snapshot(debug)
            run('generation-' + name + '-refused', configs[0], debug, 'recover', expected=1, contains=message)
            assert before == snapshot(debug) and metadata == metadata_snapshot(debug)

        try:
            for kind, (changed, message) in malformed.items():
                bind_manifest(changed)
                reject_generation(kind, message)
            rebound = bind_manifest(manifest)
            rebound['after']['registration']['sha256'] = '0' * 64
            record.write_text(json.dumps(rebound, indent=4) + '\n')
            reject_generation('registration-digest', 'registration does not describe retained sidecar')
            source = Path(installed['source'])
            saved_source, source_stamp = source.read_bytes(), source.stat()
            try:
                data = saved_source + b'\n/* inconsistent retained source */\n'
                source.write_bytes(data)
                os.utime(source, ns=(source_stamp.st_atime_ns, source_stamp.st_mtime_ns))
                changed = copy.deepcopy(manifest)
                changed['files']['source/' + manifest['sourceName']].update(
                    sha256=hashlib.sha256(data).hexdigest(), bytes=str(len(data)), crc32=str(zlib.crc32(data)))
                bind_manifest(changed)
                reject_generation('source-content', 'retained source hash differs')
            finally:
                source.write_bytes(saved_source)
                os.utime(source, ns=(source_stamp.st_atime_ns, source_stamp.st_mtime_ns))
        finally:
            manifest_path.write_bytes(saved_manifest)
            record.write_bytes(saved_record)
            os.utime(manifest_path, ns=(manifest_stamp.st_atime_ns, manifest_stamp.st_mtime_ns))
            os.utime(record, ns=(record_stamp.st_atime_ns, record_stamp.st_mtime_ns))
        assert run('generation-controls-restored', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'

        # Neither a link nor a FIFO is a retained regular artifact. A FIFO must
        # be rejected without opening it and waiting for a writer.
        for kind in ['symlink', 'fifo']:
            extra = generation / ('unsupported-' + kind)
            if kind == 'symlink':
                extra.symlink_to(Path(installed['source']))
            else:
                os.mkfifo(extra)
            identity = extra.lstat()
            try:
                reject_generation(kind, 'generation contains a ' + (
                    'symbolic link' if kind == 'symlink' else 'non-regular file'))
                after = extra.lstat()
                assert (identity.st_dev, identity.st_ino, identity.st_mode, identity.st_nlink) == (
                    after.st_dev, after.st_ino, after.st_mode, after.st_nlink)
                if kind == 'symlink':
                    assert extra.readlink() == Path(installed['source'])
            finally:
                extra.unlink()
        assert run('generation-tree-restored', configs[0], debug, 'recover')['outcome'] == 'UNCHANGED'

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
    coverage.finish(root / 'result.json')
    print('build-id-installation=PASS checks=' + str(len(checks)) + ' consumers=' + str(len(consumers)), flush=True)


if __name__ == '__main__':
    main()

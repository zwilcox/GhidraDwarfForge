#!/usr/bin/env python3
"""Independent native metadata oracle for owned files and isolated Java 21 calls."""

import argparse
import array
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inode_policy(path):
    with Path(path).open('rb') as stream:
        flags = array.array('I', [0])
        fcntl.ioctl(stream.fileno(), 0x80086601, flags, True)
        extended = bytearray(28)
        fcntl.ioctl(stream.fileno(), 0x801c581f, extended, True)
        xflags, extent, count, project, cow = struct.unpack('<5I', extended[:20])
        assert not any(extended[20:])
        return {'flags': flags[0], 'extendedFlags': xflags, 'extentSize': extent,
                'projectId': project, 'cowExtentSize': cow}


def set_inode_flags(path, value):
    with Path(path).open('rb') as stream:
        fcntl.ioctl(stream.fileno(), 0x40086602, array.array('I', [value]))


def facts(path):
    info = path.lstat()
    attributes = {os.fsencode(name).hex(): os.getxattr(path, name, follow_symlinks=False).hex()
                  for name in os.listxattr(path, follow_symlinks=False)}
    return {'mode': info.st_mode, 'uid': info.st_uid, 'gid': info.st_gid,
            'mtime': info.st_mtime_ns, 'ctime': info.st_ctime_ns, 'links': info.st_nlink,
            'identity': f'{os.major(info.st_dev)}:{os.minor(info.st_dev)}:{info.st_ino}',
            'bytes': info.st_size, 'attributes': attributes, 'inodePolicy': inode_policy(path), 'sha256': sha(path)}


def acl(named_uid):
    entries = [(1, 7, 0xffffffff), (2, 4, named_uid), (4, 0, 0xffffffff),
               (16, 4, 0xffffffff), (32, 0, 0xffffffff)]
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)


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
    source = ROOT / 'src/test/java/ghidradwarfforge/output/LinuxFileMetadataProbe.java'
    contract = ROOT / 'src/test/native/linux-metadata-contract.c'
    files = [args.jar.resolve(), args.ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar',
             args.ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar', source, contract, Path(__file__),
             ROOT / 'src/main/java/ghidradwarfforge/output/LinuxFileMetadata.java']
    original_hashes = {str(path): sha(path) for path in files}
    for path in files:
        shutil.copyfile(path, provenance / path.name)
        assert sha(provenance / path.name) == original_hashes[str(path)]
    (provenance / 'origin.json').write_text(json.dumps(original_hashes, indent=4) + '\n')
    commands = []

    def run(label, command, success=True):
        command = list(map(str, command))
        outcome = subprocess.run(command, capture_output=True, timeout=30)
        (root / (label + '.stdout')).write_bytes(outcome.stdout)
        (root / (label + '.stderr')).write_bytes(outcome.stderr)
        commands.append({'label': label, 'argv': command, 'exit': outcome.returncode})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert (outcome.returncode == 0) == success, (label, outcome.stderr.decode(errors='replace'))
        return outcome

    run('compile-contract', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', provenance / contract.name,
                            '-o', root / 'contract'])
    run('native-contract', [root / 'contract'])
    classes = root / 'classes'
    classes.mkdir()
    dependencies = os.pathsep.join(str(provenance / path.name) for path in files[:3])
    run('compile-java', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', dependencies,
                        '-d', classes, provenance / source.name])
    java = os.environ.get('JAVA', 'java')
    assert b'version "21.' in run('java-version', [java, '-version']).stderr
    prefix = [java, '-cp', str(classes) + os.pathsep + dependencies, 'ghidradwarfforge.output.LinuxFileMetadataProbe']
    fixture = root / 'owned'
    fixture.mkdir()
    original = fixture / 'ordinary λ file'
    original.write_bytes(b'protected original ELF-like bytes\0\xff\n')
    os.chmod(original, 0o751)
    other_groups = sorted(set(os.getgroups()) - {os.getgid()})
    if other_groups:
        os.chown(original, -1, other_groups[0])
    os.utime(original, ns=(1700000000000000000, 1700000000123456789))
    os.setxattr(original, b'user.binary', b'\0\xff\n')
    os.setxattr(original, b'user.empty', b'')
    os.setxattr(original, b'user.\xff', b'non-UTF8 attribute name')
    observations = []

    def inspect(label, path):
        before = facts(path)
        result = json.loads(run(label, [*prefix, 'inspect', path]).stdout)
        native = result['facts']
        for field in ('mode', 'uid', 'gid', 'links', 'identity', 'bytes'):
            assert native[field] == before[field], (field, native, before)
        assert native['modifiedSeconds'] * 1000000000 + native['modifiedNanos'] == before['mtime']
        assert native['changedSeconds'] * 1000000000 + native['changedNanos'] == before['ctime']
        assert result['visibleAttributes'] == before['attributes']
        assert result['inodePolicy'] == before['inodePolicy']
        assert facts(path) == before
        observations.append({'case': label, 'independent': before, 'java': result})
        return root / (label + '.stdout')

    def preservation(label, path, stage):
        snapshot = inspect(label + '-before', path)
        before = facts(path)
        stage_before = facts(stage)
        run(label, [*prefix, 'apply', path, stage, snapshot, '-1'])
        after = facts(stage)
        for field in ('mode', 'uid', 'gid', 'mtime', 'attributes', 'inodePolicy'):
            assert after[field] == before[field], (field, before, after)
        assert after['sha256'] == stage_before['sha256'] and after['identity'] == stage_before['identity']
        assert facts(path) == before
        inspect(label + '-after', stage)

    stage = fixture / 'private-stage'
    stage.write_bytes(b'new executable contents differ in size')
    os.setxattr(stage, b'user.unrelated', b'remove from the owned stage')
    preservation('plain', original, stage)
    acl_source = fixture / 'explicit-acl'
    shutil.copyfile(original, acl_source)
    os.setxattr(acl_source, 'system.posix_acl_access', acl(os.getuid() + 12345))
    os.setxattr(acl_source, b'user.acl-pair', b'\xff\0')
    os.utime(acl_source, ns=(1700000000000000000, 1700000000987654321))
    parent = fixture / 'default-acl'
    parent.mkdir()
    os.setxattr(parent, 'system.posix_acl_default', acl(os.getuid() + 23456))
    inherited = parent / 'private-inherited-stage'
    inherited.write_bytes(b'private stage with independently inherited ACL')
    assert os.getxattr(inherited, 'system.posix_acl_access') != os.getxattr(acl_source, 'system.posix_acl_access')
    preservation('explicit-over-inherited-acl', acl_source, inherited)
    preservation('remove-inherited-acl', original, inherited)
    for mode in [0o444, 0o555]:
        readonly = fixture / ('readonly-acl-' + oct(mode))
        shutil.copy2(acl_source, readonly)
        os.chmod(readonly, mode)
        owned = fixture / ('readonly-stage-' + oct(mode))
        owned.write_bytes(b'new private stage bytes')
        preservation('readonly-acl-' + oct(mode), readonly, owned)
    expected = inspect('stale-source-snapshot', original)
    os.setxattr(original, b'user.concurrent', b'changed after snapshot')
    before = facts(stage)
    refusal = run('stale-source', [*prefix, 'apply', original, stage, expected, '-1'], False)
    assert b'metadata source changed' in refusal.stderr and facts(stage) == before
    snapshot = inspect('cancel-source', original)
    before_source = facts(original)
    before_stage = facts(stage)
    for poll in (0, 5):
        refused = run('cancel-' + str(poll), [*prefix, 'apply', original, stage, snapshot, str(poll)], False)
        assert b'CancellationException' in refused.stderr and facts(original) == before_source
        assert facts(stage) == before_stage
    # Later cancellation may leave only the explicitly private stage partially
    # adjusted; source content/metadata must remain unchanged.
    refused = run('cancel-mid-application', [*prefix, 'apply', original, stage, snapshot, '20'], False)
    assert b'CancellationException' in refused.stderr and facts(original) == before_source
    # FS_NOATIME_FL is not represented by statx attributes. The old primitive
    # accepted this source and produced a stage without its inode policy.
    for label, selected in [('source-noatime', original), ('stage-noatime', stage)]:
        ordinary_flags = inode_policy(selected)['flags']
        set_inode_flags(selected, ordinary_flags | 0x80)
        try:
            snapshot = inspect(label + '-source', original)
            if selected == original:
                observed = json.loads(snapshot.read_text())
                assert observed['facts']['attributes'] == 0 and observed['inodePolicy']['flags'] & 0x80
            before_source, before_stage = facts(original), facts(stage)
            refused = run(label, [*prefix, 'apply', original, stage, snapshot, '-1'], False)
            assert b'unsupported inode flags' in refused.stderr
            assert facts(original) == before_source and facts(stage) == before_stage
        finally:
            set_inode_flags(selected, ordinary_flags)
    snapshot = inspect('stale-inode-policy', original)
    ordinary_flags = inode_policy(original)['flags']
    set_inode_flags(original, ordinary_flags | 0x80)
    try:
        before_stage = facts(stage)
        refused = run('stale-policy-rejection', [*prefix, 'apply', original, stage, snapshot, '-1'], False)
        assert b'metadata source changed' in refused.stderr and facts(stage) == before_stage
    finally:
        set_inode_flags(original, ordinary_flags)
    alias = fixture / 'hardlink'
    os.link(original, alias)
    snapshot = inspect('hardlink-source', original)
    before_source = facts(original)
    refused = run('hardlink-rejection', [*prefix, 'apply', original, stage, snapshot, '-1'], False)
    assert b'rejects hardlinks' in refused.stderr and facts(original) == before_source
    alias.unlink()
    snapshot = inspect('same-source', original)
    refused = run('same-file', [*prefix, 'apply', original, original, snapshot, '-1'], False)
    assert b'aliases source' in refused.stderr
    os.chmod(original, 0o4751)
    snapshot = inspect('setid-source', original)
    before_source = facts(original)
    refused = run('setid-rejection', [*prefix, 'apply', original, stage, snapshot, '-1'], False)
    assert b'privileged file mode' in refused.stderr and facts(original) == before_source
    os.chmod(original, 0o751)
    symbolic = fixture / 'symlink'
    symbolic.symlink_to(original)
    fifo = fixture / 'fifo'
    os.mkfifo(fifo)
    for label, path in (('symlink', symbolic), ('fifo', fifo), ('directory', fixture)):
        refused = run(label, [*prefix, 'inspect', path], False)
        assert b'regular non-link file' in refused.stderr
    run('native-descriptor-lifetime', [*prefix, 'leak-controls', original, fifo])
    assert all(sha(path) == expected for path, expected in original_hashes.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'observations': observations,
        'supplementaryGroupApplication': bool(other_groups),
        'scope': 'visible metadata and private-stage application; not complete host admission or hidden namespace proof'}, indent=4) + '\n')
    print('linux-file-metadata=PASS')


if __name__ == '__main__':
    main()

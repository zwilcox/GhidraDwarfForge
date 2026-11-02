#!/usr/bin/env python3
"""Build a private pinned ARM QEMU reference; never install over system tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import urllib.request

VERSION = '8.2.2'
SOURCE_SHA256 = '847346c1b82c1a54b2c38f6edbd85549edeb17430b7d4d3da12620e2962bc4f3'
PATCH_SHA256 = 'e1b8d5a11ec610961c10bc2b6d2af9c65be86340bf1ecbadb837d98c26b07f2f'
URL = 'https://download.qemu.org/qemu-' + VERSION + '.tar.xz'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='new private directory')
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--dependency-root', type=Path, help='optional extracted Ubuntu development packages')
    parser.add_argument('--jobs', type=int, default=4)
    parser.add_argument('--correct-d-register-writes', action='store_true')
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be between 1 and 32')
    root = args.directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    archive = args.archive.resolve(strict=True) if args.archive else root / ('qemu-' + VERSION + '.tar.xz')
    if not args.archive:
        with urllib.request.urlopen(URL, timeout=60) as response, archive.open('xb') as output:
            while block := response.read(1024 * 1024):
                output.write(block)
    assert digest(archive) == SOURCE_SHA256, 'source archive does not match pinned SHA-256'
    skipped = []

    def filter_member(member, path):
        try:
            return tarfile.data_filter(member, path)
        except tarfile.AbsoluteLinkError:
            # This firmware-only host-header link is not used by linux-user.
            assert member.name == 'qemu-8.2.2/roms/edk2/EmulatorPkg/Unix/Host/X11IncludeHack'
            skipped.append({'name': member.name, 'link': member.linkname})
            return None

    with tarfile.open(archive) as source:
        source.extractall(root, filter=filter_member)
    (root / 'extraction.json').write_text(json.dumps({'skipped': skipped}, indent=4) + '\n')
    source = root / ('qemu-' + VERSION)
    build = root / 'build'
    build.mkdir()
    env = dict(os.environ)
    if args.dependency_root:
        deps = args.dependency_root.resolve(strict=True)
        env.update(PATH=str(deps / 'usr/bin') + ':' + env['PATH'],
            PKG_CONFIG_PATH=str(deps / 'usr/lib/x86_64-linux-gnu/pkgconfig'),
            PKG_CONFIG_SYSROOT_DIR=str(deps), LD_LIBRARY_PATH=str(deps / 'usr/lib/x86_64-linux-gnu'))
    commands = []

    def run(name, command, cwd=build):
        command = list(map(str, command))
        commands.append({'name': name, 'command': command, 'cwd': str(cwd)})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (name + '.log')).open('w') as output:
            process = subprocess.Popen(command, cwd=cwd, env=env,
                stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                status = process.wait(timeout=1800)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                raise
        if status:
            raise subprocess.CalledProcessError(status, command)

    patch = Path(__file__).with_name('qemu-8.2.2-arm-d-register-byte-order.patch').resolve()
    patch_digest = None
    original_stub = digest(source / 'target/arm/gdbstub.c')
    if args.correct_d_register_writes:
        patch_digest = digest(patch)
        assert patch_digest == PATCH_SHA256, 'register-write patch does not match pinned SHA-256'
        run('patch', ['patch', '--batch', '--fuzz=0', '-p1', '-i', patch], source)
    run('configure', [source / 'configure', '--target-list=arm-linux-user,armeb-linux-user',
        '--disable-system', '--disable-docs', '--disable-tools', '--disable-guest-agent',
        '--disable-werror', '--without-default-features'])
    run('build', ['ninja', '-j' + str(args.jobs), 'qemu-arm', 'qemu-armeb'])
    executables = {}
    for name in ('qemu-arm', 'qemu-armeb'):
        executable = build / name
        run(name + '-version', [executable, '--version'])
        executables[name] = {'path': str(executable), 'sha256': digest(executable)}
    (root / 'receipt.json').write_text(json.dumps({'version': VERSION, 'sourceUrl': URL,
        'sourceSha256': SOURCE_SHA256, 'patchSha256': patch_digest,
        'originalStubSha256': original_stub, 'finalStubSha256': digest(source / 'target/arm/gdbstub.c'),
        'correctedDRegisterWrites': args.correct_d_register_writes, 'executables': executables,
        'systemInstallationChanged': False, 'environment': {k: env.get(k) for k in
            ('PATH', 'PKG_CONFIG_PATH', 'PKG_CONFIG_SYSROOT_DIR', 'LD_LIBRARY_PATH')}}, indent=4) + '\n')
    print('arm-qemu-build=PASS ' + str(root), flush=True)


if __name__ == '__main__':
    main()

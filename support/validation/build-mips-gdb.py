#!/usr/bin/env python3
"""Build the pinned, unmodified MIPS debugger used by register-piece acceptance."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import urllib.request

VERSION = '17.1'
ARCHIVE_SHA256 = '14996f5f74c9f68f5a543fdc45bca7800207f91f92aeea6c2e791822c7c6d876'
URL = 'https://ftp.gnu.org/gnu/gdb/gdb-' + VERSION + '.tar.xz'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='new scratch directory; never the system installation')
    parser.add_argument('--archive', type=Path, help='optional already downloaded, checksum-verified source')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error('--jobs must be between 1 and 32')
    root = args.directory.resolve()
    root.mkdir(parents=True, exist_ok=False)
    archive = args.archive.resolve(strict=True) if args.archive else root / ('gdb-' + VERSION + '.tar.xz')
    if not args.archive:
        with urllib.request.urlopen(URL, timeout=60) as response, archive.open('xb') as output:
            while block := response.read(1024 * 1024):
                output.write(block)
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != ARCHIVE_SHA256:
        raise ValueError('GDB source archive SHA-256 does not match the pinned release')
    with tarfile.open(archive) as source:
        source.extractall(root, filter='data')
    build = root / 'build'
    build.mkdir()
    commands = []

    def run(name, command, cwd=build):
        commands.append(dict(name=name, argv=list(map(str, command)), cwd=str(cwd)))
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (name + '.log')).open('w') as output:
            process = subprocess.Popen(list(map(str, command)), cwd=cwd,
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
                    pass
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
        if status:
            raise subprocess.CalledProcessError(status, command)

    for tool in ('gcc', 'g++', 'make', 'python3'):
        run(tool + '-version', [tool, '--version'])
    run('configure', [root / ('gdb-' + VERSION) / 'configure',
        '--target=mips64-linux-gnu', '--enable-targets=mips-linux-gnu,mips64-linux-gnu',
        '--with-python=/usr/bin/python3', '--without-guile', '--without-debuginfod',
        '--disable-gdbtk', '--disable-tui', '--disable-werror', '--disable-binutils',
        '--disable-gas', '--disable-ld', '--disable-gprof', '--disable-gold', '--disable-sim'])
    run('make', ['make', '-j' + str(args.jobs), 'all-gdb'])
    executable = build / 'gdb/gdb'
    data = build / 'gdb/data-directory'
    run('gdb-version', [executable, '--data-directory=' + str(data), '--version'])
    run('gdb-python', [executable, '--data-directory=' + str(data), '-nx', '-q', '-batch',
        '-ex', 'python import gdb; print("FORGE_GDB_PYTHON_PASS")'])
    assert 'FORGE_GDB_PYTHON_PASS' in (root / 'gdb-python.log').read_text()
    with executable.open('rb') as stream:
        executable_sha256 = hashlib.file_digest(stream, 'sha256').hexdigest()
    (root / 'receipt.json').write_text(json.dumps(dict(version=VERSION, sourceUrl=URL,
        sourceSha256=digest, executable=str(executable), executableSha256=executable_sha256,
        dataDirectory=str(data), modifiedSource=False, systemInstallationChanged=False), indent=4) + '\n')
    print('mips-gdb-build=PASS ' + str(root), flush=True)


if __name__ == '__main__':
    main()

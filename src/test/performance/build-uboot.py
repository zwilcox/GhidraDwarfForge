#!/usr/bin/env python3
"""Build the pinned U-Boot sandbox firmware-code workload; retain build evidence."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile

SOURCE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('benchmark_support', SOURCE / 'export-benchmark.py')
SUPPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUPPORT)
VERSION = '2025.01'
ARCHIVE_SHA256 = 'cdef7d507c93f1bbd9f015ea9bc21fa074268481405501945abc6f854d5b686f'
URLS = [f'https://ftp.denx.de/pub/u-boot/u-boot-{VERSION}.tar.bz2',
    f'https://ftp-osl.osuosl.org/pub/u-boot/u-boot-{VERSION}.tar.bz2']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='Previously downloaded archive (SHA-256 still checked)')
    parser.add_argument('--results', type=Path, default=SOURCE.parents[2] / 'build/test-results/uboot-build')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 16:
        parser.error('jobs must be between 1 and 16')
    for tool in ('make', 'gcc', 'bison', 'flex', 'm4', 'swig', 'cert-to-efi-sig-list', 'objcopy', 'readelf'):
        if shutil.which(tool) is None:
            parser.error('missing build dependency: ' + tool)
    args.results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=args.results.resolve()))
    print(case, flush=True)
    recipes = {str(p): SUPPORT.digest(p) for p in
        (Path(__file__).resolve(), SOURCE / 'export-benchmark.py')}
    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')
    def run(name, command, **kwargs):
        return SUPPORT.run(command, case / (name + '.log'), **kwargs)
    archive = case / 'u-boot.tar.bz2'
    origin = str(args.archive.resolve()) if args.archive else None
    if args.archive:
        shutil.copyfile(args.archive, archive)
    else:
        failures = []
        for index, url in enumerate(URLS):
            try:
                run(f'download-{index}', ['curl', '--fail', '--location', '--connect-timeout', '10',
                    '--max-time', '120', url, '--output', archive], timeout=130)
                origin = url
                break
            except Exception as failure:
                failures.append(str(failure))
                write('download-failures.json', failures)
        if origin is None:
            raise RuntimeError('all pinned source mirrors failed; see retained download logs')
    if SUPPORT.digest(archive) != ARCHIVE_SHA256:
        raise ValueError('U-Boot source archive SHA-256 mismatch')
    with tarfile.open(archive) as packed:
        packed.extractall(case, filter='data')
    tree = case / ('u-boot-' + VERSION)
    build = case / 'objects'
    # Reproducible build timestamp and identity, independent of the local account.
    os.environ.update(SOURCE_DATE_EPOCH='1736121600', KBUILD_BUILD_USER='forge-benchmark',
        KBUILD_BUILD_HOST='forge-benchmark', KBUILD_BUILD_VERSION='1')
    make = ['make', '-C', tree, 'O=' + str(build)]
    for tool in ('gcc', 'make', 'bison', 'flex', 'm4', 'swig', 'objcopy', 'readelf'):
        run('version-' + tool, [tool, '--version' if tool != 'swig' else '-version'])
    run('configure', [*make, 'sandbox_defconfig'])
    run('configure-headless', [tree / 'scripts/config', '--file', build / '.config',
        '-d', 'SANDBOX_SDL', '-d', 'VIDEO_SANDBOX_SDL', '-d', 'TOOLS_MKEFICAPSULE'])
    metrics = run('build', [*make, '-j' + str(args.jobs), 'u-boot', 'u-boot.dtb'],
        measured=True, timeout=1800)
    # The compiler reference remains intact; only this new fixture copy loses DWARF.
    reference = case / 'u-boot.reference'
    binary = case / 'u-boot.workload'
    shutil.copyfile(build / 'u-boot', reference)
    reference.chmod(0o755)
    run('strip-fixture-copy', ['objcopy', '--strip-debug', reference, binary])
    binary.chmod(0o755)
    shutil.copyfile(build / 'u-boot.dtb', case / 'u-boot.dtb')
    shutil.copyfile(build / '.config', case / 'build.config')
    run('elf', ['readelf', '-h', '-SW', '-n', binary])
    SUPPORT.require_clean(case / 'elf.log')
    if '.debug_info' in (case / 'elf.log').read_text():
        raise ValueError('workload still contains compiler debug information')
    run('plain', [binary, '-d', case / 'u-boot.dtb', '-c', 'echo forge-uboot-workload=PASS'],
        cwd=case, timeout=60)
    if 'forge-uboot-workload=PASS' not in (case / 'plain.log').read_text().splitlines():
        raise ValueError('U-Boot sandbox command did not execute')
    if any(SUPPORT.digest(Path(path)) != digest for path, digest in recipes.items()):
        raise ValueError('workload build recipes changed during the build')
    write('build-result.json', {'status': 'PASS', 'version': VERSION, 'archiveOrigin': origin,
        'sourceMirrors': URLS, 'recipes': recipes,
        'archiveSha256': ARCHIVE_SHA256, 'sourceDateEpoch': 1736121600,
        'configuration': 'sandbox_defconfig without SDL and capsule creation tool',
        'license': 'U-Boot source license terms in retained Licenses/ and README; GPL-2.0+ with per-file exceptions',
        'build': metrics, 'artifacts': {p.name: {'sha256': SUPPORT.digest(p), 'bytes': p.stat().st_size}
            for p in (reference, binary, case / 'u-boot.dtb', case / 'build.config')},
        'scope': 'Host sandbox firmware code; no target hardware emulation claim. '
            'Build/runtime sanity only, not exporter/validator/GDB acceptance.'})
    print('uboot-build=PASS ' + str(case), flush=True)


if __name__ == '__main__':
    main()

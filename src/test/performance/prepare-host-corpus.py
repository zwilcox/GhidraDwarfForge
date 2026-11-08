#!/usr/bin/env python3
"""Build pinned Linux ELF inputs once for Windows host export and Linux replay."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import zipfile

SOURCE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), SOURCE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='New corpus directory; existing outputs are rejected')
    parser.add_argument('--uboot-build', type=Path, help='Reuse a verified build receipt instead of rebuilding')
    parser.add_argument('--sqlite-archive', type=Path, help='Reuse pinned SQLite archive; digest still checked')
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    support, sqlite = load('export-benchmark'), load('sqlite-benchmark')
    logs = root / 'build-evidence'
    logs.mkdir()
    def run(name, command, **kwargs):
        return support.run(command, logs / (name + '.log'), **kwargs)
    sources = root / 'sources'
    sources.mkdir()
    archive = sources / 'sqlite-amalgamation-3460100.zip'
    if args.sqlite_archive:
        shutil.copyfile(args.sqlite_archive, archive)
    else:
        run('sqlite-download', ['curl', '-fL', '--retry', '3', '--max-time', '120', sqlite.URL, '-o', archive])
    assert support.digest(archive) == sqlite.ARCHIVE_SHA256
    tree = root / 'sqlite'
    tree.mkdir()
    with zipfile.ZipFile(archive) as packed:
        for name in ('sqlite3.c', 'sqlite3.h'):
            (tree / name).write_bytes(packed.read('sqlite-amalgamation-3460100/' + name))
    assert hashlib.sha3_256((tree / 'sqlite3.c').read_bytes()).hexdigest() == sqlite.SOURCE_SHA3
    assert ('#define SQLITE_SOURCE_ID      "' + sqlite.SOURCE_ID + '"') in (tree / 'sqlite3.c').read_text()
    shutil.copyfile(SOURCE / 'fixtures/sqlite-workload.c', tree / 'sqlite-workload.c')
    run('compiler-version', ['gcc', '--version'])
    run('objcopy-version', ['objcopy', '--version'])
    run('sqlite-compile', ['gcc', '-O2', '-g', '-fno-pie', '-no-pie', '-fno-omit-frame-pointer',
        '-DSQLITE_THREADSAFE=0', '-I' + str(tree), tree / 'sqlite3.c', tree / 'sqlite-workload.c',
        '-ldl', '-lm', '-o', tree / 'sqlite.reference'], timeout=300)
    run('sqlite-strip-copy', ['objcopy', '--strip-debug', tree / 'sqlite.reference', tree / 'sqlite-workload'])
    run('sqlite-plain', [tree / 'sqlite-workload'])
    support.require_clean(logs / 'sqlite-plain.log')
    assert (logs / 'sqlite-plain.log').read_text() == 'sqlite-workload=PASS count=100 sum=5050\n'
    if args.uboot_build:
        built = args.uboot_build.resolve(strict=True)
    else:
        build_root = root.parent / (root.name + '-uboot-build')
        build_root.mkdir(exist_ok=False)
        run('uboot-build', [sys.executable, SOURCE / 'build-uboot.py', '--results', build_root], timeout=2400)
        built, = build_root.glob('run.*')
    receipt = json.loads((built / 'build-result.json').read_text())
    assert receipt['status'] == 'PASS' and receipt['version'] == '2025.01'
    assert receipt['archiveSha256'] == load('build-uboot').ARCHIVE_SHA256
    assert support.digest(built / 'u-boot.tar.bz2') == receipt['archiveSha256']
    shutil.copyfile(built / 'u-boot.tar.bz2', sources / 'u-boot-2025.01.tar.bz2')
    firmware = root / 'uboot'
    firmware.mkdir()
    for name, metadata in receipt['artifacts'].items():
        assert name in ('u-boot.reference', 'u-boot.workload', 'u-boot.dtb', 'build.config')
        assert support.digest(built / name) == metadata['sha256']
        shutil.copyfile(built / name, firmware / name)
    for path in built.iterdir():
        if path.is_file() and path.suffix in ('.json', '.log', '.stderr'):
            shutil.copyfile(path, logs / ('uboot-' + path.name))
    workloads = [
        {'name': 'sqlite', 'program': 'SQLite', 'binary': 'sqlite/sqlite-workload',
            'compilerReference': 'sqlite/sqlite.reference', 'kind': 'exec',
            'sourceArchiveSha256': sqlite.ARCHIVE_SHA256,
            'functions': ['benchmark_checkpoint', 'sqlite3_step', 'sqlite3_exec', 'main']},
        {'name': 'uboot', 'program': 'UBoot', 'binary': 'uboot/u-boot.workload',
            'compilerReference': 'uboot/u-boot.reference', 'dtb': 'uboot/u-boot.dtb', 'kind': 'pie',
            'sourceArchiveSha256': receipt['archiveSha256'],
            'functions': ['sandbox_main', 'run_command', 'simple_strtoul', 'do_echo', 'main']}]
    for row in workloads:
        for key in ('binary', 'compilerReference'):
            (root / row[key]).chmod(0o755)
        run(row['name'] + '-symbols', ['nm', '-n', '--defined-only', root / row['compilerReference']])
        addresses = {}
        for line in (logs / (row['name'] + '-symbols.log')).read_text().splitlines():
            fields = line.split()
            if len(fields) == 3 and fields[1] in ('T', 't') and fields[2] in row['functions']:
                assert fields[2] not in addresses
                addresses[fields[2]] = int(fields[0], 16)
        assert set(addresses) == set(row['functions'])
        row['addresses'] = addresses
    files = {str(p.relative_to(root)).replace('\\', '/'): support.digest(p)
        for p in sorted(root.rglob('*')) if p.is_file()}
    (root / 'corpus.json').write_text(json.dumps({'schemaVersion': 1, 'status': 'BUILT',
        'workloads': workloads, 'files': files,
        'recipeSha256': {p.name: support.digest(p) for p in (Path(__file__).resolve(),
            SOURCE / 'build-uboot.py', SOURCE / 'sqlite-benchmark.py', SOURCE / 'fixtures/sqlite-workload.c')},
        'scope': 'Pinned redistributable ELF corpus with full source archives; same inputs for both hosts. '
            'Build sanity is not exporter/validator/debugger acceptance.'}, indent=4) + '\n')
    print('host-corpus=BUILT ' + str(root))


if __name__ == '__main__':
    main()

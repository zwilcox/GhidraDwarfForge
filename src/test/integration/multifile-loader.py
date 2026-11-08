#!/usr/bin/env python3
"""Exercise an actual multi-file fixture companion, transport and GDB rule ownership.

Inputs are produced from fixtures/multifile-source.c by the production exporter
with --source-lines and --gdb-loader. This driver does not create or certify them.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            value.update(block)
    return value.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original', type=Path)
    parser.add_argument('sidecar', type=Path)
    parser.add_argument('work', type=Path)
    args = parser.parse_args()
    original, sidecar, root = args.original.resolve(), args.sidecar.resolve(), args.work.resolve()
    assert not root.is_relative_to(sidecar.parent), 'transport tests must live outside the original source directory'
    root.mkdir(parents=True, exist_ok=False)
    source = Path(str(sidecar) + '.c')
    companion = Path(str(sidecar) + '.gdb.py')
    reference = next(line.removeprefix(' * Manifest: ') for line in source.read_text().splitlines()
        if line.startswith(' * Manifest: '))
    assert re.fullmatch(r'forge-src-[0-9a-f]{64}\.json', reference)
    manifest_path = sidecar.parent / reference
    assert reference == 'forge-src-' + digest(manifest_path) + '.json'
    manifest = json.loads(manifest_path.read_text())
    assert manifest['indexName'] == source.name and manifest['inputSha256'] == digest(original)
    dependencies = [manifest_path]
    for index, part in enumerate(manifest['parts'], 1):
        assert part['name'] == 'forge-src-%06d-%s.c' % (index, part['sha256'])
        path = sidecar.parent / part['name']
        assert path.stat().st_size == part['bytes'] and digest(path) == part['sha256']
        dependencies.append(path)
    selected = [original, sidecar, source, companion, *dependencies]
    assert len({p.name for p in selected}) == len(selected), 'fixture basenames conflict'
    protected = {str(path): digest(path) for path in selected}
    moved = root / 'moved'
    quoted = root / ('transport λ source' if os.name == 'nt' else 'transport λ "source"')
    for directory in (moved, quoted):
        directory.mkdir()
        for path in selected:
            shutil.copy2(path, directory / path.name)
    script = Path(__file__).with_name('multifile-source-gdb.py').resolve()
    cases = []

    def run(name, directory, binary, rule=''):
        command = ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set pagination off',
            '-ex', 'set confirm off', '-ex', 'set debuginfod enabled off',
            '-ex', 'set disable-randomization off', '-x', str(script)]
        environment = {'FORGE_TEST_ORIGINAL': str(binary),
            'FORGE_TEST_SIDECAR': str(directory / sidecar.name),
            'FORGE_TEST_COMPANION': str(directory / companion.name),
            'FORGE_TEST_RULE_CASE': rule, 'DEBUGINFOD_URLS': ''}
        (root / (name + '-command.json')).write_text(json.dumps({
            'command': command, 'environment': environment, 'cwd': str(root)}, indent=4) + '\n')
        result = subprocess.run(command, cwd=root, env=dict(os.environ, **environment),
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=60)
        (root / (name + '.log')).write_text(result.stdout)
        assert result.returncode == 0 and 'MULTIFILE_GDB_PASS' in result.stdout, result.stdout[-5000:]
        cases.append(name)

    run('original', sidecar.parent, original)
    run('original-conflicting-rule', sidecar.parent, original, 'conflict')
    run('moved-old-tree-present', moved, moved / original.name)
    for rule in ('matching', 'conflict', 'replacement'):
        run('rule-' + rule, moved, moved / original.name, rule)
    run('quoted-unicode', quoted, quoted / original.name)
    with tempfile.TemporaryDirectory(prefix='.forge-loader-hidden-', dir=sidecar.parent) as hidden:
        hidden_files = []
        try:
            for path in [source, *dependencies]:
                temporary = Path(hidden) / path.name
                path.rename(temporary)
                hidden_files.append((path, temporary))
            run('moved-old-sources-unavailable', moved, moved / original.name)
        finally:
            for path, temporary in reversed(hidden_files):
                assert not path.exists()
                temporary.rename(path)
    assert protected == {name: digest(Path(name)) for name in protected}
    for directory in (moved, quoted):
        assert all(digest(directory / path.name) == protected[str(path)] for path in selected)
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MULTIFILE_LOADER_LOCAL',
        'cases': cases, 'protectedSha256': protected,
        'gdbVersion': subprocess.check_output(['gdb-multiarch', '--version'], text=True).splitlines()[0],
        'scope': 'Native x86-64 fixture; complete dependency checks and explicit GDB loader. '
            'Does not establish other target/host profiles or full issue acceptance.'}, indent=4) + '\n')
    print('multifile-loader=PASS ' + str(root))


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Retain a real multifile-source.c export through the build-ID installer.

The configuration selects actual original/sidecar/source/report and validators,
as in build-id-installation.py. Linux production tests require an ext4 work root.
All mutations and hiding take place in independent copies under that new root.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('configuration', type=Path)
    parser.add_argument('work', type=Path)
    parser.add_argument('--java', required=True)
    parser.add_argument('--classpath', required=True)
    parser.add_argument('--host', choices=('linux', 'model'), default='linux')
    args = parser.parse_args()
    root = args.work.resolve()
    root.mkdir(parents=True, exist_ok=False)
    exported = root / 'export'
    exported.mkdir()
    config = json.loads(args.configuration.read_text())
    old_index = Path(config['files']['source'])
    reference = next(line.removeprefix(' * Manifest: ') for line in old_index.read_text().splitlines()
        if line.startswith(' * Manifest: '))
    manifest = json.loads((old_index.parent / reference).read_text())
    dependencies = [reference] + [part['name'] for part in manifest['parts']]
    selected = [Path(path) for path in config['files'].values()]
    selected += [old_index.parent / name for name in dependencies]
    assert len({p.name for p in selected}) == len(selected), 'fixture basenames conflict'
    protected = {str(path): digest(path) for path in selected}
    for path in selected:
        shutil.copy2(path, exported / path.name)
    config['files'] = {role: str(exported / Path(path).name) for role, path in config['files'].items()}
    selected_config = root / 'config.json'
    selected_config.write_text(json.dumps(config, indent=4) + '\n')
    prefix = [args.java, '--enable-native-access=ALL-UNNAMED', '-Dforge.test.buildId.host=' + args.host,
        '-cp', args.classpath]
    checks = []

    def run(name, debug, action='install', properties=(), success=True):
        command = prefix + ['-Dforge.test.buildId.' + value for value in properties] + [
            'ghidradwarfforge.output.BuildIdInstallationProbe', str(selected_config), str(debug), action]
        (root / (name + '-command.json')).write_text(json.dumps(command, indent=4) + '\n')
        result = subprocess.run(command, capture_output=True, text=True, timeout=240)
        (root / (name + '.log')).write_text(result.stdout + result.stderr)
        assert (result.returncode == 0) == success, (name, result.returncode, result.stdout, result.stderr)
        checks.append({'name': name, 'exit': result.returncode})
        return json.loads(result.stdout) if success else None

    debug = root / 'debug'
    debug.mkdir()
    installed = run('install', debug)
    assert installed['outcome'] == 'INSTALLED'
    source = Path(installed['source'])
    generation = source.parent.parent
    for name in dependencies:
        for retained in (generation / name, source.parent / name):
            assert digest(retained) == digest(exported / name)
            assert not os.path.samefile(retained, exported / name)
        assert not os.path.samefile(generation / name, source.parent / name)
    assert run('idempotent', debug)['outcome'] == 'ALREADY_INSTALLED'
    original = root / 'original'
    shutil.copy2(config['files']['original'], original)
    command = ['gdb-multiarch', '-nx', '-q', '-batch', '-ex', 'set pagination off',
        '-ex', 'set confirm off', '-ex', 'set disable-randomization off', '-x',
        str(Path(__file__).with_name('multifile-source-gdb.py').resolve())]
    environment = {'FORGE_TEST_ORIGINAL': str(original), 'FORGE_TEST_SIDECAR': installed['registration'],
        'FORGE_TEST_SOURCE': str(source), 'FORGE_TEST_DEBUG_ROOT': str(debug), 'DEBUGINFOD_URLS': ''}
    (root / 'gdb-command.json').write_text(json.dumps({'command': command, 'environment': environment}, indent=4) + '\n')
    hidden = root / 'export.hidden'
    exported.rename(hidden)
    try:
        result = subprocess.run(command, cwd=root, env=dict(os.environ, **environment),
            capture_output=True, text=True, timeout=60)
        text = result.stdout + result.stderr
        (root / 'gdb.log').write_text(text)
        assert result.returncode == 0 and 'MULTIFILE_GDB_PASS' in text and 'Traceback' not in text, text
    finally:
        hidden.rename(exported)
    # Both retained inventories must remain complete, including the report's copy.
    for label, directory in (('reported', generation), ('consumer', source.parent)):
        for index, name in enumerate(dependencies):
            path = directory / name
            hidden = path.with_name(path.name + '.hidden')
            path.rename(hidden)
            try:
                before = {str(p): (digest(p), p.stat().st_ino) for p in debug.rglob('*') if p.is_file()}
                run('missing-' + label + '-' + str(index), debug, success=False)
                after = {str(p): (digest(p), p.stat().st_ino) for p in debug.rglob('*') if p.is_file()}
                assert before == after, 'incomplete generation refusal changed managed files'
            finally:
                hidden.rename(path)
    assert run('restored', debug)['outcome'] == 'ALREADY_INSTALLED'
    for kind in ('fail', 'cancel'):
        interrupted = root / kind
        interrupted.mkdir()
        run(kind, interrupted, properties=[kind + '=GENERATION_SEALED'], success=False)
        build_id = config['buildId']
        assert not (interrupted / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')).exists()
        assert run(kind + '-retry', interrupted)['outcome'] == 'INSTALLED'
    assert run('remove', debug, action='remove')['outcome'] == 'REMOVED'
    assert not Path(installed['registration']).exists()
    for name in dependencies:
        assert (source.parent / name).exists(), 'removal deleted retained source'
    for path, expected in protected.items():
        assert digest(path) == expected, path
    for path in selected:
        assert digest(exported / path.name) == protected[str(path)], path
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MULTIFILE_INSTALLATION_LOCAL',
        'host': args.host, 'checks': checks, 'dependencies': len(dependencies), 'oldExportUnavailable': True,
        'scope': 'Native x86-64 fixture, production installer and selected real validators; no other host/target claim.'},
        indent=4) + '\n')
    print('multifile-installation=PASS ' + str(root))


if __name__ == '__main__':
    main()

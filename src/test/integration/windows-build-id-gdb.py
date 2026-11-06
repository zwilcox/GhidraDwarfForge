#!/usr/bin/env python3
"""Validate and execute actual Windows-installed ELF generations after transfer."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import signal
import subprocess


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows-results', required=True, type=Path)
    parser.add_argument('--results', required=True, type=Path)
    args = parser.parse_args()
    assert os.name == 'posix', 'execute the transferred Linux ELF on Linux'
    incoming = args.windows_results.resolve(strict=True)
    installation = incoming / 'build-id-installation'
    result_path = installation / 'result.json'
    accepted = json.loads(result_path.read_text())
    assert accepted['status'] == 'PASS_NATIVE_WINDOWS_BUILD_ID_INSTALLER'
    build_id = accepted['buildId']
    assert re.fullmatch(r'(?:[0-9a-f]{2}){1,124}', build_id)
    generations = accepted['generations']
    assert [(g['name'], g['index'], g['directory']) for g in generations] == [
        ('initial', 0, 'consumer-initial'), ('curated', 1, 'consumer-curated')]
    reference = incoming / 'attachment-operation/provenance/semantic.exec.reference'
    protected = {str(p): digest(p) for p in [result_path, reference]}
    for generation in generations:
        native = generation['nativeResult']
        assert native['host'] == 'windows-x64-local-ntfs-raw-security-v1'
        assert native['modifiesOriginal'] is False and native['buildId'] == build_id
        assert native['outcome'] == ('INSTALLED' if generation['index'] == 0 else 'UPDATED')
        source = PureWindowsPath(native['source'])
        assert source.is_absolute() and source.drive and source.parent.name == 'source'
        assert PureWindowsPath(native['registration']).parts[-3:] == (
            '.build-id', build_id[:2], build_id[2:] + '.debug')
        for key in ['original', 'sidecar', 'source']:
            path = installation / generation['directory'] / key
            assert path.is_file() and not path.is_symlink()
            assert digest(path) == generation[key + 'Sha256'], (generation['name'], key)
            protected[str(path)] = digest(path)
    assert generations[0]['originalSha256'] == generations[1]['originalSha256']
    assert generations[0]['sidecarSha256'] != generations[1]['sidecarSha256']
    assert generations[0]['sourceSha256'] != generations[1]['sourceSha256']
    assert generations[0]['nativeResult']['source'] != generations[1]['nativeResult']['source']
    work = args.results.resolve()
    work.mkdir(parents=True, exist_ok=False)
    scripts = Path(__file__).resolve().parent
    commands, consumers = [], []

    def run(name, command, environment=None):
        command = list(map(str, command))
        with subprocess.Popen(command, cwd=work, env=environment, start_new_session=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=10)
                (work / (name + '.stdout')).write_text(stdout)
                (work / (name + '.stderr')).write_text(stderr)
                raise
        (work / (name + '.stdout')).write_text(stdout)
        (work / (name + '.stderr')).write_text(stderr)
        commands.append({'name': name, 'command': command, 'exit': process.returncode})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert process.returncode == 0, (name, stdout[-3000:], stderr[-3000:])
        assert not stderr, (name, stderr)
        assert 'Traceback' not in stdout and 'Python Exception' not in stdout
        return stdout

    symbols = run('reference-symbols', ['readelf', '-Ws', reference])
    addresses = {int(fields[1], 16) for line in symbols.splitlines()
        if len(fields := line.split()) >= 8 and fields[0].rstrip(':').isdigit() and fields[7] == 'recovered_add'}
    address, = addresses
    run('gdb-version', ['gdb', '--version'])
    binary = work / 'original'
    shutil.copyfile(installation / 'consumer-initial/original', binary)
    binary.chmod(0o700)
    debug = work / 'debug-root'
    debug.mkdir()
    registration = debug / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')
    registration.parent.mkdir(parents=True)

    def consumer(name, generation=None, source=None, substitute=False):
        present = generation is not None
        curated = present and generation['name'] == 'curated'
        function = 'curated_refresh_add' if curated else 'recovered_add'
        env = dict(os.environ, DEBUGINFOD_URLS='', FORGE_ASSOCIATION_MODE='present' if present else 'absent',
            FORGE_ASSOCIATION_FUNCTION=function, FORGE_ASSOCIATION_TYPE='curated_refresh_state' if curated else 'fixture_state',
            FORGE_ASSOCIATION_ADDRESS=hex(address), FORGE_ASSOCIATION_RUNTIME='1',
            FORGE_ASSOCIATION_DEBUG_FILE=str(registration), FORGE_ASSOCIATION_SOURCE=str(source))
        if curated:
            env['FORGE_ASSOCIATION_MEMBER'] = 'curated_refresh_member'
        command = ['gdb', '-nx', '-nh', '-q', '-batch']
        options = ['set pagination off', 'set confirm off', 'set debuginfod enabled off', 'set auto-load off',
            'set auto-solib-add off', 'set disable-randomization off', 'set filename-display absolute',
            'set debug-file-directory ' + str(debug)]
        if substitute:
            windows_directory = PureWindowsPath(generation['nativeResult']['source']).parent.as_posix()
            options += ['set substitute-path ' + json.dumps(windows_directory, ensure_ascii=False) + ' ' +
                json.dumps(str(source.parent), ensure_ascii=False)]
        options += ['file ' + json.dumps(str(binary))]
        if not present or curated:
            # A retained prior generation must not supply stale function DIEs.
            options += ["python assert gdb.lookup_global_symbol('recovered_add') is None"]
        if not present:
            options += ["python assert gdb.lookup_global_symbol('curated_refresh_add') is None"]
        for option in options:
            command += ['-ex', option]
        if present and not substitute:
            oracle = work / (name + '.py')
            oracle.write_text('import gdb\n'
                'symbol = gdb.lookup_global_symbol(' + repr(function) + ')\n'
                'assert symbol is not None and symbol.symtab is not None\n'
                'assert int(symbol.value().address) == ' + str(address) + '\n'
                'try:\n'
                '    text = gdb.execute(' + repr('list ' + function) + ', to_string=True)\n'
                'except gdb.error as error:\n'
                '    text = str(error)\n'
                "assert 'No such file or directory' in text, text\n"
                'assert ' + repr(PureWindowsPath(generation['nativeResult']['source']).as_posix()) + ' in text, text\n'
                "print('WINDOWS_INSTALLED_SOURCE_MAPPING_REQUIRED')\n")
            marker = 'WINDOWS_INSTALLED_SOURCE_MAPPING_REQUIRED'
        else:
            oracle = scripts / 'automatic-association-gdb.py'
            marker = 'automatic-association=' + ('present' if present else 'absent') + ' PASS'
        text = run(name, command + ['-x', str(oracle)], env)
        assert marker in text
        if present and substitute:
            assert 'exited normally' in text
        consumers.append({'name': name, 'present': present, 'sourceSubstitution': substitute,
            'runtime': present and substitute, 'source': str(source) if source else None})

    consumer('empty')
    for generation in generations:
        name = generation['name']
        portable = installation / generation['directory']
        for key in ['original', 'sidecar']:
            text = run(name + '-' + key + '-elf', ['readelf', '-hSWn', portable / key])
            assert set(re.findall(r'Build ID: ([0-9a-f]+)', text)) == {build_id}
        info = run(name + '-info', ['readelf', '--debug-dump=info', portable / 'sidecar'])
        directory = PureWindowsPath(generation['nativeResult']['source']).parent.as_posix()
        assert directory in info
        verified = run(name + '-llvm', ['llvm-dwarfdump', '--verify', portable / 'sidecar'])
        assert verified.count('No errors.') == 1
        run(name + '-strict', ['python3', scripts / 'check-dwarfdump.py', portable / 'sidecar',
            work / (name + '-strict.log'), '--original', portable / 'original'])
        source = work / ('source-' + name) / PureWindowsPath(generation['nativeResult']['source']).name
        source.parent.mkdir()
        shutil.copyfile(portable / 'source', source)
        # Transfer the exact validated installed artifact. This is not a Linux
        # installer invocation and never rewrites the Windows DWARF source path.
        shutil.copyfile(portable / 'sidecar', registration)
        consumer(name + '-unmapped', generation, source)
        consumer(name + '-runtime', generation, source, substitute=True)
        assert digest(registration) == generation['sidecarSha256']
        assert digest(source) == generation['sourceSha256']
    registration.unlink()
    consumer('removed')
    assert digest(binary) == generations[0]['originalSha256']
    assert protected == {p: digest(Path(p)) for p in protected}
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_WINDOWS_INSTALLED_LINUX_CONSUMER',
        'buildId': build_id, 'consumers': consumers, 'protectedSha256': protected,
        'scope': 'Actual native Windows-installed initial and analyst-curated ELF generations transferred unchanged; '
            'Linux structural validators and fresh GDB build-ID discovery, exact addresses, source, types, arguments '
            'and normal exit. Windows source paths require explicit substitution after transfer. '
            'No native Windows Linux-ELF execution claim.'}, indent=4) + '\n')
    print('windows-build-id-linux-gdb=PASS generations=2 runtime=2 controls=4')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Native NTFS installer/PowerShell acceptance using two actual Windows exports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=4) + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['ghidra', 'attachment-results', 'original', 'sidecar', 'test-classes', 'results']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    assert os.name == 'nt', 'requires native Windows'
    import msvcrt

    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    module = args.ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge'
    attachment = args.attachment_results.resolve()
    refresh = json.loads((attachment / 'refresh.request.json').read_text(encoding='utf-8'))
    assert digest(args.original) == digest(refresh['originalBackup'])
    selected = [
        {'original': str(args.original.resolve()), 'sidecar': str(args.sidecar.resolve()),
            'source': str(Path(str(args.sidecar) + '.c').resolve()), 'report': str(attachment / 'export-report.json')},
        {'original': refresh['originalBackup'], 'sidecar': refresh['sidecar'],
            'source': refresh['source'], 'report': refresh['exportReport']},
    ]
    tools = refresh['validatorTools']
    dependencies = [module / 'lib/GhidraDwarfForge.jar',
        args.ghidra.resolve() / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar',
        args.ghidra.resolve() / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar']
    launcher = module / 'support/ghidra-dwarf-forge-build-id.ps1'
    protected = {p: digest(p) for files in selected for p in files.values()}
    protected.update({str(p): digest(p) for p in [*dependencies, launcher, Path(__file__)]})
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java.exe')
    classpath = os.pathsep.join(map(str, [args.test_classes.resolve(), *dependencies]))
    prefix = [java, '--enable-native-access=ALL-UNNAMED', '-Dforge.test.buildId.host=windows', '-cp', classpath,
        'ghidradwarfforge.output.BuildIdInstallationProbe']
    powershell = shutil.which('pwsh.exe')
    assert powershell is not None
    launch = [powershell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(launcher),
        '-GhidraDirectory', str(args.ghidra.resolve()), '-JavaExecutable', java]
    commands, checks, metadata, generations = [], [], [], []

    def execute(name, command, expected=0, contains=None):
        command = list(map(str, command))
        row = {'name': name, 'command': command}
        commands.append(row)
        save(root / 'commands.json', commands)
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP) as child:
            try:
                stdout, stderr = child.communicate(timeout=300)
            except subprocess.TimeoutExpired:
                # This is an isolated test transaction over owned fixture copies.
                cleanup = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/taskkill.exe'),
                    '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=30)
                (root / (name + '.cleanup.log')).write_bytes(cleanup.stdout + cleanup.stderr)
                stdout, stderr = child.communicate(timeout=30)
                (root / (name + '.stdout')).write_bytes(stdout)
                (root / (name + '.stderr')).write_bytes(stderr)
                raise
        (root / (name + '.stdout')).write_bytes(stdout)
        (root / (name + '.stderr')).write_bytes(stderr)
        row['exit'] = child.returncode
        save(root / 'commands.json', commands)
        text = (stdout + stderr).decode('utf-8', errors='replace')
        assert child.returncode == expected, (name, child.returncode, text[-4000:])
        if contains:
            assert contains in text, (name, text[-4000:])
        return stdout.decode('utf-8')

    note = execute('original-notes', [tools['readelf'], '-n', selected[0]['original']])
    ids = set(re.findall(r'Build ID: ([0-9a-f]+)', note))
    assert len(ids) == 1
    build_id = ids.pop()
    configs = []
    for index, files in enumerate(selected):
        owned = root / ('inputs-' + str(index))
        owned.mkdir()
        copied = {}
        for key, path in files.items():
            destination = owned / (key + '-' + Path(path).name)
            shutil.copy2(path, destination)
            copied[key] = str(destination)
        value = {'files': copied, 'tools': tools, 'buildId': build_id}
        report = json.loads(Path(copied['report']).read_text(encoding='utf-8'))
        for key, claim in [('original', 'inputSha256'), ('sidecar', 'outputSha256'), ('source', 'sourceSha256')]:
            assert digest(copied[key]) == report['artifacts'][claim].lower()
        path = root / ('config-' + str(index) + '.json')
        save(path, value)
        configs.append((path, value))
    assert digest(configs[0][1]['files']['sidecar']) != digest(configs[1][1]['files']['sidecar'])
    protected.update({p: digest(p) for _, config in configs for p in config['files'].values()})
    acl_script = root / 'protect-owned-dacl.ps1'
    acl_script.write_text("$ErrorActionPreference = 'Stop'\n"
        "$acl = Get-Acl -LiteralPath $args[0]\n"
        "$acl.SetAccessRuleProtection($true, $true)\n"
        "Set-Acl -LiteralPath $args[0] -AclObject $acl\n", encoding='utf-8')
    execute('protect-owned-sidecar-dacl', [powershell, '-NoProfile', '-NonInteractive', '-File', acl_script,
        configs[0][1]['files']['sidecar']])

    def fresh(name):
        path = root / name
        path.mkdir()
        return path

    def registration(debug):
        return debug / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')

    def native(name, debug, action, index=0, properties=(), expected=0, contains=None):
        request = root / (name + '.probe.json')
        save(request, [str(configs[index][0]), str(debug), action])
        command = prefix[:]
        command[1:1] = ['-Dforge.test.buildId.' + value for value in properties]
        text = execute(name, [*command, '--request-file', request], expected, contains)
        result = json.loads(text) if expected == 0 else None
        checks.append({'name': name, 'exit': expected, 'outcome': result.get('outcome') if result else None})
        return result

    def public(name, debug, action, index=0, extra=(), expected=0, outcome=None, contains=None):
        value = {'schema': 'forge-build-id-request-v1', 'action': action, 'root': str(debug)}
        if action in ['install', 'update']:
            value.update(files=configs[index][1]['files'], tools=tools)
        else:
            value['buildId'] = build_id
        request = root / (name + ' request λ 雪.json')
        save(request, value)
        text = execute(name, [*launch, '-RequestFile', request, '-RequestSha256', digest(request),
            '-EnableSecurityPrivilege', *extra], expected, contains)
        responses = [json.loads(line) for line in text.splitlines() if line.startswith('{')]
        assert responses and all(r['modifiesOriginal'] is False for r in responses)
        result = responses[-1]
        assert result['outcome'] == outcome, (name, result)
        checks.append({'name': name, 'exit': expected, 'outcome': result['outcome']})
        return result

    def tree(debug):
        return {str(p.relative_to(debug)): digest(p) for p in debug.rglob('*') if p.is_file()}

    def compare_metadata(name, source, destination):
        before = native(name + '-source', source, 'snapshot')
        after = native(name + '-destination', destination, 'snapshot')
        assert before['preservation'] == after['preservation'], name
        left = before['snapshot']['ordinary']['facts']
        right = after['snapshot']['ordinary']['facts']
        assert left['identity'] != right['identity'] and right['links'] == 1
        metadata.append({'name': name, 'source': str(source), 'destination': str(destination),
            'preservation': before['preservation']})

    def capture_generation(name, result, index):
        source = Path(result['source'])
        generation = source.parent.parent
        evidence = json.loads((generation / 'validation.json').read_text(encoding='utf-8'))
        assert evidence['schemaVersion'] == 3 and evidence['status'] == 'PASS'
        assert digest(source) == digest(configs[index][1]['files']['source'])
        assert result['gdbSetupCommand'] == 'set debug-file-directory ' + str(debug).replace('\\', '/')
        portable = fresh('consumer-' + name)
        # Retain independent copies for a subsequent Linux consumer check. This
        # native Windows test does not claim GDB runtime or automatic discovery.
        for key, path in [('original', configs[index][1]['files']['original']),
                ('sidecar', result['registration']), ('source', source)]:
            shutil.copy2(path, portable / key)
        generations.append({'name': name, 'index': index, 'nativeResult': result,
            'directory': portable.name, 'originalSha256': digest(portable / 'original'),
            'sidecarSha256': digest(portable / 'sidecar'), 'sourceSha256': digest(portable / 'source')})

    debug = fresh("debug root λ 雪 'quote' $literal")
    public('preview', debug, 'install', extra=['-Preview'], outcome='PREVIEW_NOT_VALIDATED')
    assert not list(debug.iterdir())
    first = public('install', debug, 'install', outcome='INSTALLED')
    capture_generation('initial', first, 0)
    compare_metadata('registration-initial', Path(configs[0][1]['files']['sidecar']), Path(first['registration']))
    before = tree(debug)
    public('idempotent', debug, 'install', outcome='ALREADY_INSTALLED')
    assert tree(debug) == before
    public('implicit-update', debug, 'install', index=1, expected=1, outcome='FAILED', contains='explicit update')
    assert tree(debug) == before
    updated = public('update', debug, 'update', index=1, outcome='UPDATED')
    assert first['source'] != updated['source'] and Path(first['source']).exists()
    capture_generation('curated', updated, 1)
    compare_metadata('registration-refresh', Path(configs[0][1]['files']['sidecar']), Path(updated['registration']))
    public('remove', debug, 'remove', outcome='REMOVED')
    assert not registration(debug).exists() and Path(updated['source']).exists()
    public('recover', debug, 'recover', outcome='UNCHANGED')

    for action in ['install', 'update', 'remove']:
        boundaries = ['PREPARED', 'BEFORE_PUBLICATION', 'PUBLISHED', 'COMMITTED']
        if action != 'remove':
            boundaries.insert(0, 'GENERATION_SEALED')
        for boundary in boundaries:
            name = action + '-crash-' + boundary.lower()
            debug = fresh(name)
            previous = native(name + '-baseline', debug, 'install') if action != 'install' else None
            old_hash = digest(registration(debug)) if previous else None
            index = 1 if action == 'update' else 0
            native(name, debug, action, index, ['crash=' + boundary], expected=73)
            expected = {'GENERATION_SEALED': 'UNCHANGED', 'PREPARED': 'RECOVERED_ABORT',
                'BEFORE_PUBLICATION': 'RECOVERED_ABORT', 'PUBLISHED': 'RECOVERED_COMMIT', 'COMMITTED': 'UNCHANGED'}[boundary]
            assert native(name + '-recover', debug, 'recover', index)['outcome'] == expected
            applied = boundary in ['PUBLISHED', 'COMMITTED']
            if not applied:
                assert (digest(registration(debug)) if registration(debug).exists() else None) == old_hash
            elif action == 'remove':
                assert not registration(debug).exists()
            else:
                assert registration(debug).exists() and digest(registration(debug)) != old_hash
            if previous:
                assert Path(previous['source']).exists()
            assert native(name + '-recover-repeat', debug, 'recover', index)['outcome'] == 'UNCHANGED'

    debug = fresh('locking')
    native('locking-install', debug, 'install')
    lock = debug / '.forge-build-id/v1' / build_id / 'lock'
    before = tree(debug)
    with lock.open('r+b') as held:
        msvcrt.locking(held.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            native('locking-refused', debug, 'update', 1, expected=1, contains='installation is busy')
        finally:
            held.seek(0)
            msvcrt.locking(held.fileno(), msvcrt.LK_UNLCK, 1)
    assert tree(debug) == before
    assert native('locking-released', debug, 'update', 1)['outcome'] == 'UPDATED'

    for boundary in ['BEFORE_PUBLICATION', 'PUBLISHED']:
        debug = fresh('cancel-' + boundary.lower())
        if boundary == 'BEFORE_PUBLICATION':
            native('cancel-before', debug, 'install', properties=['cancel=' + boundary], expected=1,
                contains='CancellationException')
            assert not registration(debug).exists()
            assert native('cancel-before-recover', debug, 'recover')['outcome'] == 'RECOVERED_ABORT'
        else:
            assert native('cancel-after', debug, 'install', properties=['cancel=' + boundary])['outcome'] == 'INSTALLED'
            assert registration(debug).exists()

    debug = fresh('foreign')
    leaf = registration(debug)
    leaf.parent.mkdir(parents=True)
    leaf.write_bytes(b'foreign registration')
    public('foreign-refused', debug, 'install', expected=1, outcome='FAILED', contains='registration is foreign')
    assert leaf.read_bytes() == b'foreign registration'

    debug = fresh('junction-root')
    elsewhere = fresh('junction-destination')
    subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(debug / '.build-id'), str(elsewhere)], check=True,
        capture_output=True)
    before = tree(elsewhere)
    public('junction-refused', debug, 'install', expected=1, outcome='FAILED')
    assert tree(elsewhere) == before

    debug = fresh('hardlink-input')
    alias = root / 'owned-sidecar-hardlink'
    os.link(configs[0][1]['files']['sidecar'], alias)
    try:
        public('hardlink-refused', debug, 'install', expected=1, outcome='FAILED', contains='hardlink')
        assert not registration(debug).exists()
    finally:
        alias.unlink()

    debug = fresh('alternate-stream-input')
    stream = Path(configs[0][1]['files']['source'] + ':forge-test')
    stream.write_bytes(b'unsupported owned alternate stream')
    try:
        public('alternate-stream-refused', debug, 'install', expected=1, outcome='FAILED')
        assert not registration(debug).exists() and stream.read_bytes() == b'unsupported owned alternate stream'
    finally:
        stream.unlink()

    assert protected == {p: digest(p) for p in protected}
    save(root / 'result.json', {'status': 'PASS_NATIVE_WINDOWS_BUILD_ID_INSTALLER', 'buildId': build_id,
        'checks': checks, 'metadataComparisons': metadata, 'generations': generations, 'protectedInputs': protected,
        'scope': 'Native Windows NTFS host and packaged PowerShell launcher, real original and analyst-refreshed exports, '
            'fresh structural validation, metadata preservation, interrupted lifecycle/recovery, lock, cancellation, '
            'foreign registration and junction controls. No Windows GDB runtime or consumer-discovery claim.'})
    print('windows-build-id-installation=PASS checks=' + str(len(checks)))


if __name__ == '__main__':
    main()

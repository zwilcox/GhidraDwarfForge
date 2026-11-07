#!/usr/bin/env python3
"""Persist analyst edits in Ghidra, install both exports, and prove fresh GDB refresh."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--fixture-dir', required=True, type=Path)
    parser.add_argument('--role', required=True, choices=('exec', 'pie'))
    parser.add_argument('--tools-configuration', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--scratch', required=True, type=Path)
    parser.add_argument('--java', required=True, type=Path)
    args = parser.parse_args()
    root, scratch, ghidra = args.output.resolve(), args.scratch.resolve(), args.ghidra.resolve()
    root.mkdir(parents=True, exist_ok=False)
    scratch.mkdir(parents=True, exist_ok=False)
    for name in ['project', 'tmp', 'config', 'cache']:
        (scratch / name).mkdir()
    scripts = Path(__file__).resolve().parent
    fixture = args.fixture_dir.resolve() / 'x86_64' / ('semantic.' + args.role + '.stripped')
    reference = fixture.with_suffix('.reference')
    original = root / 'original.elf'
    shutil.copy2(fixture, original)
    original_hash = digest(original)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    tools = json.loads(args.tools_configuration.read_text())['tools']
    tools['helper'] = str(module / 'os/linux_x86_64/forge-validator-supervisor')
    protected = {str(p): digest(p) for p in [fixture, reference, module / 'lib/GhidraDwarfForge.jar',
        scripts / 'ghidra_scripts/CurateAttachmentRefresh.java', scripts / 'ghidra_scripts/RenameFixtureFunction.java']}
    env = dict(os.environ, JAVA_HOME=str(args.java.resolve().parent.parent),
        JAVA_TOOL_OPTIONS='-Djava.io.tmpdir=' + str(scratch / 'tmp') + ' -Djna.tmpdir=' + str(scratch / 'tmp'),
        XDG_CONFIG_HOME=str(scratch / 'config'), XDG_CACHE_HOME=str(scratch / 'cache'))
    commands, generations = [], []

    def run(name, command, selected_env=None, timeout=240, expected=0):
        command = list(map(str, command))
        commands.append({'name': name, 'command': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with subprocess.Popen(command, env=selected_env or env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=10)
                (root / (name + '.stdout')).write_text(stdout)
                (root / (name + '.stderr')).write_text(stderr)
                raise
        (root / (name + '.stdout')).write_text(stdout)
        (root / (name + '.stderr')).write_text(stderr)
        commands[-1]['exit'] = process.returncode
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert process.returncode == expected, (name, stdout[-3000:], stderr[-1000:])
        assert digest(original) == original_hash
        return stdout

    symbols = run('reference-symbols', ['readelf', '-Ws', reference])

    def address(name):
        values = {int(line.split()[1], 16) for line in symbols.splitlines()
            if len(line.split()) >= 8 and line.split()[0].rstrip(':').isdigit() and line.split()[7] == name}
        assert len(values) == 1, name
        return values.pop()

    # Existing x86-64 semantic-fixture Ghidra import convention, not generic exporter policy.
    delta = 0x100000 if args.role == 'pie' else 0
    function_address = hex(address('recovered_add') + delta)
    prepare = ['-postScript', 'RenameFixtureFunction.java', function_address,
        hex(address('recovered_variadic') + delta), hex(address('recovered_spin') + delta), 'recovered_add',
        hex(address('fixture_sink') + delta), hex(address('recovered_composite') + delta), hex(address('scoped_counter') + delta)]
    anchor = ['-postScript', 'CurateAttachmentRefresh.java', 'anchor', function_address, str(original), original_hash]
    headless = [str(ghidra / 'support/analyzeHeadless'), str(scratch / 'project'), 'BuildIdRefresh',
        '-scriptPath', str(scripts / 'ghidra_scripts')]
    debug = root / 'debug-root'
    debug.mkdir()
    initial = root / 'initial.dbg'
    initial_text = run('initial-export', headless + ['-import', str(original), '-analysisTimeoutPerFile', '120',
        *prepare, *anchor, '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(initial)])
    assert 'GhidraDwarfForge symbol export PASS' in initial_text

    def install(name, sidecar, text, action):
        reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in text.splitlines() if 'GhidraDwarfForge report: ' in line]
        assert len(reports) == 1 and reports[0]['status'] in ['SUCCESS', 'PARTIAL']
        source = Path(str(sidecar) + '.c')
        for key, path in [('input', original), ('output', sidecar), ('source', source)]:
            assert reports[0]['artifacts'][key + 'Sha256'] == digest(path)
        report = root / (name + '.report.json')
        report.write_text(json.dumps(reports[0]) + '\n')
        files = {'original': str(original), 'sidecar': str(sidecar), 'source': str(source), 'report': str(report)}
        request = root / (name + '.request.json')
        value = {'schema': 'forge-build-id-request-v1', 'action': action, 'root': str(debug), 'files': files, 'tools': tools}
        request.write_text(json.dumps(value, indent=4) + '\n')
        command = [module / 'support/ghidra-dwarf-forge-build-id', '--java=' + str(args.java.resolve()),
            '--ghidra-dir=' + str(ghidra), '--request=' + str(request), '--request-sha256=' + digest(request)]
        output = run(name + '-install', command)
        result = json.loads(output.splitlines()[-1])
        assert result['outcome'] == ('INSTALLED' if action == 'install' else 'UPDATED'), result
        for path in [sidecar, source, report, Path(result['source'])]:
            protected[str(path)] = digest(path)
        generations.append({'request': value, 'result': result})
        return result

    def gdb(name, installed, refreshed=False):
        function = 'curated_refresh_add' if refreshed else 'recovered_add'
        data_type = 'curated_refresh_state' if refreshed else 'fixture_state'
        oracle = scripts / 'automatic-association-gdb.py'
        selected_env = dict(env, DEBUGINFOD_URLS='', FORGE_ASSOCIATION_MODE='present',
            FORGE_ASSOCIATION_FUNCTION=function, FORGE_ASSOCIATION_TYPE=data_type,
            FORGE_ASSOCIATION_ADDRESS=hex(address('recovered_add')), FORGE_ASSOCIATION_RUNTIME='1',
            FORGE_ASSOCIATION_DEBUG_FILE=installed['registration'], FORGE_ASSOCIATION_SOURCE=installed['source'])
        if refreshed:
            selected_env['FORGE_ASSOCIATION_MEMBER'] = 'curated_refresh_member'
        command = ['gdb-multiarch', '-nx', '-q', '-batch', '-ex', 'set pagination off', '-ex', 'set confirm off',
            '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off', '-ex', 'set disable-randomization off',
            '-ex', 'set filename-display absolute', '-ex', installed['gdbSetupCommand'], '-ex', 'file ' + json.dumps(str(original))]
        if refreshed:
            command += ['-ex', "python assert gdb.lookup_global_symbol('recovered_add') is None"]
        command += ['-x', str(oracle)]
        hidden = []
        try:
            for path in sorted({Path(generation['request']['files'][key]) for generation in generations
                    for key in ['sidecar', 'source', 'report']}):
                moved = path.with_name(path.name + '.hidden-for-discovery')
                assert not moved.exists()
                path.rename(moved)
                hidden.append((path, moved))
            output = run(name + '-gdb', command, selected_env, timeout=90)
            assert 'automatic-association=present PASS' in output and 'exited normally' in output
            assert 'Traceback' not in output and 'Python Exception' not in (root / (name + '-gdb.stderr')).read_text()
        finally:
            for path, moved in reversed(hidden):
                assert not path.exists()
                moved.rename(path)

    first = install('initial', initial, initial_text, 'install')
    gdb('initial', first)
    edit = ['-postScript', 'CurateAttachmentRefresh.java', 'edit', function_address, str(original), original_hash]
    assert 'curated-refresh-program=PASS mode=edit' in run('edit-save', headless + ['-process', original.name, '-noanalysis', *edit])
    verify = ['-postScript', 'CurateAttachmentRefresh.java', 'verify', function_address, str(original), original_hash]
    updated = root / 'updated.dbg'
    text = run('reopen-export', headless + ['-process', original.name, '-noanalysis', '-readOnly', *verify,
        '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(updated), *verify])
    assert text.count('curated-refresh-program=PASS mode=verify') == 2 and 'GhidraDwarfForge symbol export PASS' in text
    second = install('updated', updated, text, 'update')
    assert first['buildId'] == second['buildId'] and first['source'] != second['source']
    assert digest(initial) != digest(updated)
    gdb('updated', second, True)
    assert protected == {p: digest(p) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_SAVED_ANALYST_BUILD_ID_REFRESH', 'role': args.role,
        'originalSha256': original_hash, 'generations': generations, 'protectedInputs': protected,
        'scope': 'Production packaged headless exporter and Linux launcher/host/validators; saved function/type/member edits, '
            'fresh GDB source/type/argument/runtime discovery with former exports absent; original ELF unchanged.'}, indent=4) + '\n')
    print('build-id-curated-refresh=PASS role=' + args.role)


if __name__ == '__main__':
    main()

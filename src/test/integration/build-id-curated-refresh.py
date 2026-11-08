#!/usr/bin/env python3
"""Persist analyst edits in Ghidra, install both exports, and prove fresh GDB refresh."""
import argparse
import hashlib
import json
import os
import re
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
    parser.add_argument('--source-lines', type=int, default=0)
    parser.add_argument('--recovery', action='store_true', help='exercise production Linux recovery via fault-injection probe')
    args = parser.parse_args()
    assert args.source_lines >= 0
    root, scratch, ghidra = args.output.resolve(), args.scratch.resolve(), args.ghidra.resolve()
    root.mkdir(parents=True, exist_ok=False)
    scratch.mkdir(parents=True, exist_ok=False)
    for name in ['project', 'tmp', 'config', 'cache', 'home']:
        (scratch / name).mkdir()
    scripts = Path(__file__).resolve().parent
    fixture = args.fixture_dir.resolve() / 'x86_64' / ('semantic.' + args.role + '.stripped')
    reference = fixture.with_suffix('.reference')
    original = root / 'original.elf'
    shutil.copy2(fixture, original)
    original.chmod(original.stat().st_mode | 0o100)  # Downloaded fixture artifacts may lose executable mode.
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
    vmargs = run('launch-options', [args.java.resolve(), '-cp', ghidra / 'support/LaunchSupport.jar',
        'LaunchSupport', ghidra, '-vmargs']).splitlines()
    headless = [str(args.java.resolve()), *vmargs, '-Duser.home=' + str(scratch / 'home'),
        '-Xmx2G', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2', '-Djava.awt.headless=true',
        '-cp', str(ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar'), 'ghidra.Ghidra',
        'ghidra.app.util.headless.AnalyzeHeadless', str(scratch / 'project'), 'BuildIdRefresh',
        '-scriptPath', str(scripts / 'ghidra_scripts')]
    source_options = ['--source-lines=' + str(args.source_lines)] if args.source_lines else []
    debug = root / 'debug-root'
    debug.mkdir()
    initial = root / 'initial.dbg'
    initial_text = run('initial-export', headless + ['-import', str(original), '-analysisTimeoutPerFile', '120',
        *prepare, *anchor, '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(initial), *source_options])
    assert 'GhidraDwarfForge symbol export PASS' in initial_text

    def inventory(source, expected_name=None):
        files = [source]
        manifest = None
        if args.source_lines:
            names = re.findall(r'^ \* Manifest: (forge-src-[0-9a-f]{64}\.json)$', source.read_text(), re.M)
            assert len(names) == 1
            path = source.parent / names[0]
            assert path.name == 'forge-src-' + digest(path) + '.json'
            manifest = json.loads(path.read_text())
            assert manifest['schema'] == 1 and manifest['indexName'] == (expected_name or source.name)
            assert manifest['inputSha256'] == original_hash and manifest['targetLines'] == args.source_lines
            assert len(manifest['parts']) > 1
            files.append(path)
            logical = bytearray()
            cursor = 1
            for number, part in enumerate(manifest['parts'], 1):
                assert part['file'] == number and part['first'] == cursor and part['last'] >= cursor
                assert part['name'] == 'forge-src-%06d-%s.c' % (number, part['sha256'])
                path = source.parent / part['name']
                assert digest(path) == part['sha256'] and path.stat().st_size == part['bytes']
                lines = path.read_bytes().splitlines(keepends=True)
                assert lines[:2] == [b'/* Synthetic source partition generated by GhidraDwarfForge. */\n',
                    b'/* Decompiled presentation, not recovered original source. */\n']
                assert len(lines) == part['last'] - part['first'] + 3
                logical.extend(b''.join(lines[2:]))
                cursor = part['last'] + 1
                files.append(path)
            assert hashlib.sha256(logical).hexdigest() == manifest['logicalSourceSha256']
        return {'files': {str(path): digest(path) for path in files}, 'manifest': manifest}

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
        exported = inventory(source)
        retained_source = Path(result['source'])
        retained = inventory(retained_source)
        saved = inventory(retained_source.parent.parent / 'export.source', source.name)
        assert digest(source) == digest(retained_source) == digest(retained_source.parent.parent / 'export.source')
        assert exported['manifest'] == retained['manifest'] == saved['manifest']
        for path in exported['files']:
            original_path = Path(path)
            for copied in [retained_source.parent / original_path.name,
                    retained_source.parent.parent / ('export.source' if original_path == source else original_path.name)]:
                assert digest(copied) == exported['files'][path]
                assert not os.path.samefile(copied, original_path), 'installation aliases exported source'
        for path in [sidecar, report]:
            protected[str(path)] = digest(path)
        for selected in [exported, retained, saved]:
            protected.update(selected['files'])
        generations.append({'request': value, 'result': result,
            'exportedSource': exported, 'retainedSource': retained, 'savedSource': saved})
        return result

    def gdb(name, installed, refreshed=False):
        function = 'curated_refresh_add' if refreshed else 'recovered_add'
        data_type = 'curated_refresh_state' if refreshed else 'fixture_state'
        oracle = scripts / 'automatic-association-gdb.py'
        actual_source = installed['source']
        if args.source_lines:
            manifest = inventory(Path(actual_source))['manifest']
            selected = [entry for entry in manifest['functions']
                if entry['name'] == function and int(entry['address'], 16) == address('recovered_add')]
            assert len(selected) == 1 and selected[0]['disposition'] == 'decompiled'
            actual_source = str(Path(actual_source).parent / manifest['parts'][selected[0]['file'] - 1]['name'])
        selected_env = dict(env, DEBUGINFOD_URLS='', FORGE_ASSOCIATION_MODE='present',
            FORGE_ASSOCIATION_FUNCTION=function, FORGE_ASSOCIATION_TYPE=data_type,
            FORGE_ASSOCIATION_ADDRESS=hex(address('recovered_add')), FORGE_ASSOCIATION_RUNTIME='1',
            FORGE_ASSOCIATION_DEBUG_FILE=installed['registration'], FORGE_ASSOCIATION_SOURCE=actual_source)
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
            for path in sorted({Path(path) for generation in generations for path in
                    [generation['request']['files']['sidecar'], generation['request']['files']['report'],
                        *generation['exportedSource']['files']]}):
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
        '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(updated), *source_options, *verify])
    assert text.count('curated-refresh-program=PASS mode=verify') == 2 and 'GhidraDwarfForge symbol export PASS' in text
    second = install('updated', updated, text, 'update')
    assert first['buildId'] == second['buildId'] and first['source'] != second['source']
    assert digest(initial) != digest(updated)
    gdb('updated', second, True)
    recovery_checks = []
    if args.recovery:
        classes = scratch / 'classes'
        classes.mkdir()
        java_sources = [scripts.parent.parent / 'test/java/ghidradwarfforge/output' / (name + '.java') for name in
            ['AttachmentProtocolSmoke', 'AttachmentReceiptStoreSmoke', 'AttachmentElfTransactionProbe', 'BuildIdInstallationProbe']]
        dependencies = [module / 'lib/GhidraDwarfForge.jar', ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar',
            ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar']
        protected.update({str(path): digest(path) for path in java_sources + dependencies})
        classpath = os.pathsep.join(map(str, dependencies))
        run('compile-recovery-probe', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', classpath,
            '-d', classes, *java_sources])
        classpath = str(classes) + os.pathsep + classpath
        configs = []
        for name, generation in zip(['initial', 'updated'], generations):
            config = root / (name + '.probe.json')
            config.write_text(json.dumps({'buildId': first['buildId'], 'files': generation['request']['files'],
                'tools': tools}, indent=4) + '\n')
            configs.append(config)

        def probe(name, selected_root, action, updated=False, properties=(), expected=0):
            output = run(name, [args.java.resolve(), '--enable-native-access=ALL-UNNAMED',
                '-Dforge.test.buildId.host=linux', *['-Dforge.test.buildId.' + value for value in properties],
                '-cp', classpath, 'ghidradwarfforge.output.BuildIdInstallationProbe',
                configs[1 if updated else 0], selected_root, action], expected=expected)
            if expected:
                return None
            result = json.loads(output)
            assert result['host'] == 'linux-x64-ext4-build-id-visible-metadata-v1', result
            result['gdbSetupCommand'] = 'set debug-file-directory ' + str(selected_root)
            return result

        cases = [('crash', point) for point in
            ['GENERATION_SEALED', 'PREPARED', 'BEFORE_PUBLICATION', 'PUBLISHED', 'COMMITTED']]
        cases += [('cancel', point) for point in ['PREPARED', 'PUBLISHED']]
        cases += [('sync', 'PUBLISHED')]
        for fault, point in cases:
            name = 'recovery-' + fault + '-' + point.lower()
            selected_root = root / name
            selected_root.mkdir()
            previous = probe(name + '-initial', selected_root, 'install')
            previous_inventory = inventory(Path(previous['source']))
            before_registration = digest(previous['registration'])
            properties = ['failPublicationSync=true'] if fault == 'sync' else [fault + '=' + point]
            exit_code = 73 if fault == 'crash' else 0 if fault == 'cancel' and point == 'PUBLISHED' else 1
            probe(name + '-fault', selected_root, 'update', True, properties, exit_code)
            installed_generations = []
            for seal in sorted(selected_root.rglob('generation.json')):
                record = json.loads(seal.read_text())
                retained = inventory(seal.parent / 'source' / record['sourceName'])
                saved = inventory(seal.parent / 'export.source', record['sourceName'])
                assert retained['manifest'] == saved['manifest']
                for selected in [retained, saved]:
                    protected.update(selected['files'])
                installed_generations.append({'seal': str(seal), 'retained': retained, 'saved': saved})
            assert len(installed_generations) == 2, 'both sealed generations must survive the interruption'
            refusals = []
            if args.source_lines and fault == 'crash' and point in ['PREPARED', 'PUBLISHED']:
                # Recovery may not bless an incomplete old or proposed generation.
                for number, generation in enumerate(installed_generations):
                    for kind in ['retained', 'saved']:
                        files = list(generation[kind]['files'])
                        for part_kind, path in [('manifest', files[1]), ('part', files[2])]:
                            path = Path(path)
                            hidden = path.with_name(path.name + '.hidden-recovery-control')
                            state_before = digest(previous['state'])
                            registration_before = digest(previous['registration'])
                            assert not hidden.exists()
                            path.rename(hidden)
                            label = name + '-missing-%d-%s-%s' % (number, kind, part_kind)
                            try:
                                probe(label, selected_root, 'recover', expected=1)
                                assert 'generation file inventory changed' in (root / (label + '.stderr')).read_text()
                                assert digest(previous['state']) == state_before
                                assert digest(previous['registration']) == registration_before
                                refusals.append(str(path))
                            finally:
                                assert not path.exists()
                                hidden.rename(path)
            recovered = probe(name + '-recover', selected_root, 'recover')
            applied = point in ['PUBLISHED', 'COMMITTED']
            expected = 'RECOVERED_COMMIT' if applied else 'RECOVERED_ABORT'
            if point in ['GENERATION_SEALED', 'COMMITTED'] or fault == 'cancel' and applied:
                expected = 'UNCHANGED'
            assert recovered['outcome'] == expected, recovered
            assert (digest(recovered['registration']) != before_registration) == applied
            current = inventory(Path(recovered['source']))
            expected_generation = generations[1 if applied else 0]['exportedSource']
            assert current['manifest'] == expected_generation['manifest']
            assert digest(recovered['source']) == digest(generations[1 if applied else 0]['request']['files']['source'])
            assert previous_inventory['files'] == {path: digest(path) for path in previous_inventory['files']}
            gdb(name, recovered, applied)
            assert probe(name + '-recover-repeat', selected_root, 'recover')['outcome'] == 'UNCHANGED'
            recovery_checks.append({'fault': fault, 'boundary': point, 'outcome': recovered['outcome'],
                'updated': applied, 'generations': installed_generations, 'missingDependencyRefusals': refusals})
    assert protected == {p: digest(p) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_SAVED_ANALYST_BUILD_ID_REFRESH', 'role': args.role, 'sourceLines': args.source_lines,
        'originalSha256': original_hash, 'recoveryChecks': recovery_checks, 'generations': generations, 'protectedInputs': protected,
        'scope': 'Production packaged headless exporter and Linux launcher/host/validators; saved function/type/member edits, '
            'complete exported/saved/retained source inventory equality and preservation; '
            'fresh GDB source/type/argument/runtime discovery with every former export dependency absent; original ELF unchanged.'}, indent=4) + '\n')
    print('build-id-curated-refresh=PASS role=' + args.role)


if __name__ == '__main__':
    main()

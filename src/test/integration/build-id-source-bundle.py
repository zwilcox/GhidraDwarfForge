#!/usr/bin/env python3
"""Install real split-source exports with the Linux host and test retained-source discovery."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from integration_coverage import Collection, digest, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('export', 'ghidra', 'jar', 'java', 'strict-validator', 'helper', 'work'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    export = args.export.resolve(strict=True)
    harness = Path(__file__).resolve().parent
    repo = harness.parents[2]
    names = ('BuildIdInstallationProbe', 'AttachmentElfTransactionProbe',
        'AttachmentReceiptStoreSmoke', 'AttachmentProtocolSmoke', 'AttachmentPathBoundarySmoke')
    sources = [repo / 'src/test/java/ghidradwarfforge/output' / (name + '.java') for name in names]
    runtime = [args.jar.resolve(strict=True), args.ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar',
        args.ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar']
    validator = args.strict_validator.resolve(strict=True).parents[1]
    tools = dict(zip(('helper', 'readelf', 'llvm', 'strict', 'configuration'), map(str, (
        args.helper.resolve(strict=True), Path(shutil.which('readelf')).resolve(),
        Path(shutil.which('llvm-dwarfdump')).resolve(), validator / 'libexec/dwarfdump',
        validator / 'share/dwarfdump/dwarfdump.conf'))))
    index = export / 'forge.dbg.c'
    manifest_name, = re.findall(r'^ \* Manifest: (forge-src-[0-9a-f]{64}\.json)$', index.read_text(), re.M)
    manifest = json.loads((export / manifest_name).read_text())
    dependencies = [manifest_name]
    for part in manifest['parts']:
        assert re.fullmatch(r'forge-src-[0-9]{6}-[0-9a-f]{64}\.c', part['name'])
        assert digest(export / part['name']) == part['sha256']
        assert (export / part['name']).stat().st_size == part['bytes']
        dependencies.append(part['name'])
    assert len(dependencies) >= 3 and len(dependencies) == len(set(dependencies))
    assert manifest['inputSha256'] == digest(export / 'original')
    input_paths = [export / name for name in ('original', 'forge.dbg', 'forge.dbg.c',
        'multi-report.json', 'single/forge.dbg', 'single/forge.dbg.c', 'single-report.json', *dependencies)]
    protected = {str(path): digest(path) for path in [*input_paths, *runtime, *sources,
        *map(Path, tools.values()), Path(__file__), harness / 'integration_coverage.py',
        harness / 'multifile-target-gdb.py']}
    save(work / 'protected.json', protected)
    owned = work / 'inputs'
    owned.mkdir()
    configs = {}
    for layout in ('multi', 'single'):
        selected = owned / layout
        selected.mkdir()
        directory = export if layout == 'multi' else export / 'single'
        files = {'original': export / 'original', 'sidecar': directory / 'forge.dbg',
            'source': directory / 'forge.dbg.c', 'report': export / (layout + '-report.json')}
        report = json.loads(files['report'].read_text())
        for role, path in (('input', files['original']), ('output', files['sidecar']), ('source', files['source'])):
            assert digest(path) == report['artifacts'][role + 'Sha256']
        assert report['failure'] is None and not report['failedFunctions']
        for role, path in list(files.items()):
            copied = selected / path.name
            shutil.copy2(path, copied)
            files[role] = copied
        if layout == 'multi':
            for name in dependencies:
                shutil.copy2(export / name, selected / name)
        notes = subprocess.check_output(['readelf', '-n', files['original']], text=True)
        build_id, = set(re.findall(r'Build ID: ([0-9a-f]+)', notes))
        configs[layout] = work / (layout + '.json')
        save(configs[layout], {'buildId': build_id, 'files': {key: str(value) for key, value in files.items()}, 'tools': tools})
    original = work / 'runtime-original'
    shutil.copy2(export / 'original', original)
    protected[str(original)] = digest(original)
    owned_hashes = {str(path.relative_to(owned)): digest(path) for path in owned.rglob('*') if path.is_file()}
    classes = work / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(map(str, [classes, *runtime]))
    java = args.java.resolve(strict=True)
    commands, checks, consumers, generations, refusals = [], [], [], [], []
    coverage = Collection('build-id-source-bundle', args.jar, 'native-java',
        test_classes=tuple('ghidradwarfforge.output.' + name for name in names))

    def run(label, command, *, measured=False, success=True, environment=None):
        command = list(map(str, command))
        if measured:
            with coverage.session(command, label) as selected:
                result = execute(label, selected, environment)
                assert (result.returncode == 0) == success, (label, result.stderr[-5000:])
        else:
            result = execute(label, command, environment)
            assert (result.returncode == 0) == success, (label, result.stderr[-5000:])
        return result

    def execute(label, command, environment):
        result = subprocess.run(command, capture_output=True, text=True, timeout=240, env=environment)
        (work / (label + '.stdout')).write_text(result.stdout)
        (work / (label + '.stderr')).write_text(result.stderr)
        commands.append({'label': label, 'command': command, 'exit': result.returncode})
        save(work / 'commands.json', commands)
        return result

    run('compile', [java.with_name('javac'), '--release', '21', '-proc:none', '-cp', classpath, '-d', classes, *sources])
    debug = work / 'debug'
    debug.mkdir()

    def operation(label, layout, action, expected):
        result = run(label, [java, '--enable-native-access=ALL-UNNAMED', '-Djava.io.tmpdir=' + os.environ.get('TMPDIR', '/tmp'),
            '-Dforge.test.buildId.host=linux', '-cp', classpath, 'ghidradwarfforge.output.BuildIdInstallationProbe',
            configs[layout], debug, action], measured=True, success=expected is not None)
        if expected is None:
            assert 'java.io.IOException: attachment recovery file no longer matches its observation:' in result.stderr, result.stderr
            return result
        outcome = json.loads(result.stdout)
        assert outcome['outcome'] == expected and outcome['host'] == 'linux-x64-ext4-build-id-visible-metadata-v1'
        assert outcome['durability'] == 'linux-file-force-directory-fsync-v1'
        checks.append({'label': label, 'outcome': expected})
        return outcome

    def generation(result, layout):
        source = Path(result['source'])
        folder = source.parent.parent
        assert source.parent.name == 'source' and source.name == 'forge.dbg.c'
        assert digest(folder / 'export.source') == digest(owned / layout / 'forge.dbg.c') == digest(source)
        if layout == 'multi':
            for name in dependencies:
                assert digest(folder / name) == digest(owned / layout / name) == digest(source.parent / name)
        retained = {str(path): digest(path) for path in folder.rglob('*') if path.is_file()}
        assert 'validation.json' in {Path(path).name for path in retained}
        generations.append({'layout': layout, 'source': str(source), 'files': retained})
        return source

    def gdb(label, layout, source=None):
        result_dir = work / label
        result_dir.mkdir()
        options = ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
            'set auto-solib-add off', 'set disable-randomization off',
            'set debug-file-directory ' + str(debug)]
        if source is not None:
            # GDB applies the first matching substitution. A retained generation
            # may live below the export fixture root; preserve that more specific
            # directory while making fallback to the old export sources fail.
            options.append('set substitute-path ' + json.dumps(str(source.parent)) + ' ' + json.dumps(str(source.parent)))
        options += ['set substitute-path ' + json.dumps(str(export)) + ' ' + json.dumps(str(work / 'unavailable-export')),
            'file ' + json.dumps(str(original))]
        if source is None:
            options += ['python assert gdb.find_pc_line(int(gdb.parse_and_eval("&recovered_first"))).symtab is None',
                'echo NO_INSTALLED_SOURCE_PASS\\n']
        command = ['gdb-multiarch', '-q', '-nx', '-batch']
        for option in options: command += ['-ex', option]
        if source is not None: command += ['-x', str(harness / 'multifile-target-gdb.py')]
        environment = dict(os.environ, DEBUGINFOD_URLS='', FORGE_MULTI_CASE=str(result_dir),
            FORGE_MULTI_MODE=layout, FORGE_MULTI_SYMBOLS=str(source)[:-2] if source else '', FORGE_MULTI_REMOTE='')
        hidden = work / 'inputs-offline'
        owned.rename(hidden)
        try:
            result = run(label, command, environment=environment)
        finally:
            hidden.rename(owned)
        output = result.stdout + result.stderr
        assert not re.search(r'warning:|error:|Traceback|No such file', output, re.I), output
        if source is None:
            assert 'NO_INSTALLED_SOURCE_PASS' in output
            observed = {'status': 'PASS_NO_REGISTRATION'}
        else:
            observed = json.loads((result_dir / (layout + '-observations.json')).read_text())
            assert observed['status'] == 'PASS' and observed['observed'] == 10 and observed['exitCodes'] == [0]
            assert len(observed['stops']) == 2
            assert all(Path(stop['file']).parent == source.parent for stop in observed['stops'])
        consumers.append({'label': label, 'layout': layout, 'observation': observed,
            'stdoutSha256': digest(work / (label + '.stdout')), 'inputsHidden': True})

    installed = operation('install-multi', 'multi', 'install', 'INSTALLED')
    first_source = generation(installed, 'multi')
    gdb('gdb-installed-multi', 'multi', first_source)
    before = {str(path): (digest(path), path.stat().st_ino) for path in debug.rglob('*') if path.is_file()}
    operation('idempotent-multi', 'multi', 'install', 'ALREADY_INSTALLED')
    assert before == {str(path): (digest(path), path.stat().st_ino) for path in debug.rglob('*') if path.is_file()}
    registration = Path(installed['registration'])
    for index, name in enumerate(dependencies):
        selected = first_source.parent / name
        content, stat = selected.read_bytes(), selected.stat()
        try:
            selected.write_bytes(bytes([content[0] ^ 1]) + content[1:])
            os.utime(selected, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            operation('changed-dependency-' + str(index), 'multi', 'remove', None)
            assert digest(registration) == before[str(registration)][0]
            refusals.append(name)
        finally:
            selected.write_bytes(content)
            os.utime(selected, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    single = operation('update-single', 'single', 'update', 'UPDATED')
    single_source = generation(single, 'single')
    gdb('gdb-updated-single', 'single', single_source)
    multi = operation('update-multi', 'multi', 'update', 'UPDATED')
    last_source = generation(multi, 'multi')
    assert last_source != first_source
    gdb('gdb-updated-multi', 'multi', last_source)
    operation('remove', 'multi', 'remove', 'REMOVED')
    assert not registration.exists()
    gdb('gdb-removed', 'multi')
    assert all(digest(Path(path)) == expected for item in generations for path, expected in item['files'].items())
    assert owned_hashes == {str(path.relative_to(owned)): digest(path) for path in owned.rglob('*') if path.is_file()}
    assert protected == {path: digest(Path(path)) for path in protected}
    save(work / 'result.json', {'status': 'PASS_BUILD_ID_SOURCE_BUNDLE', 'target': 'x86_64',
        'host': 'linux-x64-ext4-build-id-visible-metadata-v1', 'checks': checks, 'consumers': consumers,
        'dependencies': dependencies, 'refusedDependencies': refusals, 'generations': generations,
        'protected': protected, 'productionJarSha256': digest(args.jar), 'inputsUnchanged': True,
        'retainedGenerationsUnchanged': True, 'registrationRemoved': True})
    coverage.finish(work / 'result.json')
    print('build-id-source-bundle=PASS dependencies=' + str(len(dependencies)), flush=True)


if __name__ == '__main__':
    main()

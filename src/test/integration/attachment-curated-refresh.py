#!/usr/bin/env python3
"""Saved Ghidra analyst edits through the real attachment/refresh coordinator.

This Linux x86-64 harness selects the production host only through an explicit
already-authorized test invocation; the historical limited host remains a control.
Both modes require the production live validator for initial and refreshed pairs.
It does not enable a public attachment command or prove Windows metadata.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import zlib

ROOT = Path(__file__).resolve().parents[3]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def state(path):
    metadata = path.stat()
    return [digest(path), metadata.st_dev, metadata.st_ino, metadata.st_mode,
            metadata.st_uid, metadata.st_gid, metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--role', choices=['exec', 'pie'], required=True)
    parser.add_argument('--strict-validator', type=Path, required=True)
    parser.add_argument('--supervised-validator-helper', type=Path, required=True)
    parser.add_argument('--result-dir', type=Path, required=True)
    parser.add_argument('--consumer', type=Path)
    parser.add_argument('--producer', type=Path)
    parser.add_argument('--production-linux-host', action='store_true')
    parser.add_argument('--source-lines', type=int, default=0)
    parser.add_argument('--scratch', type=Path)
    args = parser.parse_args()
    require(args.source_lines >= 0, "source lines must be nonnegative")
    require(not args.production_linux_host or os.geteuid() == 0,
            'production Linux host fixture requires explicit privileged invocation')
    require(bool(args.consumer) == bool(args.producer), 'select both native development paths or neither')
    work = args.result_dir.absolute()
    work.mkdir(parents=True, exist_ok=False)
    scratch = args.scratch.absolute() if args.scratch else work / 'scratch'
    scratch.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve(strict=True)
    fixture = args.fixture_dir.resolve() / 'x86_64' / ('semantic.' + args.role + '.stripped')
    reference = fixture.with_suffix('.reference')
    original = work / 'original.elf'
    shutil.copy2(fixture, original)
    original.chmod(original.stat().st_mode | 0o100)
    original_hash = digest(original)
    backup = work / 'original.backup'
    project = scratch / 'project'
    project.mkdir()
    provenance = work / 'provenance'
    provenance.mkdir()
    exporter_jar = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    java_sources = [ROOT / 'src/test/java/ghidradwarfforge/output' / (name + '.java') for name in
                    ['AttachmentProtocolSmoke', 'AttachmentReceiptStoreSmoke',
                     'AttachmentElfTransactionProbe', 'AttachmentCuratedRefreshProbe']]
    scripts = ROOT / 'src/test/integration/ghidra_scripts'
    oracle = ROOT / 'src/test/integration/automatic-association-gdb.py'
    # CI selects the installed JAR for both roles. Keep both retained names even
    # when their source path is identical; a path-keyed dict drops operation.jar.
    inputs = [(args.jar.resolve(), 'operation.jar'), (exporter_jar, 'installed-exporter.jar'),
              (ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar', 'gson.jar'),
              (ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar', 'jna.jar')]
    checker_bundle = args.strict_validator.resolve(strict=True).parents[1]
    validator_tools = {'helper': args.supervised_validator_helper.resolve(strict=True),
        'readelf': Path(shutil.which('readelf')).resolve(strict=True),
        'llvm': Path(shutil.which('llvm-dwarfdump')).resolve(strict=True),
        'strict': checker_bundle / 'libexec/dwarfdump',
        'configuration': checker_bundle / 'share/dwarfdump/dwarfdump.conf'}
    for role, path in validator_tools.items():
        inputs.append((path, 'validator-' + role))
    for path in [*java_sources, Path(__file__), oracle, scripts / 'CurateAttachmentRefresh.java',
                 scripts / 'RenameFixtureFunction.java', ROOT / 'src/test/integration/check-dwarfdump.py']:
        inputs.append((path, path.name))
    protected = {str(path): digest(path) for path in
                 [*[path for path, _ in inputs], fixture, reference, args.strict_validator.resolve()]}
    for path, name in inputs:
        shutil.copyfile(path, provenance / name)
        require(digest(provenance / name) == protected[str(path)], 'retained source/runtime differs')
    (provenance / 'origin.json').write_text(json.dumps(protected, indent=4) + '\n')
    commands = []

    def run(label, argv, env=None, timeout=60, expected=0):
        command = list(map(str, argv))
        # Own the entire Linux test process group so a headless shell timeout
        # cannot leave its Ghidra JVM running against the retained project.
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd=work, env=env, start_new_session=True) as child:
            timed_out = False
            try:
                stdout, stderr = child.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                stdout, stderr = child.communicate(timeout=10)
            result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        (work / (label + '.stdout')).write_bytes(result.stdout)
        (work / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'label': label, 'argv': command, 'exit': result.returncode, 'timedOut': timed_out})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        require(result.returncode == expected, label + ' unexpected exit; inspect retained stdout/stderr')
        return result

    java = os.environ.get('JAVA', 'java')
    require(b'version "21.' in run('java-version', [java, '-version']).stderr, 'actual Java 21 is required')
    for tool in ['readelf', 'llvm-dwarfdump', 'gdb-multiarch']:
        run(tool + '-version', [tool, '--version'])
    classes = work / 'classes'
    classes.mkdir()
    classpath = os.pathsep.join(str(provenance / name) for name in ['operation.jar', 'gson.jar', 'jna.jar'])
    run('compile', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', classpath,
                    '-d', classes, *[provenance / path.name for path in java_sources]])
    runtime = os.pathsep.join([str(classes), classpath])
    spec = importlib.util.spec_from_file_location('refresh_strict_oracle', provenance / 'check-dwarfdump.py')
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    symbols = run('reference-symbols', ['readelf', '-Ws', reference]).stdout.decode()

    def address(name):
        found = {int(line.split()[1], 16) for line in symbols.splitlines()
                 if len(line.split()) >= 8 and line.split()[0].rstrip(':').isdigit() and line.split()[7] == name}
        require(len(found) == 1, 'compiler reference symbol is not unique: ' + name)
        return found.pop()

    delta = 0x100000 if args.role == 'pie' else 0  # This existing x86-64 fixture import profile only.
    function_address = hex(address('recovered_add') + delta)
    prepare = ['-postScript', 'RenameFixtureFunction.java', function_address,
               hex(address('recovered_variadic') + delta), hex(address('recovered_spin') + delta),
               'recovered_add', hex(address('fixture_sink') + delta),
               hex(address('recovered_composite') + delta), hex(address('scoped_counter') + delta)]
    native = ['--packaged-natives'] if args.consumer is None else [
        '--libdwarf=' + str(args.consumer.resolve()), '--libdwarfp=' + str(args.producer.resolve())]
    for name in ['home', 'tmp']:
        (scratch / name).mkdir()
    vmargs = run('launch-options', [java, '-cp', ghidra / 'support/LaunchSupport.jar',
        'LaunchSupport', ghidra, '-vmargs']).stdout.decode().splitlines()
    headless = [java, *vmargs, '-Duser.home=' + str(scratch / 'home'), '-Djava.io.tmpdir=' + str(scratch / 'tmp'),
        '-Djna.tmpdir=' + str(scratch / 'tmp'), '-Xmx2G', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2',
        '-Djava.awt.headless=true', '-cp', ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar', 'ghidra.Ghidra',
        'ghidra.app.util.headless.AnalyzeHeadless', project, 'AttachmentRefresh', '-scriptPath', scripts]
    source_options = ['--source-lines=' + str(args.source_lines)] if args.source_lines else []
    initial = work / 'initial.dbg'
    refreshed = work / 'refreshed.dbg'
    anchor = ['-postScript', 'CurateAttachmentRefresh.java', 'anchor', function_address, str(original), original_hash]
    initial_export = run('initial-export', headless + ['-import', original, '-analysisTimeoutPerFile', '120',
        *prepare, *anchor, '-postScript', 'GhidraDwarfForge.java', *native, '--output=' + str(initial), *source_options], timeout=240)
    require(b'GhidraDwarfForge symbol export PASS' in initial_export.stdout, 'initial export did not complete')
    require(digest(original) == original_hash, 'default export changed original')
    generations = {}
    source_controls = []

    def source_inventory(source):
        paths = [source]
        manifest = None
        if args.source_lines:
            names = re.findall(r'^ \* Manifest: (forge-src-[0-9a-f]{64}\.json)$', source.read_text(), re.M)
            require(len(names) == 1, 'missing unique source manifest')
            path = source.parent / names[0]
            require(path.name == 'forge-src-' + digest(path) + '.json', 'manifest hash mismatch')
            manifest = json.loads(path.read_text())
            require(manifest['inputSha256'] == original_hash and manifest['indexName'] == source.name,
                'manifest input/index mismatch')
            require(len(manifest['parts']) > 1, 'fixture must contain multiple source parts')
            paths.append(path)
            for index, part in enumerate(manifest['parts'], 1):
                require(part['file'] == index and part['name'] == 'forge-src-%06d-%s.c' % (index, part['sha256']),
                    'incorrect source part identity')
                path = source.parent / part['name']
                require(digest(path) == part['sha256'] and path.stat().st_size == part['bytes'], 'source part differs')
                paths.append(path)
        return paths, manifest

    def attach(phase, sidecar, export_result, refresh=False):
        selected_original = backup if refresh else original
        records = []
        for line in export_result.stdout.decode().splitlines():
            marker = 'GhidraDwarfForge report: '
            if marker in line:
                value, end = json.JSONDecoder().raw_decode(line.split(marker, 1)[1])
                records.append(value)
        require(len(records) == 1 and records[0]['status'] in ['SUCCESS', 'PARTIAL'], 'expected one completed export report')
        report = work / (phase + '.report.json')
        report.write_text(json.dumps(records[0]) + '\n')
        source = Path(str(sidecar) + '.c')
        for role, path in [('input', selected_original), ('output', sidecar), ('source', source)]:
            require(records[0]['artifacts'][role + 'Sha256'].lower() == digest(path), 'export report bytes disagree')
        outputs = []
        for tool, argv in [
            ('readelf', ['readelf', '-h', '-S', '--debug-dump=info,abbrev,aranges,decodedline', sidecar]),
            ('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
            ('strict', ['python3', provenance / 'check-dwarfdump.py', sidecar, work / (phase + '.strict.txt'),
                        '--tool', args.strict_validator.resolve(), '--original', selected_original])
        ]:
            label = phase + '-' + tool
            result = run(label, argv)
            require(not result.stderr, 'unexpected validator diagnostic: ' + label)
            if tool == 'llvm':
                require(result.stdout.count(b'No errors.') == 1, 'incomplete LLVM verification')
            outputs.append({'label': label, 'stdoutSha256': digest(work / (label + '.stdout')),
                            'stderrSha256': digest(work / (label + '.stderr'))})
        strict = json.loads((work / (phase + '.strict.txt.check.json')).read_text())
        require(strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0, 'strict validation failed')
        captured = work / (phase + '.captured.json')
        captured.write_text(json.dumps({'inputs': {str(path): digest(path) for path in
            [selected_original, sidecar, source, report]}, 'checks': outputs, 'strict': strict}, indent=4) + '\n')
        request = {'target': str(original), 'sidecar': str(sidecar), 'source': str(source),
            'exportReport': str(report), 'originalBackup': str(backup),
            'validatorTools': {role: str(path) for role, path in validator_tools.items()}}
        for field, suffix in [('validationEvidence', '.validation.json'), ('receipt', '.receipt.json'),
                              ('recoveryReceipt', '.recovery.json'), ('restoreImage', '.restore.elf')]:
            request[field] = str(work / (phase + suffix))
        if refresh:
            request.update({'previousReceipt': str(work / 'initial.receipt.json'), 'previousSidecar': str(initial),
                'previousSource': str(initial) + '.c', 'priorTargetBackup': str(work / 'prior-target.backup')})
        config = work / (phase + '.request.json')
        config.write_text(json.dumps(request, indent=4) + '\n')
        bound_inputs = {role: {'path': str(path), 'sha256': digest(path)} for role, path in
                        [('exportOriginal', selected_original), ('sidecar', sidecar), ('source', source), ('exportReport', report)]}
        host_option = ['-Dforge.test.attachment.productionLinuxHost=true'] if args.production_linux_host else []
        if refresh and args.source_lines:
            base_command = [java, *host_option, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
                'ghidradwarfforge.output.AttachmentCuratedRefreshProbe']
            for role in ['source', 'previousSource']:
                paths, _ = source_inventory(Path(request[role]))
                for kind, dependency in [('manifest', paths[1]), ('part', paths[2])]:
                    label = 'missing-' + role + '-' + kind
                    hidden = dependency.with_name(dependency.name + '.preflight-hidden')
                    require(not hidden.exists(), 'refusal control destination exists')
                    before = state(original)
                    dependency.rename(hidden)
                    try:
                        run(label, [*base_command, config], timeout=300, expected=1)
                        require(state(original) == before, 'incomplete source preparation changed target')
                        require(all(not Path(request[key]).exists() for key in
                            ['validationEvidence', 'receipt', 'recoveryReceipt', 'restoreImage', 'priorTargetBackup']),
                            'incomplete source preparation published output')
                    finally:
                        require(not dependency.exists(), 'missing dependency was unexpectedly recreated')
                        hidden.rename(dependency)
                    source_controls.append({'kind': 'preflight-refusal', 'role': role, 'dependency': str(dependency)})
            paths, manifest = source_inventory(source)
            function, = [entry for entry in manifest['functions'] if entry['name'] == 'curated_refresh_add'
                and int(entry['address'], 16) == address('recovered_add')]
            changed_part = source.parent / manifest['parts'][function['file'] - 1]['name']
            require(changed_part not in source_inventory(Path(request['previousSource']))[0], 'fault must not damage old generation')
            for boundary in ['PREPARED', 'TARGET_REPLACED']:
                for kind, dependency in [('manifest', paths[1]), ('part', changed_part)]:
                    label = 'rollback-' + boundary.lower() + '-' + kind
                    selected = dict(request, missingDependency=str(dependency), faultBoundary=boundary)
                    for key in ['validationEvidence', 'receipt', 'recoveryReceipt', 'restoreImage', 'priorTargetBackup']:
                        selected[key] = str(work / (label + '-' + key))
                    fault_config = work / (label + '.request.json')
                    fault_config.write_text(json.dumps(selected, indent=4) + '\n')
                    before = state(original)
                    result = run(label, [*base_command, fault_config], timeout=300)
                    require(b'attachment-curated-refresh=ROLLED_BACK' in result.stdout, 'fault did not roll back')
                    after = state(original)
                    require(after[0] == before[0] and after[3:] == before[3:], 'rollback changed old image or metadata')
                    require(source_inventory(source)[1] == manifest, 'rollback changed selected source inventory')
                    debug(label, initial)
                    source_controls.append({'kind': 'rollback', 'boundary': boundary, 'dependency': str(dependency)})
        committed = run(phase + '-attach', [java, *host_option, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
            'ghidradwarfforge.output.AttachmentCuratedRefreshProbe', config], timeout=300)
        require(b'attachment-curated-refresh=COMMITTED' in committed.stdout, 'attachment did not commit')
        receipt = json.loads(Path(request['receipt']).read_text())
        if args.production_linux_host:
            require(b'host=production-linux' in committed.stdout and
                    receipt['hostContract'] == 'linux-x64-ext4-protected-metadata-v1', 'wrong production host')
            require(not list(work.glob('.forge-visibility-*')), 'production visibility workspace leaked')
        require(receipt['phase'] == 'COMMITTED', 'receipt did not commit')
        require(receipt['debuglinkCrc32'] == zlib.crc32(sidecar.read_bytes()), 'receipt CRC differs from actual pair')
        validation = json.loads(Path(request['validationEvidence']).read_text())
        require(validation['policy'] == 'gnu-llvm-libdwarf-2.3.2-v1' and validation['status'] == 'PASS',
                'refresh did not use the complete live policy')
        require(validation['exportStatus'] == records[0]['status'] and
                validation['exportValidationStatus'] == records[0]['validation']['status'], 'export status was rewritten')
        for role, expected in bound_inputs.items():
            require(all(validation['inputs'][role][key] == value for key, value in expected.items()), 'live input binding differs')
        expected_checks = {'gnuReadelfVersion', 'llvmDwarfdumpVersion', 'strictDwarfdumpVersion',
                           'gnuReadelf', 'llvmDwarfdump', 'strictSidecar'}
        if validation['corroboratedFrameDiagnostics']:
            expected_checks.add('strictOriginal')
            frame, _ = checker.elf_frame_identity(backup)
            require(frame['section_sha256'] == validation['inheritedFrame']['sha256'], 'refresh frame evidence differs')
        require(set(validation['checks']) == expected_checks, 'incomplete live refresh checks')
        for name, check in validation['checks'].items():
            require(check['reason'] == 'completed' and check['cleanupComplete'] and check['exitCode'] == 0,
                    'live refresh process did not complete')
            for log in check['logs'].values():
                path = Path(log['path'])
                require(path.is_relative_to(work) and digest(path) == log['sha256'] and path.stat().st_size == log['bytes'],
                        'live refresh raw evidence is missing or changed')
                generations.setdefault(str(path), state(path))
            require(not Path(check['logs']['tool.stderr']['path']).read_bytes(), 'live refresh checker wrote stderr')
            text = Path(check['logs']['tool.stdout']['path']).read_text()
            if name in ('strictSidecar', 'strictOriginal'):
                checker.validate_output(text, validation['corroboratedFrameDiagnostics'], original=name == 'strictOriginal')
            if name == 'llvmDwarfdump':
                require(text.count('No errors.') == 1, 'live refresh LLVM check incomplete')
        for tool in validation['tools'].values():
            require(digest(Path(tool['path'])) == tool['sha256'], 'live refresh tool provenance changed')
        for path in [sidecar, *source_inventory(source)[0], report, captured, Path(request['receipt']), Path(request['validationEvidence']), backup]:
            generations.setdefault(str(path), state(path))
        return receipt

    def debug(phase, sidecar, updated=False):
        source = Path(str(sidecar) + '.c')
        _, manifest = source_inventory(source)
        if manifest:
            function = 'curated_refresh_add' if updated else 'recovered_add'
            selected = [entry for entry in manifest['functions']
                if entry['name'] == function and int(entry['address'], 16) == address('recovered_add')]
            require(len(selected) == 1 and selected[0]['disposition'] == 'decompiled', 'missing function source part')
            source = source.parent / manifest['parts'][selected[0]['file'] - 1]['name']
        env = {**os.environ, 'DEBUGINFOD_URLS': '', 'FORGE_ASSOCIATION_MODE': 'present',
               'FORGE_ASSOCIATION_ADDRESS': hex(address('recovered_add')),
               'FORGE_ASSOCIATION_DEBUG_FILE': str(sidecar), 'FORGE_ASSOCIATION_SOURCE': str(source),
               'FORGE_ASSOCIATION_RUNTIME': '1'}
        if updated:
            env.update({'FORGE_ASSOCIATION_FUNCTION': 'curated_refresh_add',
                        'FORGE_ASSOCIATION_TYPE': 'curated_refresh_state',
                        'FORGE_ASSOCIATION_MEMBER': 'curated_refresh_member'})
        observed = run(phase + '-gdb', ['gdb-multiarch', '-nx', '-nh', '-batch',
            '-iex', 'set debuginfod enabled off', '-iex', 'set auto-load off',
            '-iex', 'set debug-file-directory ' + str(work / 'empty-debug-root'),
            '-ex', 'file "' + str(original) + '"', '-ex', 'source ' + str(provenance / oracle.name)], env)
        require(not observed.stderr, 'GDB emitted unexpected diagnostics')
        require(b'automatic-association=present PASS' in observed.stdout and b'exited normally' in observed.stdout,
                'GDB did not discover/run the selected generation')

    (work / 'empty-debug-root').mkdir()
    first_receipt = attach('initial', initial, initial_export)
    require(digest(backup) == original_hash and digest(original) != original_hash, 'initial attachment/backup bytes incorrect')
    debug('initial', initial)
    first_target = state(original)
    before_programs = run('initial-programs', ['readelf', '-lW', original]).stdout
    edit = ['-postScript', 'CurateAttachmentRefresh.java', 'edit', function_address, str(original), original_hash]
    edited = run('curate-save', headless + ['-process', original.name, '-noanalysis', *edit], timeout=180)
    require(b'curated-refresh-program=PASS mode=edit' in edited.stdout, 'analyst edits did not save')
    verify = ['-postScript', 'CurateAttachmentRefresh.java', 'verify', function_address, str(original), original_hash]
    # Ordinary export must still reject the modified original: do not weaken or
    # rewrite the saved program's import hash to make refresh appear successful.
    rejected_path = work / 'must-not-exist.dbg'
    rejected = run('attached-input-rejection', headless + ['-process', original.name, '-noanalysis', '-readOnly',
        *verify, '-postScript', 'GhidraDwarfForge.java', *native, '--input=' + str(original),
        '--output=' + str(rejected_path)], timeout=180)
    require(b'imported executable SHA-256' in rejected.stdout and not rejected_path.exists() and
            not Path(str(rejected_path) + '.c').exists(), 'modified target bypassed the import hash contract')
    fresh_export = run('refresh-export', headless + ['-process', original.name, '-noanalysis', '-readOnly',
        *verify, '-postScript', 'GhidraDwarfForge.java', *native, '--input=' + str(backup),
        '--output=' + str(refreshed), *source_options, *verify], timeout=180)
    require(fresh_export.stdout.count(b'curated-refresh-program=PASS mode=verify') == 2 and
            b'GhidraDwarfForge symbol export PASS' in fresh_export.stdout, 'saved analyst refresh export failed')
    require(state(original) == first_target, 're-export modified attached target')
    require(zlib.crc32(initial.read_bytes()) != zlib.crc32(refreshed.read_bytes()), 'fixture must exercise changed CRC')
    second_receipt = attach('refresh', refreshed, fresh_export, True)
    require(second_receipt['mode'] == 'REFRESH', 'refresh did not retain transaction ancestry')
    require(second_receipt['files']['previousReceipt']['sha256'] == digest(work / 'initial.receipt.json') and
            second_receipt['files']['previousSidecar']['sha256'] == digest(initial) and
            second_receipt['files']['previousSource']['sha256'] == digest(Path(str(initial) + '.c')) and
            second_receipt['files']['originalBackup'] == first_receipt['files']['originalBackup'],
            'refresh receipt did not bind the original backup and immutable prior generation')
    require(state(original)[0] != first_target[0], 'refresh did not replace debuglink')
    require(digest(work / 'prior-target.backup') == first_target[0], 'prior attached target was not retained')
    require(before_programs == run('refresh-programs', ['readelf', '-lW', original]).stdout,
            'refresh changed program headers or section mappings')
    debug('refresh', refreshed, True)
    for path, expected in generations.items():
        require(state(Path(path)) == expected, 'retained generation changed: ' + path)
    for path, expected in protected.items():
        require(digest(Path(path)) == expected, 'fixture/tool/source input changed: ' + path)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'role': args.role, 'sourceLines': args.source_lines,
        'originalSha256': original_hash, 'initialReceipt': first_receipt, 'refreshReceipt': second_receipt,
        'preservedGenerations': generations, 'preservedInputs': protected, 'sourceControls': source_controls,
        'host': 'production Linux ext4 host' if args.production_linux_host else 'limited Linux test host',
        'scope': 'saved Ghidra edit/reopen and backup-based re-export; real coordinator/live validator initial/changed-CRC refresh; native GDB source/type/member/arguments'}, indent=4) + '\n')
    print('attachment-curated-refresh=PASS role=' + args.role)


if __name__ == '__main__':
    main()

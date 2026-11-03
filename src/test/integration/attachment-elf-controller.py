#!/usr/bin/env python3
"""Real-export controller test, not the product attachment entry point.

Fresh validators gate each transaction. Production Linux initial attachment
runs the isolated product helper; rollback injection uses the test-only bridge.
The historical default bridge retains its explicitly limited test host.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import zlib

ROOT = Path(__file__).resolve().parents[3]


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            result.update(chunk)
    return result.hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def file_state(path):
    state = path.stat()
    return {'sha256': digest(path), 'device': state.st_dev, 'inode': state.st_ino,
            'mode': state.st_mode, 'uid': state.st_uid, 'gid': state.st_gid,
            'links': state.st_nlink, 'size': state.st_size, 'mtimeNs': state.st_mtime_ns}


def debuglink_payload(path):
    """Independent bounded ELF section reader for these small runtime fixtures."""
    data = path.read_bytes()
    require(data[:4] == b'\x7fELF' and data[4] in (1, 2) and data[5] in (1, 2), 'invalid fixture ELF')
    wide = data[4] == 2
    order = '<' if data[5] == 1 else '>'
    offset = struct.unpack_from(order + ('Q' if wide else 'I'), data, 40 if wide else 32)[0]
    size, count, names_index = struct.unpack_from(order + 'HHH', data, 58 if wide else 46)
    fmt = order + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII')
    require(offset > 0 and size >= struct.calcsize(fmt), 'fixture section table is absent or truncated')
    zero = struct.unpack_from(fmt, data, offset)
    count = count or zero[5]
    names_index = zero[6] if names_index == 0xffff else names_index
    require(0 < count <= 10000 and names_index < count and offset + count * size <= len(data), 'fixture table bounds')
    sections = [struct.unpack_from(fmt, data, offset + i * size) for i in range(count)]
    names = sections[names_index]
    require(names[4] + names[5] <= len(data), 'fixture names exceed file')
    strings = data[names[4]:names[4] + names[5]]
    matches = [s for s in sections if s[0] < len(strings) and strings[s[0]:].split(b'\0', 1)[0] == b'.gnu_debuglink']
    require(len(matches) == 1, 'fixture must have one debuglink section')
    link = matches[0]
    require(link[1] == 1 and link[4] + link[5] <= len(data), 'fixture debuglink payload bounds/type')
    return data[link[4]:link[4] + link[5]], order


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--target', choices=['x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'], required=True)
    parser.add_argument('--role', choices=['exec', 'pie', 'exec.no-build-id'], required=True)
    parser.add_argument('--report-log', type=Path, required=True)
    parser.add_argument('--strict-validator', type=Path, required=True)
    parser.add_argument('--supervised-validator-helper', type=Path)
    parser.add_argument('--production-linux-host', action='store_true',
                        help='explicit already-authorized fixture process using the production Linux Host')
    parser.add_argument('--sidecar-basename', help='Literal basename for the owned transaction copy; original inputs remain unchanged')
    parser.add_argument('--result-dir', type=Path, required=True)
    args = parser.parse_args()
    require(not args.production_linux_host or (os.geteuid() == 0 and args.supervised_validator_helper is not None),
            'production Linux host fixtures require explicit privileged invocation and live validators')
    work = args.result_dir.absolute()
    work.mkdir(parents=True, exist_ok=False)
    stem = args.fixture_dir.resolve() / args.target / ('semantic.' + args.role)
    original = Path(str(stem) + '.stripped')
    sidecar = Path(str(stem) + '.ghidra-forge.dbg')
    source = Path(str(sidecar) + '.c')
    reference = Path(str(stem) + '.reference')
    jar = args.jar.resolve(strict=True)
    gson = args.ghidra.resolve() / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar'
    jna = args.ghidra.resolve() / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar'
    sources = [ROOT / 'src/test/java/ghidradwarfforge/output' / (name + '.java') for name in
               ['AttachmentProtocolSmoke', 'AttachmentReceiptStoreSmoke', 'AttachmentElfTransactionProbe',
                'StrictDwarfCheckProbe', 'AttachmentValidatorProbe', 'LinuxAttachmentRecoveryProbe']]
    oracle = ROOT / 'src/test/integration/automatic-association-gdb.py'
    policy_controls = ROOT / 'src/test/integration/attachment-validator-controls.py'
    protected = {str(p): digest(p) for p in [original, sidecar, source, reference, jar, gson, jna,
                                           args.report_log, args.strict_validator, Path(__file__), oracle, policy_controls, *sources]}
    provenance = work / 'provenance'
    provenance.mkdir()
    for path in [jar, gson, jna, Path(__file__), oracle, policy_controls, *sources]:
        shutil.copyfile(path, provenance / path.name)
        require(digest(provenance / path.name) == protected[str(path)], 'retained runtime/source differs')
    # Run the exact retained production JAR and dependencies. Preserve their
    # input origin/hash above; subsequent local builds cannot erase this proof.
    runtime_files = [provenance / path.name for path in [jar, gson, jna]]
    (provenance / 'origin.json').write_text(json.dumps({str(path): protected[str(path)]
        for path in [jar, gson, jna, Path(__file__), oracle, policy_controls, *sources]}, indent=4) + '\n')
    commands = []

    def run(label, argv, env=None, timeout=60, success=True, input_bytes=None):
        command = list(map(str, argv))
        completed = subprocess.run(command, capture_output=True, timeout=timeout, env=env, cwd=work, input=input_bytes)
        (work / (label + '.stdout')).write_bytes(completed.stdout)
        (work / (label + '.stderr')).write_bytes(completed.stderr)
        commands.append({'label': label, 'argv': command, 'exit': completed.returncode})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        require((completed.returncode == 0) == success, label + ' had unexpected status; inspect retained stdout/stderr')
        return completed

    for tool in ['readelf', 'llvm-dwarfdump', 'gdb-multiarch']:
        run(tool + '-version', [tool, '--version'])

    records = []
    for line in args.report_log.read_text().splitlines():
        marker = 'GhidraDwarfForge report: '
        if marker in line:
            text = line.split(marker, 1)[1]
            value, end = json.JSONDecoder().raw_decode(text)
            records.append((value, text[:end]))
    require(len(records) == 1, 'select a log with exactly one exporter report')
    report, raw_report = records[0]
    require(report['status'] in ['SUCCESS', 'PARTIAL'], 'export did not complete')
    for role, path in [('input', original), ('output', sidecar), ('source', source)]:
        require(report['artifacts'][role + 'Sha256'].lower() == protected[str(path)], 'stale selected ' + role)
    report_path = work / 'export-report.json'
    report_path.write_text(raw_report + '\n')
    retained = work / 'validated-inputs'
    retained.mkdir()
    for path in [original, sidecar, source]:
        shutil.copyfile(path, retained / path.name)
        require(digest(retained / path.name) == protected[str(path)], 'retained input differs')
    validated_original = retained / original.name
    validated_sidecar = retained / sidecar.name
    validation = []
    for label, argv in [
        ('readelf', ['readelf', '-h', '-S', '--debug-dump=info,abbrev,aranges,decodedline', validated_sidecar]),
        ('llvm', ['llvm-dwarfdump', '--verify', validated_sidecar]),
        ('strict', ['python3', ROOT / 'src/test/integration/check-dwarfdump.py', validated_sidecar,
                    work / 'strict.txt', '--tool', args.strict_validator.resolve(), '--original', validated_original])
    ]:
        observed = run(label, argv)
        require(not observed.stderr, label + ' emitted unexplained stderr')
        if label == 'llvm':
            require(observed.stdout.count(b'No errors.') == 1, 'LLVM did not verify complete sidecar')
        validation.append({'tool': label, 'stdoutSha256': digest(work / (label + '.stdout')),
                           'stderrSha256': digest(work / (label + '.stderr'))})
    strict_result = json.loads((work / 'strict.txt.check.json').read_text())
    require(strict_result['status'] == 'PASS', 'strict validator rejected sidecar')
    evidence = work / 'validation-evidence.json'
    evidence.write_text(json.dumps({'scope': 'test-only fresh validation of explicitly selected retained export',
        'inputs': {str(p): digest(p) for p in [validated_original, validated_sidecar, retained / source.name, report_path]},
        'checks': validation, 'strict': strict_result}, indent=4) + '\n')
    classes = work / 'classes'
    classes.mkdir()
    dependencies = os.pathsep.join(map(str, runtime_files))
    run('compile', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', dependencies,
                    '-d', classes, *sources])
    java = os.environ.get('JAVA', 'java')
    version = run('java-version', [java, '-version'])
    require(b'version "21.' in version.stderr, 'this harness requires actual Java 21')
    runtime = os.pathsep.join([str(classes), dependencies])
    live_validator_arguments = []
    if args.supervised_validator_helper is not None:
        helper = args.supervised_validator_helper.resolve(strict=True)
        checker_bundle = args.strict_validator.resolve(strict=True).parents[1]
        raw_checker = checker_bundle / 'libexec/dwarfdump'
        configuration = checker_bundle / 'share/dwarfdump/dwarfdump.conf'
        live_validator_arguments = [helper, Path(shutil.which('readelf')).resolve(),
                                    Path(shutil.which('llvm-dwarfdump')).resolve(), raw_checker, configuration]
        for path in [helper, raw_checker, configuration]:
            protected[str(path)] = digest(path)
            shutil.copyfile(path, provenance / path.name)
        checks = work / 'supervised-strict'
        checks.mkdir()

        def strict_case(label, selected_report=report_path, selected_sidecar=sidecar,
                        selected_tool=raw_checker, selected_config=configuration, success=True):
            directory = checks / label
            directory.mkdir()
            outcome = run('supervised-' + label, [java, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
                'ghidradwarfforge.output.StrictDwarfCheckProbe', selected_report, original,
                selected_sidecar, source, helper, selected_tool, selected_config, directory],
                timeout=300, success=success)
            require((directory / 'result.json').exists() == success, 'unexpected strict result publication')
            return directory, outcome

        successful, _ = strict_case('actual')
        observed = json.loads((successful / 'result.json').read_text())
        strict_output = Path(observed['sidecarCheck']['directory']) / 'tool.stdout'
        require(digest(strict_output) == observed['sidecarCheck']['stdoutSha256'], 'strict raw log hash differs')
        spec = importlib.util.spec_from_file_location('strict_report_oracle', ROOT / 'src/test/integration/check-dwarfdump.py')
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        inherited = strict_result.get('inherited_frame_evidence', {}).get('diagnostics', [])
        require(observed['corroboratedDiagnostics'] == inherited, 'supervised and independent diagnostics disagree')
        checker.validate_output(strict_output.read_text(), inherited)
        if inherited:
            original_output = Path(observed['originalCheck']['directory']) / 'tool.stdout'
            checker.validate_output(original_output.read_text(), inherited, original=True)
            # Same bytes and valid complete reports are insufficient when the
            # observed diagnostic offsets differ between original and sidecar.
            changed = checks / 'different-frame-report.txt'
            changed.write_text(original_output.read_text().replace(inherited[0],
                re.sub(r'offset 0x[0-9a-f]+', 'offset 0xffffffffffffffff', inherited[0]), 1))
            mismatch = checks / 'different-frame-tool'
            mismatch.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\n' +
                'selected = ' + repr(str(changed)) + ' if sys.argv[-1] == ' + repr(str(original)) +
                ' else ' + repr(str(strict_output)) + '\n' +
                'sys.stdout.buffer.write(Path(selected).read_bytes())\n')
            mismatch.chmod(0o755)
            directory, failure = strict_case('different-frame-diagnostics', selected_tool=mismatch, success=False)
            require(b'diagnostic identities/multiplicities differ' in failure.stderr,
                    'frame mismatch did not reach independent corroboration')
        # Exit-zero replay tools deliberately provide unusable reports. Their
        # outputs cannot become success evidence or reach target replacement.
        for label, payload in [('empty-report', b''),
                               ('truncated-report', strict_output.read_bytes().split(b'** Summarize **', 1)[0])]:
            replay = checks / (label + '.txt')
            replay.write_bytes(payload)
            fake = checks / (label + '-tool')
            fake.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nimport sys\n' +
                            'sys.stdout.buffer.write(Path(' + repr(str(replay)) + ').read_bytes())\n')
            fake.chmod(0o755)
            directory, _ = strict_case(label, selected_tool=fake, success=False)
            require(list(directory.glob('.forge-validation-*/status.json')), 'replay was not actually executed')
        bad_config = checks / 'changed.conf'
        bad_config.write_bytes(configuration.read_bytes() + b'\n# changed configuration\n')
        directory, _ = strict_case('wrong-config', selected_config=bad_config, success=False)
        require(not list(directory.iterdir()), 'wrong configuration launched a checker')
        # Keep report hashes current while corrupting only newly emitted DWARF:
        # binding must succeed, then the actual checker must reject the bytes.
        corrupted = checks / 'invalid-dwarf.dbg'
        data = bytearray(sidecar.read_bytes())
        wide = data[4] == 2
        endian = '<' if data[5] == 1 else '>'
        section_offset = struct.unpack_from(endian + ('Q' if wide else 'I'), data, 40 if wide else 32)[0]
        entry_size, count, names_index = struct.unpack_from(endian + 'HHH', data, 58 if wide else 46)
        format_ = endian + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII')
        sections = [struct.unpack_from(format_, data, section_offset + index * entry_size) for index in range(count)]
        names = sections[names_index]
        strings = data[names[4]:names[4] + names[5]]
        info = [section for section in sections if strings[section[0]:].split(b'\0', 1)[0] == b'.debug_info']
        require(len(info) == 1 and info[0][5] >= 4, 'fixture lacks one debug_info section')
        struct.pack_into(endian + 'I', data, info[0][4], 0x7ffffffe)
        corrupted.write_bytes(data)
        corrupt_report = json.loads(raw_report)
        corrupt_report['artifacts']['outputSha256'] = digest(corrupted)
        bad_report = checks / 'invalid-dwarf-report.json'
        bad_report.write_text(json.dumps(corrupt_report) + '\n')
        directory, _ = strict_case('invalid-dwarf', selected_report=bad_report, selected_sidecar=corrupted, success=False)
        require(list(directory.glob('.forge-validation-*/status.json')), 'invalid DWARF did not reach the actual checker')
        if args.target == 'x86_64' and args.role == 'exec':
            spec = importlib.util.spec_from_file_location('policy_controls', policy_controls)
            controls = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(controls)
            controls.exercise(java, runtime, report_path, original, sidecar, source,
                              live_validator_arguments, work / 'policy-controls', run)
    for action in ['commit', 'rollback']:
        directory = work / action
        directory.mkdir()
        basename_option = [] if args.sidecar_basename is None else [
            '-Dforge.test.attachment.sidecarBasename=' + args.sidecar_basename]
        if args.production_linux_host:
            basename_option.append('-Dforge.test.attachment.productionLinuxHost=true')
        if args.production_linux_host and action == 'commit':
            target = directory / original.name
            selected_sidecar = directory / (args.sidecar_basename or sidecar.name)
            selected_report = directory / report_path.name
            for src, dst in [(original, target), (sidecar, selected_sidecar), (report_path, selected_report)]:
                shutil.copy2(src, dst)
            invocation = {
                'schemaVersion': 1, 'operation': 'ATTACH',
                'paths': {name: str(path) for name, path in {
                    'target': target, 'sidecar': selected_sidecar, 'source': source, 'exportReport': selected_report,
                    'originalBackup': directory / 'original.backup', 'validationEvidence': directory / 'validation.json',
                    'receipt': directory / 'transaction.json', 'recoveryReceipt': directory / 'recovery.json',
                    'restoreImage': directory / 'restore.elf', 'recoveryInvocation': directory / 'saved-recovery.json'}.items()},
                'validatorTools': dict(zip(['helper', 'readelf', 'llvm', 'strict', 'configuration'],
                                          map(str, live_validator_arguments)))}
            request_file = directory / 'attachment-request.json'
            request_file.write_text(json.dumps(invocation, ensure_ascii=True) + '\n')
            command = [java, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
                'ghidradwarfforge.output.AttachmentHelper', '--request', request_file,
                '--request-sha256', digest(request_file)]
            before_admission = {str(path): file_state(path) for path in directory.iterdir()}
            for label, extra in [('no-consent', []), ('cancelled', ['--confirm-target-change', '--cancel-on-stdin'])]:
                refused = run('helper-' + label, command + extra, success=False, input_bytes=b'')
                response = json.loads(refused.stdout)
                require(response['outcome'] == ('CANCELLED' if label == 'cancelled' else 'FAILED'),
                        'helper admission returned the wrong outcome')
                require(before_admission == {str(path): file_state(path) for path in directory.iterdir()},
                        'helper refusal changed a selected file or created an output')
            outcome = run(action, command + ['--confirm-target-change'], timeout=300)
            response = json.loads(outcome.stdout)
            require(response['outcome'] == 'COMMITTED' and response['exitCode'] == 0 and
                    response['requestSha256'] == digest(request_file), 'helper did not commit the selected request')
            require(response['selection'] == invocation, 'helper used different explicit selections')
            saved = json.loads((directory / 'saved-recovery.json').read_text())
            require(saved['operation'] == 'RECOVER' and saved['paths']['receipt'] == str(directory / 'transaction.json') and
                    saved['committedReceiptSha256'] == digest(directory / 'transaction.json'),
                    'saved recovery selections do not bind the committed receipt')
            require(response['recoverySelection']['prepared']['hostContract'] ==
                    'linux-x64-ext4-protected-metadata-v1', 'helper used an incorrect host')
        else:
            outcome = run(action, [java, *basename_option, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
                'ghidradwarfforge.output.AttachmentElfTransactionProbe', report_path, original,
                sidecar, source, evidence, directory, action, *live_validator_arguments], timeout=300)
            require(b'attachment-elf-controller=PASS' in outcome.stdout, 'controller did not complete')
            if args.production_linux_host:
                require(b'host=production-linux' in outcome.stdout, 'controller did not use the production host')
        if args.production_linux_host:
            receipt = json.loads((directory / 'transaction.json').read_text())
            require(receipt['hostContract'] == 'linux-x64-ext4-protected-metadata-v1', 'wrong receipt host contract')
            require(not list(directory.glob('.forge-visibility-*')), 'production host visibility workspace leaked')
        require(digest(directory / 'original.backup') == protected[str(original)], 'backup bytes differ')
        if live_validator_arguments:
            combined = json.loads((directory / 'validation.json').read_text())
            require(combined['schemaVersion'] == 1 and combined['status'] == 'PASS' and
                    combined['policy'] == 'gnu-llvm-libdwarf-2.3.2-v1', 'wrong combined validator policy')
            require(combined['exportStatus'] == report['status'] and
                    combined['exportValidationStatus'] == report['validation']['status'],
                    'live validation rewrote the export status')
            for role, expected in [('exportOriginal', original), ('sidecar', sidecar),
                                   ('source', source), ('exportReport', report_path)]:
                require(combined['inputs'][role]['sha256'] == digest(expected), 'combined input binding differs')
            required_checks = {'gnuReadelfVersion', 'llvmDwarfdumpVersion', 'strictDwarfdumpVersion',
                               'gnuReadelf', 'llvmDwarfdump', 'strictSidecar'}
            if combined['corroboratedFrameDiagnostics']:
                required_checks.add('strictOriginal')
                frame, _ = checker.elf_frame_identity(directory / 'original.backup')
                require(frame['section_sha256'] == combined['inheritedFrame']['sha256'] and
                        frame['section_size'] == combined['inheritedFrame']['bytes'] and
                        frame['section_address'] == combined['inheritedFrame']['address'], 'frame proof differs')
            require(set(combined['checks']) == required_checks, 'missing or unexpected combined checks')
            for name, check in combined['checks'].items():
                require(check['reason'] == 'completed' and check['exitCode'] == 0 and check['cleanupComplete'],
                        'combined check did not complete')
                for log in check['logs'].values():
                    path = Path(log['path'])
                    require(path.is_relative_to(directory) and path.stat().st_size == log['bytes'] and
                            digest(path) == log['sha256'], 'combined raw log is missing, moved or changed')
                stdout = Path(check['logs']['tool.stdout']['path']).read_text()
                require(not Path(check['logs']['tool.stderr']['path']).read_bytes(), 'combined checker stderr')
                if name in ('strictSidecar', 'strictOriginal'):
                    checker.validate_output(stdout, combined['corroboratedFrameDiagnostics'], original=name == 'strictOriginal')
                if name == 'llvmDwarfdump':
                    require(stdout.count('No errors.') == 1, 'combined LLVM verification incomplete')
            for tool in combined['tools'].values():
                require(digest(Path(tool['path'])) == tool['sha256'], 'combined tool/configuration provenance differs')
        if action == 'rollback':
            require(digest(directory / original.name) == protected[str(original)], 'rollback did not restore original')
        before = run(action + '-original-programs', ['readelf', '-lW', original])
        after = run(action + '-installed-programs', ['readelf', '-lW', directory / original.name])
        require(before.stdout == after.stdout, 'installed program headers or section mapping differs')

    if args.production_linux_host and args.target == 'x86_64' and args.role == 'exec':
        recovered = run('native-recovery', [java, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
            'ghidradwarfforge.output.LinuxAttachmentRecoveryProbe', work / 'native-recovery'], timeout=300)
        require(b'linux-attachment-recovery=PASS cases=8 abrupt-exits=8' in recovered.stdout,
                'native initial/refresh recovery did not complete')
        recovery = json.loads((work / 'native-recovery/result.json').read_text())
        require(len(recovery['outcomes']) == 8 and recovery['retainedCrashCanaries'] == 8,
                'missing crash outcomes or incorrect canary lifecycle')
    generations = {str(path): file_state(path) for action in ['commit', 'rollback']
                   for path in (work / action).rglob('*') if path.is_file()}
    (work / 'generation-state.json').write_text(json.dumps(generations, indent=4) + '\n')

    symbols = run('reference-symbols', ['readelf', '-Ws', reference]).stdout.decode()
    addresses = {int(line.split()[1], 16) for line in symbols.splitlines()
                 if len(line.split()) >= 8 and line.split()[0].rstrip(':').isdigit() and line.split()[7] == 'recovered_add'}
    require(len(addresses) == 1, 'reference recovered_add must have one address')
    empty = work / 'empty-debug-root'
    empty.mkdir()
    installed_sidecar = work / 'commit' / (args.sidecar_basename or sidecar.name)
    payload, byte_order = debuglink_payload(work / 'commit' / original.name)
    filename = os.fsencode(installed_sidecar.name)
    expected_payload = filename + b'\0'
    expected_payload += b'\0' * ((-len(expected_payload)) % 4)
    expected_payload += struct.pack(byte_order + 'I', zlib.crc32(installed_sidecar.read_bytes()))
    require(payload == expected_payload, 'debuglink basename bytes, padding or target-endian CRC differ')
    env = os.environ.copy()
    env.update({'DEBUGINFOD_URLS': '', 'FORGE_ASSOCIATION_ADDRESS': hex(addresses.pop()),
                'FORGE_ASSOCIATION_DEBUG_FILE': str(installed_sidecar), 'FORGE_ASSOCIATION_SOURCE': str(source),
                'FORGE_ASSOCIATION_RUNTIME': '1'})
    gdb = ['gdb-multiarch', '-nx', '-nh', '-batch', '-iex', 'set debuginfod enabled off',
           '-iex', 'set auto-load off', '-iex', 'set debug-file-directory ' + str(empty),
           '-ex', 'file "' + str(work / 'commit' / original.name) + '"',
           '-ex', 'source ' + str(oracle)]
    env['FORGE_ASSOCIATION_MODE'] = 'present'
    profiles = {
        'aarch64': ('qemu-aarch64-static', '/usr/aarch64-linux-gnu'),
        'arm32': ('qemu-arm-static', os.environ.get('FORGE_ARM32_SYSROOT', '/usr/arm-linux-gnueabihf')),
        'mips32be': ('qemu-mips-static', '/usr/mips-linux-gnu'),
        'mips32le': ('qemu-mipsel-static', '/usr/mipsel-linux-gnu'),
    }
    def remote_session(label, executable, reference_control=False):
        emulator, sysroot = profiles[args.target]
        with tempfile.TemporaryDirectory(prefix='forge-attach-qemu-', dir='/tmp') as sockets:
            endpoint = str(Path(sockets) / 'gdb.socket')
            remote_env = {**env, 'FORGE_ASSOCIATION_REMOTE': endpoint, 'FORGE_ASSOCIATION_SYSROOT': sysroot}
            qemu_argv = [emulator, '-L', sysroot, '-g', endpoint, str(executable)]
            (work / (label + '-qemu.json')).write_text(json.dumps({'argv': qemu_argv,
                'toolSha256': digest(Path(shutil.which(emulator)))}, indent=4) + '\n')
            with (work / (label + '-qemu.stdout')).open('wb') as stdout, (work / (label + '-qemu.stderr')).open('wb') as stderr:
                child = subprocess.Popen(qemu_argv, stdout=stdout, stderr=stderr)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        require(child.poll() is None, 'QEMU exited before listening')
                        rows = [line.split() for line in Path('/proc/net/unix').read_bytes().splitlines()]
                        if any(len(row) >= 8 and row[3:5] == [b'00010000', b'0001'] and row[7] == os.fsencode(endpoint) for row in rows):
                            break
                        require(time.monotonic() < deadline, 'QEMU startup timed out')
                        time.sleep(0.05)
                    arguments = gdb
                    if reference_control:
                        arguments = ['gdb-multiarch', '-nx', '-nh', '-batch',
                            '-iex', 'set debuginfod enabled off', '-iex', 'set auto-load off',
                            '-ex', 'set sysroot ' + sysroot, '-ex', 'set auto-solib-add off',
                            '-ex', 'file "' + str(executable) + '"',
                            '-ex', 'target remote ' + endpoint, '-ex', 'detach']
                    observed = run(label, arguments, remote_env)
                    code = child.wait(timeout=10)
                    (work / (label + '-qemu.status')).write_text('exit=' + str(code) + '\n')
                    require(code == 0, 'QEMU target did not exit normally')
                finally:
                    if child.poll() is None:
                        child.kill()
                    child.wait(timeout=10)
            require(not (work / (label + '-qemu.stderr')).read_bytes(), 'QEMU emitted unexpected stderr')
        return observed

    if args.target == 'x86_64':
        observed = run('gdb-discovery', gdb, env)
    else:
        run('qemu-version', [profiles[args.target][0], '--version'])
        observed = remote_session('gdb-discovery', work / 'commit' / original.name)
    require(b'automatic-association=present PASS' in observed.stdout, 'GDB did not discover actual Forge DWARF')
    if observed.stderr:
        # A QEMU-supplied vDSO warning must also occur with the independent
        # compiler ELF. Retain both diagnostics; do not accept other warnings.
        pattern = rb'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index\n'
        require(args.target != 'x86_64' and re.fullmatch(pattern, observed.stderr) is not None,
                'unexpected GDB discovery diagnostic')
        control = remote_session('gdb-reference-warning', reference, True)
        require(re.fullmatch(pattern, control.stderr) is not None,
                'compiler reference did not corroborate QEMU vDSO warning')
    # Keep the committed generation (including receipt-bound metadata) intact.
    # Corrupt a separate negative-control copy and retain those rejected bytes.
    negative = work / 'crc-negative'
    negative.mkdir()
    shutil.copyfile(work / 'commit' / original.name, negative / original.name)
    shutil.copyfile(installed_sidecar, negative / installed_sidecar.name)
    with (negative / installed_sidecar.name).open('ab') as stream:
        stream.write(b'CRC mismatch control\n')
    env['FORGE_ASSOCIATION_MODE'] = 'absent'
    negative_gdb = [argument.replace(str(work / 'commit' / original.name), str(negative / original.name))
                    for argument in gdb]
    observed = run('gdb-crc-rejection', negative_gdb, env)
    require(b'automatic-association=absent PASS' in observed.stdout, 'GDB accepted mismatched CRC')
    require(b'CRC mismatch' in observed.stderr, 'negative control did not reach actual CRC checking')
    require(digest(installed_sidecar) == protected[str(sidecar)], 'committed sidecar changed')
    for path, expected in protected.items():
        require(digest(Path(path)) == expected, 'selected input changed: ' + path)
    for path in [original, sidecar, source]:
        require(digest(retained / path.name) == protected[str(path)], 'validated retained input changed')
    for path, expected in generations.items():
        require(file_state(Path(path)) == expected, 'completed generation metadata or bytes changed: ' + path)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'target': args.target, 'role': args.role,
        'preserved': protected, 'strict': strict_result,
        'host': 'production Linux ext4 host' if args.production_linux_host else 'limited Linux test host',
        'entryPoint': 'AttachmentHelper' if args.production_linux_host else 'test bridge',
        'runtime': True, 'debuglinkBasename': installed_sidecar.name, 'debuglinkPayloadHex': payload.hex(),
        'validator': 'production-live' if live_validator_arguments else 'captured-test-adapter',
        'scope': 'real ELF initial commit/rollback and GDB discovery/runtime/CRC rejection; public UI and refresh acceptance remain separate'}, indent=4) + '\n')
    print('attachment-elf-controller=PASS target=' + args.target + ' role=' + args.role)


if __name__ == '__main__':
    main()

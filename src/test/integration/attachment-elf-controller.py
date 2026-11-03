#!/usr/bin/env python3
"""Real-export controller test, not the product attachment entry point.

Fresh validators gate the test-only Java bridge. The Linux host adapter is
explicitly limited; this does not establish production metadata preservation.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jar', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--target', choices=['x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'], required=True)
    parser.add_argument('--role', choices=['exec', 'pie', 'exec.no-build-id'], required=True)
    parser.add_argument('--report-log', type=Path, required=True)
    parser.add_argument('--strict-validator', type=Path, required=True)
    parser.add_argument('--result-dir', type=Path, required=True)
    args = parser.parse_args()
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
               ['AttachmentProtocolSmoke', 'AttachmentReceiptStoreSmoke', 'AttachmentElfTransactionProbe']]
    oracle = ROOT / 'src/test/integration/automatic-association-gdb.py'
    protected = {str(p): digest(p) for p in [original, sidecar, source, reference, jar, gson, jna,
                                           args.report_log, args.strict_validator, Path(__file__), oracle, *sources]}
    commands = []

    def run(label, argv, env=None, timeout=60):
        command = list(map(str, argv))
        completed = subprocess.run(command, capture_output=True, timeout=timeout, env=env, cwd=work)
        (work / (label + '.stdout')).write_bytes(completed.stdout)
        (work / (label + '.stderr')).write_bytes(completed.stderr)
        commands.append({'label': label, 'argv': command, 'exit': completed.returncode})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        require(completed.returncode == 0, label + ' failed; inspect retained stdout/stderr')
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
    dependencies = os.pathsep.join(map(str, [jar, gson, jna]))
    run('compile', [os.environ.get('JAVAC', 'javac'), '--release', '21', '-cp', dependencies,
                    '-d', classes, *sources])
    java = os.environ.get('JAVA', 'java')
    version = run('java-version', [java, '-version'])
    require(b'version "21.' in version.stderr, 'this harness requires actual Java 21')
    runtime = os.pathsep.join([str(classes), dependencies])
    for action in ['commit', 'rollback']:
        directory = work / action
        directory.mkdir()
        outcome = run(action, [java, '--enable-native-access=ALL-UNNAMED', '-cp', runtime,
            'ghidradwarfforge.output.AttachmentElfTransactionProbe', report_path, original,
            sidecar, source, evidence, directory, action])
        require(b'attachment-elf-controller=PASS' in outcome.stdout, 'controller did not complete')
        require(digest(directory / 'original.backup') == protected[str(original)], 'backup bytes differ')
        if action == 'rollback':
            require(digest(directory / original.name) == protected[str(original)], 'rollback did not restore original')
        before = run(action + '-original-programs', ['readelf', '-lW', original])
        after = run(action + '-installed-programs', ['readelf', '-lW', directory / original.name])
        require(before.stdout == after.stdout, 'installed program headers or section mapping differs')

    generations = {str(path): file_state(path) for action in ['commit', 'rollback']
                   for path in (work / action).rglob('*') if path.is_file()}
    (work / 'generation-state.json').write_text(json.dumps(generations, indent=4) + '\n')

    symbols = run('reference-symbols', ['readelf', '-Ws', reference]).stdout.decode()
    addresses = {int(line.split()[1], 16) for line in symbols.splitlines()
                 if len(line.split()) >= 8 and line.split()[0].rstrip(':').isdigit() and line.split()[7] == 'recovered_add'}
    require(len(addresses) == 1, 'reference recovered_add must have one address')
    empty = work / 'empty-debug-root'
    empty.mkdir()
    installed_sidecar = work / 'commit' / sidecar.name
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
    shutil.copyfile(installed_sidecar, negative / sidecar.name)
    with (negative / sidecar.name).open('ab') as stream:
        stream.write(b'CRC mismatch control\n')
    env['FORGE_ASSOCIATION_MODE'] = 'absent'
    negative_gdb = [argument.replace(str(work / 'commit' / original.name), str(negative / original.name))
                    for argument in gdb]
    observed = run('gdb-crc-rejection', negative_gdb, env)
    require(b'automatic-association=absent PASS' in observed.stdout, 'GDB accepted mismatched CRC')
    require(digest(installed_sidecar) == protected[str(sidecar)], 'committed sidecar changed')
    for path, expected in protected.items():
        require(digest(Path(path)) == expected, 'selected input changed: ' + path)
    for path in [original, sidecar, source]:
        require(digest(retained / path.name) == protected[str(path)], 'validated retained input changed')
    for path, expected in generations.items():
        require(file_state(Path(path)) == expected, 'completed generation metadata or bytes changed: ' + path)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'target': args.target, 'role': args.role,
        'preserved': protected, 'strict': strict_result, 'host': 'limited Linux test host',
        'runtime': True, 'scope': 'real ELF initial commit/rollback and GDB discovery/runtime/CRC rejection; production host/validator integration and refresh remain required'}, indent=4) + '\n')
    print('attachment-elf-controller=PASS target=' + args.target + ' role=' + args.role)


if __name__ == '__main__':
    main()

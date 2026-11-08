#!/usr/bin/env python3
"""Install real shared/sectionless exports and prove fresh GDB discovery/runtime."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['fixtures', 'exports', 'configuration', 'ghidra', 'output', 'java']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--target', required=True, choices=['x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'])
    parser.add_argument('--role', required=True, choices=['shared', 'exec.no-sections'])
    parser.add_argument('--sectionless-discovery-limit', action='store_true',
        help='Prove the known consumer limitation with compiler controls, then test explicit loading separately.')
    args = parser.parse_args()
    assert not args.sectionless_discovery_limit or args.role == 'exec.no-sections'
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    fixture = args.fixtures.resolve() / args.target
    stem = 'libsemantic.so' if args.role == 'shared' else 'semantic.exec.no-sections'
    original = fixture / (stem + '.stripped')
    with original.open('rb') as stream:
        header = stream.read(64)
    assert header[:4] == b'\x7fELF' and header[4] in (1, 2) and header[5] in (1, 2)
    order = 'little' if header[5] == 1 else 'big'
    assert int.from_bytes(header[16:18], order) == (3 if args.role == 'shared' else 2)
    if args.role == 'exec.no-sections':
        offset, width, count = (40, 8, 60) if header[4] == 2 else (32, 4, 48)
        assert int.from_bytes(header[offset:offset + width], order) == 0
        assert header[count:count + 4] == bytes(4), 'section count/name index must both be zero'
    sidecar = fixture / (stem + '.ghidra-forge.dbg')
    source = Path(str(sidecar) + '.c')
    report_log = args.exports.resolve() / (args.target + '.' + args.role + '.log')
    module = args.ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge'
    tools = json.loads(args.configuration.read_text())['tools']
    tools['helper'] = str(module / 'os/linux_x86_64/forge-validator-supervisor')
    protected = {str(p): digest(p) for p in [original, sidecar, source, report_log, module / 'lib/GhidraDwarfForge.jar']}
    reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
        for line in report_log.read_text().splitlines() if 'GhidraDwarfForge report: ' in line]
    assert len(reports) == 1
    inputs = root / 'inputs'
    inputs.mkdir()
    files = {}
    for key, path in [('original', original), ('sidecar', sidecar), ('source', source)]:
        copied = inputs / path.name
        shutil.copy2(path, copied)
        files[key] = str(copied)
    report = inputs / 'report.json'
    report.write_text(json.dumps(reports[0], indent=4) + '\n')
    files['report'] = str(report)
    protected.update({p: digest(p) for p in files.values()})
    debug = root / 'debug'
    debug.mkdir()
    command_records, observations = [], []
    environment = dict(os.environ, JAVA_HOME=str(args.java.resolve().parent.parent),
        JAVA_TOOL_OPTIONS='-Djava.io.tmpdir=' + str(root) + ' -Djna.tmpdir=' + str(root), DEBUGINFOD_URLS='')

    def run(name, command, env=None):
        command = list(map(str, command))
        command_records.append({'name': name, 'command': command})
        (root / 'commands.json').write_text(json.dumps(command_records, indent=4) + '\n')
        result = subprocess.run(command, env=env or environment, capture_output=True, text=True, timeout=240)
        (root / (name + '.stdout')).write_text(result.stdout)
        (root / (name + '.stderr')).write_text(result.stderr)
        command_records[-1]['exit'] = result.returncode
        (root / 'commands.json').write_text(json.dumps(command_records, indent=4) + '\n')
        assert result.returncode == 0, (name, result.stdout[-3000:], result.stderr[-3000:])
        return result.stdout

    ids = set(re.findall(r'Build ID: ([0-9a-f]+)', run('original-notes', [tools['readelf'], '-n', original])))
    assert len(ids) == 1
    build_id = ids.pop()
    registration = debug / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')

    def symbol(file, name):
        lines = run(file.name + '-' + name, [tools['readelf'], '-Ws', file]).splitlines()
        values = {int(fields[1], 16) for line in lines
            if len(fields := line.split()) >= 8 and fields[0].rstrip(':').isdigit() and fields[7] == name}
        assert len(values) == 1
        return values.pop()

    shared = args.role == 'shared'
    chosen = 'recovered_add' if shared or args.target == 'x86_64' else 'main'
    reference = fixture / ('libsemantic.so.reference' if shared else 'semantic.exec.reference')
    protected[str(reference)] = digest(reference)
    link = symbol(reference, chosen)
    function = chosen if shared else 'FUN_%08x' % link
    driver = Path(files['original'])
    main_address = None
    if shared:
        driver = inputs / 'semantic.shared-driver.stripped'
        shutil.copy2(fixture / driver.name, driver)
        protected[str(driver)] = digest(driver)
        protected[str(fixture / driver.name)] = digest(fixture / driver.name)
        main_address = symbol(fixture / 'semantic.shared-driver.reference', 'main')
    sysroots = {'x86_64': '/', 'aarch64': '/usr/aarch64-linux-gnu',
        'arm32': os.environ.get('FORGE_ARM32_SYSROOT', '/usr/arm-linux-gnueabihf'),
        'mips32be': '/usr/mips-linux-gnu', 'mips32le': '/usr/mipsel-linux-gnu'}
    scripts = Path(__file__).resolve().parent

    compiler_controls = []
    if args.sectionless_discovery_limit:
        compiler_debug = root / 'compiler-debug'
        compiler_sidecar = compiler_debug / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')
        compiler_sidecar.parent.mkdir(parents=True)
        shutil.copy2(reference, compiler_sidecar)
        assert build_id in run('compiler-notes', [tools['readelf'], '-n', reference])
        for label, binary in [('sectioned', fixture / 'semantic.exec.stripped'), ('sectionless', original)]:
            command = ['gdb-multiarch', '-nx', '-q', '-batch', '-ex', 'set debuginfod enabled off',
                '-ex', 'set auto-solib-add off', '-ex', 'set debug-file-directory ' + str(compiler_debug),
                '-ex', 'file ' + json.dumps(str(binary)), '-ex',
                'python s=gdb.lookup_global_symbol("recovered_add"); print("COMPILER_DWARF_PRESENT",s is not None and s.symtab is not None)']
            output = run('compiler-' + label, command)
            present = 'COMPILER_DWARF_PRESENT True' in output
            assert present == (label == 'sectioned'), 'compiler discovery behavior differs from the documented limitation'
            compiler_controls.append({'layout': label, 'compilerDwarfPresent': present})

    def consumer(name, installed=None, explicit=False):
        config = {'target': args.target, 'role': args.role, 'function': function, 'linkAddress': link,
            'functionCandidates': [function] if shared else list(dict.fromkeys([function, chosen])),
            'mainAddress': main_address, 'original': files['original'], 'driver': str(driver),
            'debugRoot': str(debug), 'registration': str(registration), 'present': installed is not None,
            'source': installed['source'] if installed else None, 'sysroot': sysroots[args.target],
            'explicitFallback': explicit}
        path = root / (name + '.gdb.json')
        path.write_text(json.dumps(config, indent=4) + '\n')
        command = ['gdb-multiarch', '-nx', '-q', '-batch', '-x', str(scripts / 'build-id-layouts-gdb.py')]
        if args.target != 'x86_64':
            emulator = {'aarch64': 'qemu-aarch64-static', 'arm32': 'qemu-arm-static',
                'mips32be': 'qemu-mips-static', 'mips32le': 'qemu-mipsel-static'}[args.target]
            wrapper = '''set -euo pipefail
source "$1"
trap qemu_socket_cleanup EXIT
qemu_socket_start "$2" "$3" "$4" "$5"
export FORGE_BUILD_ID_REMOTE="$qemu_socket_path"
shift 5
"$@"
qemu_socket_wait
'''
            command = ['bash', '-c', wrapper, 'build-id-layout', str(scripts / 'qemu-socket.sh'),
                str(root / (name + '.qemu')), emulator, sysroots[args.target], str(driver), *command]
        hidden = []
        try:
            for selected in [sidecar, source, Path(files['sidecar']), Path(files['source'])]:
                moved = selected.with_name(selected.name + '.build-id-layout-hidden')
                assert not moved.exists()
                selected.rename(moved)
                hidden.append((selected, moved))
            text = run(name, command, dict(environment, FORGE_BUILD_ID_LAYOUT=str(path)))
            assert 'build-id-layout-gdb=PASS' in text
            diagnostics = (root / (name + '.stderr')).read_text()
            if diagnostics:
                assert args.target in ('aarch64', 'arm32') and re.fullmatch(
                    r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index\n',
                    diagnostics), diagnostics
                # The empty-root run has no Forge symbols; retain the same QEMU
                # system-DSO warning as the independent baseline diagnostic.
                assert (root / 'empty.stderr').read_text() == diagnostics
            observations.append({'name': name, 'present': installed is not None, 'oldExportsAbsent': True,
                'loading': 'explicit-fallback' if explicit else 'automatic', 'diagnostic': diagnostics})
        finally:
            for selected, moved in reversed(hidden):
                assert not selected.exists()
                moved.rename(selected)

    consumer('empty')
    results = []
    for action in ['install', 'remove']:
        request = {'schema': 'forge-build-id-request-v1', 'action': action, 'root': str(debug)}
        if action == 'install':
            request.update(files=files, tools=tools)
        else:
            request['buildId'] = build_id
        path = root / (action + '.json')
        path.write_text(json.dumps(request, indent=4) + '\n')
        stdout = run(action, [module / 'support/ghidra-dwarf-forge-build-id', '--ghidra-dir=' + str(args.ghidra.resolve()),
            '--java=' + str(args.java.resolve()), '--request=' + str(path), '--request-sha256=' + digest(path)])
        result = [json.loads(line) for line in stdout.splitlines() if line.startswith('{')][-1]
        assert result['outcome'] == ('INSTALLED' if action == 'install' else 'REMOVED')
        if action == 'install' and args.role == 'exec.no-sections':
            assert result['gdbAutomaticDiscovery'] == 'UNAVAILABLE_IN_TESTED_GDB_FOR_SECTIONLESS_ELF'
            assert 'symbol-file' in result['consumerSetup'] and 'compiler-generated' in result['consumerSetup']
        results.append(result)
        if action == 'install' and args.sectionless_discovery_limit:
            consumer('installed-auto-unavailable')
            consumer('installed-explicit-fallback', result, explicit=True)
        else:
            consumer(action + '-consumer', result if action == 'install' else None)
    assert protected == {p: digest(p) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_WITH_CONFIRMED_SECTIONLESS_GDB_LIMITATION'
        if args.sectionless_discovery_limit else 'PASS_BUILD_ID_LAYOUT', 'target': args.target,
        'role': args.role, 'results': results, 'consumers': observations, 'compilerControls': compiler_controls,
        'gdbVersion': run('gdb-version', ['gdb-multiarch', '--version']).splitlines()[0],
        'protectedInputs': protected}, indent=4) + '\n')
    print('build-id-layout=PASS target=' + args.target + ' role=' + args.role)


if __name__ == '__main__':
    main()

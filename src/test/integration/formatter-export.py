#!/usr/bin/env python3
"""Real saved-program export, generation determinism, validators and formatter consumers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import time

import lldb_consumer

TARGETS = {
    'x86_64': ('gcc', 'strip', None, None, []),
    'aarch64': ('aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-strip', 'qemu-aarch64-static', '/usr/aarch64-linux-gnu', []),
    'arm32': ('arm-linux-gnueabihf-gcc', 'arm-linux-gnueabihf-strip', 'qemu-arm-static', '/usr/arm-linux-gnueabihf',
        ['-march=armv7-a', '-marm', '-mfpu=vfpv3-d16']),
    'mips32be': ('mips-linux-gnu-gcc', 'mips-linux-gnu-strip', 'qemu-mips-static', '/usr/mips-linux-gnu', []),
    'mips32le': ('mipsel-linux-gnu-gcc', 'mipsel-linux-gnu-strip', 'qemu-mipsel-static', '/usr/mipsel-linux-gnu', []),
}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(command, log, timeout=300, env=None, input_text=None, expected_status=0):
    log.with_suffix(log.suffix + '.command.json').write_text(json.dumps(command, indent=4) + '\n')
    with log.open('w') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=timeout, env=env,
            input=input_text, text=True)
    text = log.read_text()
    assert result.returncode == expected_status, (command[0], result.returncode, text[-6000:])
    assert 'Traceback' not in text and 'Python Exception' not in text and 'Error occurred in Python' not in text, text[-6000:]
    return text


def gdb(original, sidecar, companion, root, emulator, sysroot, reference=None, mi=False,
        source_directory=None, loader=False):
    commands = ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
        'set auto-solib-add off', 'set disable-randomization off', 'file ' + json.dumps(str(original), ensure_ascii=False)]
    if sidecar is not None:
        commands.append('symbol-file ' + json.dumps(str(sidecar), ensure_ascii=False))
    if source_directory is not None:
        commands.append('directory ' + json.dumps(str(source_directory), ensure_ascii=False))
    if loader:
        commands.append('source ' + str(sidecar) + '.gdb.py')
    commands.append('break forge_formatter_marker')
    qemu = None
    qlog = None
    try:
        if emulator:
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            qlog = root.with_suffix('.qemu.log').open('w')
            qemu = subprocess.Popen([emulator, '-L', sysroot, '-g', str(port), str(original)], stdout=qlog, stderr=subprocess.STDOUT)
            time.sleep(0.2)
            assert qemu.poll() is None
            commands.extend(['set sysroot ' + sysroot, 'target remote 127.0.0.1:' + str(port), 'continue'])
        else:
            commands.append('run')
        if source_directory is not None:
            commands.append('list forge_formatter_marker')
        if companion is not None:
            # GDB's source command consumes the entire filename literally,
            # unlike file/symbol-file which parse quotes and backslash escapes.
            commands.append('source ' + str(companion))
            commands.append('source ' + str(companion))
        commands.extend(['print forge_flags', 'print forge_zero', 'print forge_combined', 'print forge_high', 'print forge_node',
            'print forge_signed8', 'print forge_unsigned16', 'print forge_unsigned64', 'print forge_signed64', 'print forge_envelope',
            'python n=gdb.parse_and_eval("forge_node"); assert int(n["a"]) == 5 and int(n["b"]) == 17 and int(n["value"]) == 42'])
        if companion is not None:
            commands.extend([
                'python assert len(list(gdb.default_visualizer(n).children())) == 5',
                'python assert "unknown=0x4" in gdb.default_visualizer(gdb.parse_and_eval("forge_flags")).to_string()'])
            if reference is not None and not mi:
                commands.append('python import sys; sys.path.insert(0, ' + repr(str(Path(__file__).resolve().parent)) +
                    '); import formatter_checks; formatter_checks.gdb_checks(' + repr(str(reference)) + ')')
            commands.extend([
                'forge-formatters unload',
                'python assert gdb.default_visualizer(gdb.parse_and_eval("forge_flags")) is None'])
        commands.append('continue')
        if mi:
            mi_commands = ['-enable-pretty-printing']
            for command in commands:
                if command == 'forge-formatters unload':
                    mi_commands.extend(['-var-create flags * forge_flags', '-var-create node * forge_node',
                        '-var-list-children --all-values node'])
                mi_commands.append('-interpreter-exec console ' + json.dumps(command, ensure_ascii=False))
            mi_commands.extend(['-gdb-exit', ''])
            input_text = '\n'.join(mi_commands)
            root.with_suffix('.mi-input').write_text(input_text)
            text = run(['gdb-multiarch', '-q', '-nx', '--interpreter=mi2'], root, input_text=input_text)
            assert '^error' not in text, text[-5000:]
            for field in ['a', 'b', 'value', 'next', 'unreadable']:
                assert 'exp="' + field + '"' in text, text[-5000:]
            assert 'numchild="5"' in text, text[-5000:]
        else:
            argv = ['gdb-multiarch', '-q', '-nx', '-batch']
            for command in commands:
                argv.extend(['-ex', command])
            text = run(argv, root)
        if qemu is not None:
            assert qemu.wait(timeout=5) == 0
        if source_directory is not None:
            assert 'return forge_node.value;' in text, 'relocated synthetic source was not listed'
        if companion is not None:
            for expected in ['unknown=0x4', 'a=5', 'b=17', 'value=42', 'unreadable=0x1', 'Forge formatters unloaded',
                    'raw: -127 / 0x81', 'raw: 32773 / 0x8005', 'raw: 13835058055282163717 / 0xc000000000000005',
                    'raw: -9223372036854775807 / 0x8000000000000001', 'unknown=0x8000000000000004',
                    'node=<5 children; expand to inspect>', 'tail=-9', 'nil=NULL', '4 more children']:
                assert expected in text, (expected, text[-5000:])
        return text
    finally:
        if qemu is not None and qemu.poll() is None:
            qemu.terminate()
            qemu.wait(timeout=5)
        if qlog is not None:
            qlog.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--role', choices=['exec', 'pie'], default='exec')
    parser.add_argument('--compression', choices=['none', 'zlib'], default='none')
    parser.add_argument('--companions', action='store_true', help='Combine formatters with the GDB loader and strict unwind evidence')
    parser.add_argument('--lldb')
    parser.add_argument('--dwarfdump', default=os.environ.get('DWARFDUMP', 'dwarfdump'))
    parser.add_argument('--sysroot', type=Path, help='Explicit cross-toolchain/QEMU sysroot when not installed system-wide')
    parser.add_argument('--source-lines', type=int, help='exercise formatters with a complete multi-file source bundle')
    parser.add_argument('--java', type=Path, help='explicit runtime through the production headless entry point')
    args = parser.parse_args()
    if args.source_lines is not None and not 1 <= args.source_lines <= 2147483647:
        parser.error('--source-lines must be in 1..2147483647')
    repo = Path(__file__).resolve().parents[3]
    root = args.work.resolve()
    root.mkdir(parents=True, exist_ok=False)
    project = root / 'project'
    project.mkdir()
    ghidra = args.ghidra.resolve()
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    headless = [str(ghidra / 'support/analyzeHeadless')]
    if args.java:
        java = args.java.resolve(strict=True)
        vmargs = subprocess.check_output([java, '-cp', ghidra / 'support/LaunchSupport.jar',
            'LaunchSupport', ghidra, '-vmargs'], text=True).splitlines()
        for name in ('java-home', 'java-tmp'):
            (root / name).mkdir()
        headless = list(map(str, [java, *vmargs, '-Duser.home=' + str(root / 'java-home'),
            '-Djava.io.tmpdir=' + str(root / 'java-tmp'), '-Xmx2G', '-XX:ParallelGCThreads=2',
            '-XX:CICompilerCount=2', '-Djava.awt.headless=true', '-showversion', '-cp',
            ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar', 'ghidra.Ghidra',
            'ghidra.app.util.headless.AnalyzeHeadless']))
    proof_paths = [Path(__file__).resolve(), Path(__file__).resolve().with_name('formatter_checks.py'),
        repo / 'src/test/fixtures/formatter-values.c',
        repo / 'src/test/integration/ghidra_scripts/ApplyFormatterFixture.java',
        repo / 'src/test/integration/ghidra_scripts/CancelDuringFormatters.java',
        module / 'lib/GhidraDwarfForge.jar', module / 'ghidra_scripts/GhidraDwarfForge.java',
        module / 'support/ghidra-dwarf-forge-headless']
    tested_sources = {str(path): digest(path) for path in proof_paths}
    compiler, strip, emulator, sysroot, extra = TARGETS[args.target]
    if args.sysroot is not None:
        assert emulator is not None and args.sysroot.is_dir(), 'sysroot override requires a cross target and existing directory'
        sysroot = str(args.sysroot.resolve())
    reference = root / 'compiler-reference'
    role = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    run([compiler, '-gdwarf-5', '-O0', *role, *extra, str(repo / 'src/test/fixtures/formatter-values.c'),
        '-o', str(reference)], root / 'compiler.log')
    original = root / 'original'
    shutil.copyfile(reference, original)
    original.chmod(0o755)
    run([strip, '--strip-all', str(original)], root / 'strip.log')
    original_hash = digest(original)
    names = ['forge_formatter_marker', 'forge_flags', 'forge_zero', 'forge_combined', 'forge_high', 'forge_node',
        'forge_signed8', 'forge_unsigned16', 'forge_unsigned64', 'forge_signed64', 'forge_envelope', 'forge_text',
        'forge_choice', 'forge_other_choice', 'forge_ambiguous', 'forge_other_ambiguous']
    symbols = {}
    for line in subprocess.check_output(['readelf', '-Ws', str(reference)], text=True).splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[-1] in names:
            symbols[fields[-1]] = fields[1]
    assert set(symbols) == set(names)
    symbol_map = root / 'compiler-symbols.json'
    symbol_map.write_text(json.dumps(symbols, indent=4) + '\n')
    selection = root / 'selection.json'
    env = dict(os.environ, LC_ALL='C.UTF-8')
    text = run([*headless, str(project), 'Formatters', '-import', str(original),
        '-analysisTimeoutPerFile', '120', '-scriptPath', str(repo / 'src/test/integration/ghidra_scripts'),
        '-postScript', 'ApplyFormatterFixture.java', str(selection), str(symbol_map), str(original)], root / 'prepare.log', env=env)
    assert 'formatter-fixture=PASS' in text and selection.is_file(), text[-5000:]
    selection_hash = digest(selection)
    sidecar = root / 'original.λ "quoted".dbg'
    source = sidecar.with_name(sidecar.name + '.c')
    companion = sidecar.with_name('forge_formatters_' + hashlib.sha256(sidecar.name.encode()).hexdigest() + '.py')
    enabled_outputs = [sidecar, source, companion]
    if args.companions:
        enabled_outputs.extend([Path(str(sidecar) + '.gdb.py'), Path(str(sidecar) + '.unwind.json')])
    wrapper = module / 'support/ghidra-dwarf-forge-headless'
    dependencies = []

    def source_dependencies():
        if args.source_lines is None:
            return []
        manifest_name, = [line.removeprefix(' * Manifest: ') for line in source.read_text().splitlines()
            if line.startswith(' * Manifest: ')]
        manifest_path = source.parent / manifest_name
        manifest = json.loads(manifest_path.read_text())
        assert manifest['inputSha256'] == original_hash
        assert digest(manifest_path) == manifest_name.removeprefix('forge-src-').removesuffix('.json')
        parts = [source.parent / item['name'] for item in manifest['parts']]
        assert len(parts) > 1
        for path, item in zip(parts, manifest['parts']):
            assert digest(path) == item['sha256'] and path.stat().st_size == item['bytes']
        return [manifest_path, *parts]

    def export(label, enabled):
        command = ['bash', str(wrapper), '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
            '--project-name=Formatters', '--program=original', '--input=' + str(original), '--output=' + str(sidecar),
            '--compress-debug-sections=' + args.compression]
        if args.java:
            command = [*headless, str(project), 'Formatters', '-process', 'original', '-readOnly', '-noanalysis',
                '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--input=' + str(original),
                '--output=' + str(sidecar), '--compress-debug-sections=' + args.compression]
        if args.source_lines is not None:
            command.append('--source-lines=' + str(args.source_lines))
        if enabled:
            command.append('--formatters=' + str(selection))
            if args.companions:
                command.extend(['--gdb-loader', '--synthesize-unwind=strict'])
        text = run(command, root / (label + '.log'), env=env)
        assert 'GhidraDwarfForge symbol export PASS' in text, text[-5000:]
        assert digest(original) == original_hash and digest(selection) == selection_hash
        current = source_dependencies()
        if not dependencies:
            dependencies.extend(current)
            enabled_outputs.extend(current)
        assert current == dependencies
        return [digest(p) for p in (enabled_outputs if enabled else [sidecar, source, *dependencies])]

    baseline = export('default-before', False)
    assert not companion.exists()
    enabled = export('enabled', True)
    assert export('repeat', True) == enabled, 'enabled artifacts are not deterministic'
    assert enabled[1] == baseline[1], 'formatters changed synthetic source'
    assert export('default-after', False) == baseline, 'disabled export changed after formatter use'
    assert export('restored-enabled', True) == enabled
    text = run([*headless, str(project), 'Formatters', '-process', 'original',
        '-readOnly', '-noanalysis', '-scriptPath', str(repo / 'src/test/integration/ghidra_scripts'),
        '-postScript', 'CancelDuringFormatters.java', str(original), str(sidecar), str(selection), args.compression,
        'all' if args.companions else 'formatters', *([] if args.source_lines is None else [str(args.source_lines)])],
        root / 'cancellation.log', env=env)
    assert 'formatter-cancellation-recovery=PASS' in text, text[-5000:]
    if args.companions:
        assert Path(str(sidecar) + '.gdb.py').is_file() and Path(str(sidecar) + '.unwind.json').is_file()
    for label, types in [('missing-key', [{'key': 'uid:does-not-exist', 'mode': 'flags'}]),
            ('wrong-kind', [dict(json.loads(selection.read_text())['types'][0], mode='structure')])]:
        invalid = root / (label + '.json')
        invalid.write_text(json.dumps({'schema': 1, 'types': types}))
        command = ['bash', str(wrapper), '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
            '--project-name=Formatters', '--program=original', '--input=' + str(original),
            '--output=' + str(sidecar), '--formatters=' + str(invalid)]
        text = run(command, root / (label + '.log'), env=env, expected_status=10)
        assert 'formatter selection requires an emitted' in text
        assert [digest(path) for path in enabled_outputs] == enabled
        assert digest(original) == original_hash and digest(selection) == selection_hash
        assert not list(root.glob('.*.staged')) and not list(root.glob('.forge-*'))
    for index, command in enumerate([['readelf', '-h', '-S', '-n', str(sidecar)]] + [
            ['readelf', '--debug-dump=' + dump, str(sidecar)] for dump in ['info', 'abbrev', 'aranges', 'decodedline']] + [
            ['llvm-dwarfdump', '--verify', str(sidecar)], ['python3', str(repo / 'src/test/integration/check-dwarfdump.py'),
                str(sidecar), str(root / 'strict.txt'), '--tool', args.dwarfdump, '--original', str(original)]]):
        text = run(command, root / ('validator-%d.log' % index))
        if command[0] == 'readelf':
            assert 'Warning:' not in text and 'Error:' not in text, text[-5000:]
    compiler_text = gdb(reference, None, None, root / 'compiler-gdb.log', emulator, sysroot)
    forge_text = gdb(original, sidecar, companion, root / 'forge-gdb.log', emulator, sysroot, reference,
        source_directory=root if args.source_lines else None, loader=args.companions)
    gdb(original, sidecar, companion, root / 'forge-gdb-mi.log', emulator, sysroot, mi=True,
        source_directory=root if args.source_lines else None, loader=args.companions)
    # Keep known QEMU DSO diagnostics separate and require compiler corroboration.
    import re
    def warnings(text):
        return [re.sub(r'0x[0-9a-f]+', '<address>', line) for line in text.splitlines() if line.startswith('warning:')]
    assert warnings(compiler_text) == warnings(forge_text), 'new debugger warning'
    allowed = {'warning: BFD: warning: system-supplied DSO at <address> has a corrupt string table index'} \
        if args.target in ('aarch64', 'arm32') else set()
    assert set(warnings(forge_text)) <= allowed, 'unexpected compiler-correlated warning'
    if args.lldb:
        assert args.target in ('x86_64', 'aarch64')
        text = lldb_consumer.run(original, sidecar, root / 'lldb', args.lldb, args.target,
            ['breakpoint set --name forge_formatter_marker'], [
                'command script import ' + shlex.quote(str(companion)),
                'command script import ' + shlex.quote(str(companion)),
                'frame variable forge_flags forge_zero forge_combined forge_high forge_node',
                'frame variable forge_signed8 forge_unsigned16 forge_unsigned64 forge_signed64 forge_envelope',
                'script v=lldb.target.FindFirstGlobalVariable("forge_node"); assert v.IsValid() and v.GetNumChildren() == 5',
                'script import sys; sys.path.insert(0, ' + repr(str(Path(__file__).resolve().parent)) +
                    '); import formatter_checks; formatter_checks.lldb_checks(lldb.debugger, ' + repr(str(reference)) + ')',
                'forge-formatters unload', 'continue'], {})
        for expected in ['unknown=0x4', 'a=5', 'b=17', 'value=42', 'Forge formatters unloaded',
                'raw: -127 / 0x81', 'raw: 32773 / 0x8005', 'raw: 13835058055282163717 / 0xc000000000000005',
                'raw: -9223372036854775807 / 0x8000000000000001', 'unknown=0x8000000000000004',
                'node=<5 children; expand to inspect>', 'tail=-9', 'nil=NULL', '4 more children']:
            assert expected in text, (expected, text[-5000:])
    assert tested_sources == {str(path): digest(path) for path in proof_paths}, 'test/exporter sources changed during validation'
    assert [digest(path) for path in enabled_outputs] == enabled
    assert digest(original) == original_hash and digest(selection) == selection_hash
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_BASIC_PRODUCTION_FORMATTERS',
        'target': args.target, 'role': args.role, 'compression': args.compression, 'originalSha256': original_hash,
        'selectionSha256': selection_hash, 'enabledSha256': enabled, 'defaultSha256': baseline,
        'lldb': bool(args.lldb), 'allCompanions': args.companions, 'testedSources': tested_sources,
        'sourceLines': args.source_lines,
        'portableArtifacts': {'role': args.role, 'sidecar': sidecar.name, 'companion': companion.name,
            'sha256': {path.name: digest(path) for path in [original, reference, selection, *enabled_outputs]}},
        'gdbVersion': subprocess.check_output(['gdb-multiarch', '--version'], text=True).splitlines()[0]}, indent=4) + '\n')
    print('formatter-export=PASS', args.target, args.role)


if __name__ == '__main__':
    main()

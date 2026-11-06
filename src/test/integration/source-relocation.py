#!/usr/bin/env python3
"""Validate source-only DWARF relocation with independent ELF packaging and debuggers."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import time
import lldb_consumer


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, log, environment=None):
    log.with_suffix('.command.json').write_text(json.dumps(list(map(str, argv)), indent=4) + '\n')
    result = subprocess.run(list(map(str, argv)), env=dict(os.environ, **(environment or {})),
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    log.write_text(result.stdout)
    assert result.returncode == 0, result.stdout[-5000:]
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--jar', required=True, type=Path)
    parser.add_argument('--target', required=True,
        choices=('x86_64', 'aarch64', 'arm32', 'mips32be', 'mips32le'))
    parser.add_argument('--java', default='java')
    parser.add_argument('--lldb')
    parser.add_argument('--perf')
    args = parser.parse_args()
    fixture, root, jar = args.fixture.resolve(), args.output.resolve(), args.jar.resolve()
    root.mkdir(parents=True, exist_ok=False)
    script_root = Path(__file__).resolve().parent
    repo = script_root.parents[2]
    original = fixture / 'floating.stripped'
    sidecar = fixture / 'artifacts/floating.dbg'
    source = Path(str(sidecar) + '.c')
    labels = fixture / 'labels.txt'
    reference = fixture / 'floating.reference'
    protected = {str(p): digest(p) for p in (original, sidecar, source, labels, reference, jar)}
    generation = root / 'managed source' / digest(sidecar)
    generation.mkdir(parents=True)
    retained_source = generation / source.name
    shutil.copy2(source, retained_source)
    java = Path(shutil.which(args.java)).resolve()
    classes = root / 'classes'
    classes.mkdir()
    command([java.with_name('javac'), '-Xlint:all', '-Werror', '-cp', jar, '-d', classes,
        repo / 'src/test/java/ghidradwarfforge/dwarf/SyntheticSourceRelocationSmoke.java'], root / 'compile.log')
    spec = importlib.util.spec_from_file_location('fixture_elf', script_root / 'elf-build-id.py')
    elf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(elf)
    before = sidecar.read_bytes()
    order, wide, sections = elf.sections(before)
    raw = root / 'sections'
    raw.mkdir()
    for name in ('info', 'abbrev', 'str', 'line'):
        section = sections['.debug_' + name]
        flags, = struct.unpack_from(order + ('Q' if wide else 'I'), before, section['header'] + 8)
        assert flags & 0x802 == 0, 'this initial oracle requires plain nonallocated sections'
        (raw / name).write_bytes(before[section['offset']:section['offset'] + section['size']])
    rewritten = root / 'rewritten'
    command([java, '-cp', str(jar) + os.pathsep + str(classes),
        'ghidradwarfforge.dwarf.SyntheticSourceRelocationSmoke', raw, rewritten,
        generation, 'little' if order == '<' else 'big'], root / 'relocation.log')
    assert (rewritten / 'file-name.txt').read_text() == source.name
    assert Path((rewritten / 'previous-directory.txt').read_text()) == source.parent
    # Independent fixture packager: append the changed plain sections and alter
    # only their section offset/size fields. This is not the production installer.
    after = bytearray(before)
    changed_headers = set()
    for name in ('info', 'str', 'line'):
        data = (rewritten / name).read_bytes()
        section = sections['.debug_' + name]
        location = section['header'] + (24 if wide else 16)
        struct.pack_into(order + ('QQ' if wide else 'II'), after, location, len(after), len(data))
        changed_headers.update(range(location, location + (16 if wide else 8)))
        after.extend(data)
    assert all(a == b or i in changed_headers for i, (a, b) in enumerate(zip(before, after)))
    build_id, = set(re.findall(r'Build ID: ([0-9a-f]+)',
        subprocess.check_output(['readelf', '-n', str(original)], text=True)))
    debug_root = root / 'debug root'
    installed = debug_root / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')
    installed.parent.mkdir(parents=True)
    installed.write_bytes(after)
    binary = root / 'original'
    shutil.copy2(original, binary)
    command(['readelf', '-hSWn', installed], root / 'elf.log')
    for kind in ('info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc'):
        command(['readelf', '--debug-dump=' + kind, installed], root / (kind + '.log'))
    command(['llvm-dwarfdump', '--verify', installed], root / 'llvm.log')
    command(['python3', script_root / 'check-dwarfdump.py', installed, root / 'strict.log',
        '--original', original], root / 'strict-command.log')
    assert b'\0' + str(generation).encode() + b'\0' in (rewritten / 'str').read_bytes()
    hidden = source.with_name(source.name + '.relocation-test-hidden')
    assert not hidden.exists()
    source.rename(hidden)
    emulator = None
    emulator_log = None
    try:
        environment = {'FORGE_FP_LABELS': str(labels), 'FORGE_FP_MODE': 'forge',
            'FORGE_FP_TARGET': args.target, 'FORGE_FP_BASELINE': '0', 'DEBUGINFOD_URLS': ''}
        options = ['set pagination off', 'set confirm off', 'set debuginfod enabled off',
            'set auto-solib-add off', 'set disable-randomization off',
            'set debug-file-directory ' + str(debug_root), 'file ' + json.dumps(str(binary))]
        if args.target != 'x86_64':
            profile = {'aarch64': ('aarch64', 'aarch64-linux-gnu'),
                'arm32': ('arm', 'arm-linux-gnueabihf'), 'mips32be': ('mips', 'mips-linux-gnu'),
                'mips32le': ('mipsel', 'mipsel-linux-gnu')}[args.target]
            with socket.socket() as reserved:
                reserved.bind(('127.0.0.1', 0))
                port = reserved.getsockname()[1]
            sysroot = os.environ.get('FORGE_ARM32_SYSROOT', '/usr/' + profile[1]) if args.target == 'arm32' else '/usr/' + profile[1]
            emulator_log = (root / 'qemu.log').open('w')
            emulation = ['qemu-' + profile[0] + '-static', '-L', sysroot,
                '-g', str(port), str(binary)]
            (root / 'qemu-command.json').write_text(json.dumps(emulation, indent=4) + '\n')
            emulator = subprocess.Popen(emulation, stdout=emulator_log, stderr=subprocess.STDOUT)
            time.sleep(0.2)
            assert emulator.poll() is None
            environment['FORGE_FP_REMOTE'] = '127.0.0.1:' + str(port)
            options.append('set sysroot ' + sysroot)
        else:
            environment['FORGE_FP_REMOTE'] = ''
        argv = ['gdb-multiarch', '-q', '-nx', '-batch']
        for option in options:
            argv += ['-ex', option]
        argv += ['-x', script_root / 'floating-registers-gdb.py']
        transcript = command(argv, root / 'gdb.log', environment)
        assert 'floating-registers-gdb=forge PASS' in transcript
        assert 'fp_float_first = first;' in transcript and 'fp_float_second = second;' in transcript
        if emulator is not None:
            assert emulator.wait(timeout=5) == 0
        if args.lldb:
            assert args.target in ('x86_64', 'aarch64')
            config = root / 'lldb-config.json'
            config.write_text(json.dumps({'mode': 'forge', 'target': args.target,
                'source': str(retained_source), 'observations': str(root / 'lldb/observations.json'),
                'labels': {n: int(v, 16) for n, v in (row.split() for row in labels.read_text().splitlines())}}, indent=4) + '\n')
            before_commands = ['source list -n fp_float'] + [
                'breakpoint set --name ' + name + ' --skip-prologue false --one-shot true'
                for name in ('fp_float', 'fp_double', 'fp_clobbered')]
            after_commands = ['script exec(open(' + repr(str(script_root / 'floating-registers-lldb-observe.py')) + ').read())']
            transcript = lldb_consumer.run(binary, None, root / 'lldb', args.lldb, args.target,
                before_commands, after_commands, {'FORGE_LLDB_FP_CONFIG': str(config)},
                qemu_cpu='cortex-a53' if args.target == 'aarch64' else None,
                setup=['settings set symbols.enable-external-lookup false',
                    'settings set target.debug-file-search-paths ' + json.dumps(str(debug_root))])
            assert 'FORGE_LLDB_FLOATING_PASS' in transcript
            assert 'fp_float_first = first;' in transcript and 'fp_float_second = second;' in transcript
        if args.perf:
            symfs = root / 'symfs'
            mirror = symfs / str(binary).lstrip('/')
            mirror.parent.mkdir(parents=True)
            shutil.copy2(binary, mirror)
            debug_copy = symfs / 'usr/lib/debug' / installed.relative_to(debug_root)
            debug_copy.parent.mkdir(parents=True)
            shutil.copy2(installed, debug_copy)
            transcript = command([args.perf, '--buildid-dir', root / 'perf-cache', 'probe',
                '--symfs', symfs, '-x', binary, '-L', 'fp_float'], root / 'perf.log', {'DEBUGINFOD_URLS': ''})
            assert str(retained_source) in transcript and 'fp_float_first = first;' in transcript
        assert not source.exists()
    finally:
        if emulator is not None and emulator.poll() is None:
            emulator.terminate()
            try:
                emulator.wait(timeout=5)
            except subprocess.TimeoutExpired:
                emulator.kill()
                emulator.wait()
        if emulator_log is not None:
            emulator_log.close()
        assert not source.exists()
        hidden.rename(source)
    assert protected == {p: digest(Path(p)) for p in protected}
    assert digest(binary) == protected[str(original)]
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_SOURCE_RELOCATION',
        'target': args.target, 'role': fixture.name, 'protectedSha256': protected,
        'installedSha256': digest(installed), 'sourceSha256': digest(retained_source),
        'sourceDirectory': str(generation), 'javaSource': str(jar),
        'gdb': True, 'lldb': bool(args.lldb), 'perf': bool(args.perf),
        'scope': 'Production pure-section relocator with independent test-only ELF packaging; '
            'original source absent during real automatic-lookup runtime checks; no installer transaction.'}, indent=4) + '\n')
    print('source-relocation=PASS ' + args.target + ' ' + fixture.name)


if __name__ == '__main__':
    main()

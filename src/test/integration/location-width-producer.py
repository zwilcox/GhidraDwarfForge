#!/usr/bin/env python3
"""Validate location address width and preserved output through the real native exporter."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from integration_coverage import Collection


TARGETS = {
    'x86_64': ('gcc', 'objcopy', 'nm', None, None, 2, 1, 62),
    'aarch64': ('aarch64-linux-gnu-gcc', 'aarch64-linux-gnu-objcopy', 'aarch64-linux-gnu-nm',
        'qemu-aarch64-static', '/usr/aarch64-linux-gnu', 2, 1, 183),
    'arm32': ('arm-linux-gnueabihf-gcc', 'arm-linux-gnueabihf-objcopy', 'arm-linux-gnueabihf-nm',
        'qemu-arm-static', '/usr/arm-linux-gnueabihf', 1, 1, 40),
    'mips32be': ('mips-linux-gnu-gcc', 'mips-linux-gnu-objcopy', 'mips-linux-gnu-nm',
        'qemu-mips-static', '/usr/mips-linux-gnu', 1, 2, 8),
    'mips32le': ('mipsel-linux-gnu-gcc', 'mipsel-linux-gnu-objcopy', 'mipsel-linux-gnu-nm',
        'qemu-mipsel-static', '/usr/mipsel-linux-gnu', 1, 1, 8),
}
FIXTURE = '''__attribute__((noinline)) int forge_location_probe(void) {
    static volatile int observed = 42;
    static volatile int *retained = &observed;
    ++observed;
    __asm__ volatile("nop");
    __asm__ volatile(".globl forge_location_split\\nforge_location_split:\\nnop");
    return *retained;
}
int main(void) { return forge_location_probe() != 43; }
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('jar', 'consumer', 'producer', 'ghidra', 'java-home', 'results'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--target', choices=TARGETS, required=True)
    parser.add_argument('--role', choices=('exec', 'pie'), default='exec')
    parser.add_argument('--mode', choices=('listed', 'stable', 'listed-indirect', 'stable-indirect'), default='listed')
    args = parser.parse_args()
    if args.role == 'pie' and args.target != 'x86_64':
        parser.error('PIE runtime relocation is currently validated only for x86_64 in this harness')
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[3]
    scripts = Path(__file__).resolve().parent
    harness = repo / 'src/test/java/ghidradwarfforge/nativeapi/LocationWidthProducerProbe.java'
    protected = {str(p.resolve()): digest(p) for p in (args.jar, args.consumer, args.producer,
        Path(__file__), harness, scripts / 'qemu-socket.sh', scripts / 'check-dwarfdump.py',
        scripts / 'integration_coverage.py')}
    commands = []

    def run(label, command):
        command = list(map(str, command))
        completed = subprocess.run(command, capture_output=True, text=True, timeout=90)
        (root / (label + '.stdout')).write_text(completed.stdout)
        (root / (label + '.stderr')).write_text(completed.stderr)
        commands.append({'label': label, 'command': command, 'exit': completed.returncode})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert completed.returncode == 0, (label, completed.stderr)
        if label in ('compile', 'javac', 'readelf'):
            assert not completed.stderr.strip(), (label, completed.stderr)
        return completed.stdout

    cc, objcopy, nm, emulator, sysroot, elf_class, data, machine = TARGETS[args.target]
    fixture = root / 'fixture.c'
    fixture.write_text(FIXTURE)
    reference, binary = root / 'reference', root / 'input'
    flags = ['-fPIE', '-pie'] if args.role == 'pie' else ['-fno-pie', '-no-pie']
    run('compile', [cc, '-O0', '-gdwarf-5', *flags, fixture, '-o', reference])
    header = reference.read_bytes()[:64]
    order = 'little' if data == 1 else 'big'
    assert header[:4] == b'\x7fELF' and header[4] == elf_class and header[5] == data
    elf_type = 3 if args.role == 'pie' else 2
    assert int.from_bytes(header[16:18], order) == elf_type
    assert int.from_bytes(header[18:20], order) == machine
    run('strip', [objcopy, '--strip-all', reference, binary])
    protected.update({str(p): digest(p) for p in (reference, binary)})
    symbols = {}
    for line in run('nm', [nm, '-S', '--defined-only', reference]).splitlines():
        parts = line.split()
        if len(parts) == 4:
            symbols[parts[3]] = (int(parts[0], 16), int(parts[1], 16))
        elif len(parts) == 3 and parts[2] == 'forge_location_split':
            symbols[parts[2]] = (int(parts[0], 16), 0)
    address, size = symbols['forge_location_probe']
    split = symbols['forge_location_split'][0]
    observed, = [value for name, value in symbols.items() if name.startswith('observed.')]
    retained, = [value for name, value in symbols.items() if name.startswith('retained.')]
    assert observed[1] == 4 and address < split < address + size
    assert retained[1] == (4 if elf_class == 1 else 8)
    location = retained[0] if args.mode.endswith('-indirect') else observed[0]
    classes = root / 'classes'
    classes.mkdir()
    jna, = args.ghidra.glob('Ghidra/Framework/Pty/lib/jna-[0-9]*.jar')
    gson, = args.ghidra.glob('Ghidra/Framework/Generic/lib/gson-[0-9]*.jar')
    classpath = os.pathsep.join(map(str, (classes, args.jar.resolve(), jna.resolve(), gson.resolve())))
    run('javac', [args.java_home / 'bin/javac', '--release', '21', '-cp', classpath, '-d', classes, harness])
    output = root / 'output'
    output.mkdir()
    sidecar = output / 'input.dbg'
    coverage = Collection('location-width-producer', args.jar.resolve(), 'native-java',
        test_classes=('ghidradwarfforge.nativeapi.LocationWidthProducerProbe',))
    command = [args.java_home / 'bin/java', '--enable-native-access=ALL-UNNAMED',
        '-cp', classpath, 'ghidradwarfforge.nativeapi.LocationWidthProducerProbe',
        args.consumer.resolve(), args.producer.resolve(), binary, sidecar,
        hex(address), hex(size), hex(location), hex(split), args.mode]
    with coverage.session(command, 'producer') as measured:
        text = run('producer', measured)
    rejected = 4 if elf_class == 1 else 0
    assert f'location-width-producer=PASS rejected={rejected} deterministic=true preserved=true' in text
    info = run('readelf', ['readelf', '-h', '-S', '--debug-dump=info', '--debug-dump=abbrev',
        '--debug-dump=aranges', '--debug-dump=decodedline', '--debug-dump=loc', sidecar])
    listed = args.mode.startswith('listed')
    assert ('.debug_loclists' in info) == listed and 'DW_AT_location' in info
    assert info.count('DW_OP_addr: ' + format(location, 'x')) == (2 if listed else 1)
    assert info.count('DW_OP_deref') == ((2 if listed else 1) if args.mode.endswith('-indirect') else 0)
    run('llvm', ['llvm-dwarfdump', '--verify', sidecar])
    run('strict', [sys.executable, '-B', scripts / 'check-dwarfdump.py', sidecar,
        root / 'strict.log', '--original', binary, '--tool', args.dwarfdump])
    for label, debug in (('compiler', reference), ('exported', sidecar)):
        script = root / (label + '.gdb')
        runtime_check = ('python\n'
            f'base = int(gdb.parse_and_eval("(void *)forge_location_probe")) - {address}\n'
            f'assert (base != 0) == {args.role == "pie"!r}, "unexpected load bias"\n'
            f'assert int(gdb.parse_and_eval("&observed")) == base + {observed[0]}\n'
            'assert int(gdb.parse_and_eval("observed")) == expected_value\n'
            'assert int(gdb.parse_and_eval("sizeof(observed)")) == 4\n'
            'end\n')
        script.write_text('set pagination off\nset confirm off\nset debuginfod enabled off\n'
            'set auto-solib-add off\nset disable-randomization off\nfile ' + json.dumps(str(binary))
            + '\nsymbol-file ' + json.dumps(str(debug)) + '\n'
            + 'python exits = []; gdb.events.exited.connect(lambda e: exits.append(getattr(e,"exit_code",None)))\n'
            + f'break *forge_location_probe\nbreak *((char *)forge_location_probe + {split - address})\n'
            + ('target remote $FORGE_SOCKET\ncontinue\n' if emulator else 'run\n')
            + 'python expected_value = 42\n'
            + f'python assert int(gdb.parse_and_eval("$pc")) == int(gdb.parse_and_eval("(void *)forge_location_probe"))\n'
            + runtime_check + 'continue\n'
            + 'python expected_value = 43\n'
            + f'python assert int(gdb.parse_and_eval("$pc")) == int(gdb.parse_and_eval("(void *)forge_location_probe")) + {split - address}\n'
            + runtime_check
            + 'continue\npython assert exits == [0]\necho LOCATION_WIDTH_GDB_PASS\\n\n')
        if emulator:
            command = ['bash', '-c', '''set -euo pipefail
source "$1"
trap qemu_socket_cleanup EXIT
qemu_socket_start "$2" "$3" "$4" "$5"
sed "s|[$]FORGE_SOCKET|$qemu_socket_path|g" "$6" > "$7"
timeout 45s gdb-multiarch -nx -q -batch -ex "set sysroot $4" -x "$7"
qemu_socket_wait
''', 'location-width', scripts / 'qemu-socket.sh', root / (label + '-qemu'), emulator,
                sysroot, binary, script, root / (label + '-remote.gdb')]
        else:
            command = ['gdb-multiarch', '-nx', '-q', '-batch', '-x', script]
        assert 'LOCATION_WIDTH_GDB_PASS' in run(label + '-gdb', command)
    assert all(digest(path) == value for path, value in protected.items())
    result = {'status': 'PASS_LOCATION_WIDTH_PRODUCER', 'target': args.target, 'mode': args.mode,
        'role': args.role, 'elfType': elf_type, 'runtimeAddressChecksPerDebugger': 2,
        'rejectedOverflowExports': rejected, 'validators': ['readelf', 'llvm', 'strict'],
        'compilerGdb': 'PASS', 'exportedGdb': 'PASS', 'deterministic': True,
        'inputPreserved': True, 'sidecarSha256': digest(sidecar), 'protectedSha256': protected,
        'productionJarSha256': digest(args.jar),
        'nativeSha256': {'consumer': digest(args.consumer), 'producer': digest(args.producer)},
        'harnessSha256': {str(p.relative_to(repo)): digest(p) for p in (Path(__file__).resolve(), harness,
            scripts / 'qemu-socket.sh', scripts / 'check-dwarfdump.py', scripts / 'integration_coverage.py')},
        'scope': 'Explicit compiler fixture model and actual native serializer; not a Ghidra extraction claim'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    coverage.finish(root / 'result.json')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()

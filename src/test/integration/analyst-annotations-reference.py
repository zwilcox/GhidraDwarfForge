#!/usr/bin/env python3
"""Build and validate compiler fixtures before applying Ghidra annotations.

This preparation harness does not export Forge DWARF or establish completion of
issues 116/114. Results retain commands, compiler DWARF and real debugger values.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import subprocess
import tempfile

PREFIXES = {
    'x86_64': '',
    'aarch64': 'aarch64-linux-gnu-',
    'arm32': 'arm-linux-gnueabihf-',
    'mips32be': 'mips-linux-gnu-',
    'mips32le': 'mipsel-linux-gnu-',
}


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=PREFIXES)
    parser.add_argument('--role', choices=['exec', 'pie'], default='exec')
    parser.add_argument('--results', type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[3]
    results = args.results or repository / 'build/test-results/analyst-annotations-reference'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '-', dir=results)).resolve()
    print('analyst-annotations-reference-results=' + str(case), flush=True)
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.stdout')).open('w') as stdout, (case / (label + '.stderr')).open('w') as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=180)
        (case / (label + '.status.json')).write_text(json.dumps({'returncode': result.returncode}) + '\n')
        if result.returncode:
            raise RuntimeError(label + ' failed; see ' + str(case))

    source = repository / 'src/test/fixtures/analyst-annotations.c'
    helpers = [Path(__file__), *Path(__file__).parent.glob('analyst-annotations-reference-gdb.*'),
        Path(__file__).with_name('qemu-socket.sh')]
    protected = {str(path): digest(path) for path in [source, *helpers]}
    prefix = PREFIXES[args.target]
    flags = ['-fno-pie', '-no-pie'] if args.role == 'exec' else ['-fPIE', '-pie']
    if args.target == 'arm32':
        flags += ['-marm', '-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=hard']
    reference, stripped = case / 'reference', case / 'stripped'
    run('compiler-version', [prefix + 'gcc', '--version'])
    run('compile', [prefix + 'gcc', '-O0', '-g', '-gdwarf-5', '-Wall', '-Wextra', '-Werror',
        '-fno-stack-protector', '-fno-omit-frame-pointer', *flags, source, '-o', reference])
    assert not (case / 'compile.stderr').read_text().strip()
    repeated = case / 'reference.repeat'
    run('compile-repeat', [prefix + 'gcc', '-O0', '-g', '-gdwarf-5', '-Wall', '-Wextra', '-Werror',
        '-fno-stack-protector', '-fno-omit-frame-pointer', *flags, source, '-o', repeated])
    assert digest(reference) == digest(repeated), 'compiler fixture is not deterministic'
    expected = {'x86_64': (2, 1, 62), 'aarch64': (2, 1, 183), 'arm32': (1, 1, 40),
        'mips32be': (1, 2, 8), 'mips32le': (1, 1, 8)}[args.target]
    header = reference.read_bytes()[:64]
    assert header[:4] == b'\x7fELF' and tuple(header[4:6]) == expected[:2]
    elf_type, machine = struct.unpack_from(('<' if header[5] == 1 else '>') + 'HH', header, 16)
    assert machine == expected[2] and elf_type == (2 if args.role == 'exec' else 3)
    run('strip', [prefix + 'objcopy', '--strip-all', reference, stripped])
    protected.update({str(path): digest(path) for path in (reference, stripped)})
    run('symbols', [prefix + 'nm', '-S', reference])
    run('disassembly', [prefix + 'objdump', '-d', reference])
    run('elf', ['readelf', '-hSWn', reference])
    run('programs', ['readelf', '-lW', reference])
    run('info', ['readelf', '--debug-dump=info', reference])
    run('line', ['readelf', '--debug-dump=decodedline', reference])
    run('abbrev', ['readelf', '--debug-dump=abbrev', reference])
    run('aranges', ['readelf', '--debug-dump=aranges', reference])
    run('llvm', ['llvm-dwarfdump', '--verify', reference])
    for label in ('elf', 'programs', 'info', 'line', 'abbrev', 'aranges', 'llvm'):
        assert not (case / (label + '.stderr')).read_text().strip(), label
    run('strict', ['python3', Path(__file__).with_name('check-dwarfdump.py'),
        reference, case / 'dwarfdump.txt', '--original', stripped])
    labels = {}
    wanted = {'annotation_probe', 'annotation_failure', 'annotation_data', 'ANNOTATION_COLLISION',
        'annotation_literal_19', 'annotation_literal_23', 'annotation_live',
        'annotation_gap_begin', 'annotation_gap_end'}
    for line in (case / 'symbols.stdout').read_text().splitlines():
        fields = line.split()
        if fields[-1] in wanted:
            assert fields[-1] not in labels
            labels[fields[-1]] = {'address': int(fields[0], 16)}
            if len(fields) == 4:
                labels[fields[-1]]['bytes'] = int(fields[1], 16)
    assert labels.keys() == wanted
    sequence = ['annotation_probe', 'annotation_literal_19', 'annotation_literal_23',
        'annotation_live', 'annotation_gap_begin', 'annotation_gap_end']
    assert all(labels[left]['address'] < labels[right]['address'] for left, right in zip(sequence, sequence[1:]))
    assert labels['annotation_gap_end']['address'] < labels['annotation_probe']['address'] + labels['annotation_probe']['bytes']
    loads = [int(line.split()[2], 16) for line in (case / 'programs.stdout').read_text().splitlines()
        if line.split() and line.split()[0] == 'LOAD']
    assert loads, 'fixture needs load segments'
    labels['_imageBase'] = {'address': min(loads)}
    (case / 'labels.json').write_text(json.dumps(labels, indent=4, sort_keys=True) + '\n')
    run('gdb', ['bash', Path(__file__).with_name('analyst-annotations-reference-gdb.sh'), case, args.target])
    assert 'analyst-annotations-compiler=PASS values=14' in (case / 'gdb.stdout').read_text()
    assert protected == {path: digest(Path(path)) for path in protected}
    receipt = {'status': 'PASS_COMPILER_REFERENCE', 'target': args.target, 'role': args.role,
        'protectedSha256': protected, 'labels': labels,
        'strictFrameReference': 'The stripped copy independently retains the exact compiler frame sections; only byte-matched frame diagnostics may be corroborated, not arbitrary compiler DWARF errors.',
        'observations': json.loads((case / 'compiler-observations.json').read_text()),
        'limits': 'Compiler reference only. Ghidra annotation curation, actual Forge emission, production GUI/headless integration remain required. Compiler strict validation is separate from emitted Forge artifact validation.'}
    (case / 'result.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print('analyst-annotations-reference=PASS ' + args.target + ' ' + args.role)


if __name__ == '__main__':
    main()

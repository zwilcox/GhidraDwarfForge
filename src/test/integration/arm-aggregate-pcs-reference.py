#!/usr/bin/env python3
"""Establish compiler/runtime aggregate PCS references before exporter changes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--order', choices=('little', 'big'), required=True)
    parser.add_argument('--pcs', choices=('softfp', 'hard'), required=True)
    args = parser.parse_args()
    args.gdb = args.gdb.resolve(strict=True)
    args.gdb_data = args.gdb_data.resolve(strict=True)
    args.qemu = args.qemu.resolve(strict=True)
    output = repository / 'build/test-results/arm-aggregate-pcs-reference'
    output.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.order + '.' + args.pcs + '.', dir=output))
    print(case, flush=True)
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    objcopy = os.environ.get('ARM32_OBJCOPY', 'arm-linux-gnueabihf-objcopy')
    objdump = os.environ.get('ARM32_OBJDUMP', 'arm-linux-gnueabihf-objdump')
    reference = load('aggregate_pcs_reference', source / 'arm-pcs-call-reference.py')
    protected = [Path(__file__), source / 'arm-aggregate-pcs-gdb.py',
        source / 'arm_aggregate_pcs_oracle.py',
        source / 'arm-pcs-profile-runtime.sh', source / 'qemu-socket.sh',
        source / 'arm-pcs-call-reference.py', source / 'check-dwarfdump.py',
        repository / 'src/test/fixtures/arm-aggregate-pcs.c',
        repository / 'src/test/fixtures/arm-pcs-start.S', args.gdb, args.qemu]
    protected += [Path(shutil.which(tool)).resolve(strict=True) for tool in (compiler, objcopy, objdump)]
    protected += [p for p in args.gdb_data.rglob('*') if p.is_file()]
    before = {str(p): digest(p) for p in protected}
    commands = []

    def write(name, value):
        (case / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'command': command})
        write('commands.json', commands)
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.err')).open('wb') as err:
            result = subprocess.run(command, stdout=log, stderr=err, timeout=180)
        assert result.returncode == 0, (case, label, result.returncode)
        assert not (case / (label + '.err')).read_bytes(), (case, label, 'unexpected stderr')

    write('profile.json', {'order': args.order, 'pcs': args.pcs})
    run('compiler-version', [compiler, '--version'])
    run('gdb-version', [args.gdb, '--data-directory=' + str(args.gdb_data), '--version'])
    run('qemu-version', [args.qemu, '--version'])
    compile_command = [compiler, '-marm', '-march=armv7-a', '-mfpu=vfpv3-d16',
        '-mfloat-abi=' + args.pcs, '-O0', '-g3', '-gdwarf-5', '-fno-omit-frame-pointer',
        '-nostdlib', '-nostartfiles', '-static', '-fno-pie', '-no-pie',
        '-Wl,--build-id=none', '-Wl,-e,_start',
        *(['-mbig-endian', '-Wl,--be8'] if args.order == 'big' else [])]
    # A fixed assembly object name avoids GCC's random temporary STT_FILE name.
    run('startup', [*compile_command, '-c', repository / 'src/test/fixtures/arm-pcs-start.S',
        '-o', case / 'start.o'])
    compile_command += [case / 'start.o', repository / 'src/test/fixtures/arm-aggregate-pcs.c']
    run('compile', [*compile_command, '-o', case / 'calls.reference'])
    run('repeat', [*compile_command, '-o', case / 'calls.repeat'])
    assert (case / 'calls.reference').read_bytes() == (case / 'calls.repeat').read_bytes()
    run('strip', [objcopy, '--strip-all', case / 'calls.reference', case / 'calls.input'])
    for leaf in ('calls.reference', 'calls.input'):
        before[str(case / leaf)] = digest(case / leaf)
    write('protected-before.json', before)
    run('elf', ['readelf', '-hASW', case / 'calls.reference'])
    run('info', ['readelf', '--debug-dump=info', case / 'calls.reference'])
    run('locations', ['readelf', '--debug-dump=loc', case / 'calls.reference'])
    run('disassembly', [objdump, '-drw', case / 'calls.reference'])
    run('llvm', ['llvm-dwarfdump', '--verify', case / 'calls.reference'])
    assert 'No errors.' in (case / 'llvm.log').read_text()
    run('strict', ['python3', source / 'check-dwarfdump.py', case / 'calls.reference', case / 'strict-report.log'])
    run('runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'compiler', args.qemu,
        args.gdb, args.gdb_data, source / 'arm-aggregate-pcs-gdb.py'])
    observed = json.loads((case / 'compiler-gdb.json').read_text())
    assert observed['status'] == 'PASS_COMPILER_REFERENCE'
    assert len(observed['natural']) == 12 and len(observed['injected']) == 18
    assert sum('return' in row for row in observed['natural']) == 9
    warnings = (case / 'compiler.stderr').read_text().splitlines()
    for line in warnings:
        if line == 'Failed to read a valid object file image from memory.':
            reference.corroborate_unmapped_vdso_sections(observed)
        else:
            assert re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', line), warnings
            reference.corroborate_unmapped_vdso_sections(observed)
    assert len(warnings) <= 1, warnings
    assert (case / 'compiler.qemu.status').read_text() == 'exit=0\n'
    assert not (case / 'compiler.qemu.stderr').read_bytes()
    assert before == {path: digest(Path(path)) for path in before}
    write('result.json', {'status': 'PASS_COMPILER_REFERENCE', 'order': args.order, 'pcs': args.pcs,
        'naturalCalls': 12, 'rawEntryTransfers': 12, 'typedReturns': 9, 'injectedCalls': 18,
        'repeatIdentical': True, 'protectedFilesUnchanged': True,
        'scope': 'Independent compiler/consumer reference only; no Forge acceptance'})
    print('PASS_COMPILER_REFERENCE', flush=True)


if __name__ == '__main__':
    main()

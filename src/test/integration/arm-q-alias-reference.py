#!/usr/bin/env python3
"""Differential compiler-only QEMU D/Q alias controls; no exporter support claim."""
import argparse
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
spec = importlib.util.spec_from_file_location('alias_reference', source / 'arm-pcs-call-reference.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    parser.add_argument('--d-only-qemu', type=Path, required=True, help='D-write-only corrected build directory')
    parser.add_argument('--alias-qemu', type=Path, required=True, help='D/Q corrected build directory')
    args = parser.parse_args()
    root = repository / 'build/test-results/arm-q-alias-reference'
    root.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix='run.', dir=root))
    print(output, flush=True)
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    protected = [Path(__file__), source / 'arm-q-alias-reference-gdb.py', source / 'arm-pcs-profile-runtime.sh',
        source / 'arm-pcs-call-reference.py', source / 'qemu-socket.sh',
        repository / 'src/test/fixtures/arm-pcs-profile.c', repository / 'src/test/fixtures/arm-pcs-start.S',
        args.gdb.resolve(strict=True), Path(shutil.which(compiler)).resolve()]
    protected += [p for p in args.gdb_data.rglob('*') if p.is_file()]
    protected += [base / leaf for base in (args.d_only_qemu, args.alias_qemu) for leaf in ('qemu-arm', 'qemu-armeb')]
    before = {str(p): reference.digest(p) for p in protected}
    commands = []

    def run(label, command, case):
        command = list(map(str, command))
        commands.append({'label': label, 'case': str(case), 'command': command})
        (output / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.err')).open('wb') as err:
            process = subprocess.run(command, stdout=log, stderr=err, timeout=120)
        assert process.returncode == 0 and not (case / (label + '.err')).read_bytes(), (case, label)

    results = []
    for order in ('little', 'big'):
        for fixed, directory in [(False, args.d_only_qemu), (True, args.alias_qemu)]:
            case = output / (order + ('.fixed' if fixed else '.d-only'))
            case.mkdir()
            (case / 'profile.json').write_text(json.dumps({'order': order, 'pcs': 'hard'}) + '\n')
            run('compile', [compiler, '-marm', '-march=armv7-a', '-mfpu=vfpv3-d16', '-mfloat-abi=hard',
                '-O0', '-g3', '-gdwarf-5', '-nostdlib', '-nostartfiles', '-static', '-fno-pie', '-no-pie',
                '-Wl,--build-id=none', '-Wl,-e,_start', *(['-mbig-endian', '-Wl,--be8'] if order == 'big' else []),
                repository / 'src/test/fixtures/arm-pcs-start.S', repository / 'src/test/fixtures/arm-pcs-profile.c',
                '-o', case / 'calls.reference'], case)
            shutil.copy2(case / 'calls.reference', case / 'calls.input')
            before.update({str(p): reference.digest(p) for p in (case / 'calls.reference', case / 'calls.input')})
            run('runtime', ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'compiler',
                directory / ('qemu-armeb' if order == 'big' else 'qemu-arm'), args.gdb, args.gdb_data,
                source / 'arm-q-alias-reference-gdb.py'], case)
            observed = json.loads((case / 'alias-observations.json').read_text())
            assert observed['status'] == 'OBSERVED' and observed['exitCode'] == 0
            assert len(observed['readAliases']) == len(observed['writeAliases']) == 16
            for row in observed['readAliases']:
                assert (row['expected'] == row['actual']) == fixed, (order, fixed, row)
            for row in observed['writeAliases']:
                assert (row['expected'] == row['actual']) == fixed, (order, fixed, row)
            stderr = (case / 'compiler.stderr').read_text()
            assert stderr.startswith('Failed to read a valid object file image from memory.\n')
            reference.corroborate_unmapped_vdso_sections(observed)
            assert not re.search(r'(?im)^(?:warning:|error|Python Exception)', stderr)
            packets = re.findall(r'Sending packet: \$P([0-9a-f]+)=([0-9a-f]+)#', stderr)
            quad_writes = [p for p in packets if len(p[1]) == 32]
            assert len(quad_writes) == 32 and len({p[0] for p in quad_writes}) == 16, quad_writes
            assert (case / 'compiler.qemu.status').read_text() == 'exit=0\n'
            assert not (case / 'compiler.qemu.stderr').read_bytes()
            results.append({'case': str(case), 'fixed': fixed, 'observed': observed, 'quadPackets': quad_writes})
    after = {path: reference.digest(Path(path)) for path in before}
    assert before == after
    (output / 'result.json').write_text(json.dumps({'status': 'PASS_DIFFERENTIAL_REFERENCE',
        'scope': 'all 16 D/Q alias pairs in LE/BE8; not exporter acceptance', 'cases': results,
        'protectedBefore': before, 'protectedAfter': after}, indent=4) + '\n')
    print('arm-q-alias-reference=PASS ' + str(output))


if __name__ == '__main__':
    main()

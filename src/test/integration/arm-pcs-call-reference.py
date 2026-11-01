#!/usr/bin/env python3
"""Reproduce base/VFP compiler call references and diagnosed tool limitations.

PASS_REFERENCE_LIMITATIONS is not exporter or architecture acceptance. This
oracle deliberately requires the current wrong-consumer controls; a fixed tool
needs a separately reviewed positive profile, not a silently relaxed assertion.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

repository = Path(__file__).resolve().parents[3]
source = repository / 'src/test/integration'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gdb', type=Path, required=True)
    parser.add_argument('--gdb-data', type=Path, required=True)
    args = parser.parse_args()
    gdb = args.gdb.resolve(strict=True)
    data = args.gdb_data.resolve(strict=True)
    output = repository / 'build/test-results/arm-pcs-call-reference'
    output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='run.', dir=output))
    print(root, flush=True)
    compiler = os.environ.get('ARM32_CC', 'arm-linux-gnueabihf-gcc')
    protected = [Path(__file__), source / 'arm-pcs-call-reference-gdb.py',
        source / 'arm-pcs-call-reference-runtime.sh', source / 'qemu-socket.sh',
        source / 'check-dwarfdump.py', gdb,
        repository / 'src/test/fixtures/arm-pcs-start.S',
        repository / 'src/test/fixtures/arm-pcs-call-reference.c']
    protected += [Path(shutil.which(tool)).resolve() for tool in
        (compiler, 'qemu-arm-static', 'qemu-armeb-static')]
    protected += [p for p in data.rglob('*') if p.is_file()]
    before = {str(p): digest(p) for p in protected}
    commands = []

    def run(case, label, command):
        command = list(map(str, command))
        commands.append({'name': label, 'directory': str(case), 'command': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('wb') as log, (case / (label + '.stderr')).open('wb') as err:
            result = subprocess.run(command, stdout=log, stderr=err, timeout=120)
        assert result.returncode == 0, (case, label, result.returncode)
        assert not (case / (label + '.stderr')).read_bytes(), (case, label)

    run(root, 'gdb-version', [gdb, '--data-directory=' + str(data), '--version'])
    assert '17.1' in (root / 'gdb-version.log').read_text()
    observations = []
    for order, emulator in [('little', 'qemu-arm-static'), ('big', 'qemu-armeb-static')]:
        case = root / order
        case.mkdir()
        run(case, 'qemu-version', [emulator, '--version'])
        assert '8.2.2' in (case / 'qemu-version.log').read_text()
        run(case, 'compile', [compiler, '-marm', '-march=armv7-a', '-mfpu=vfpv3-d16',
            '-mfloat-abi=hard', '-O0', '-g3', '-gdwarf-5', '-fno-omit-frame-pointer',
            '-nostdlib', '-nostartfiles', '-static', '-fno-pie', '-no-pie',
            '-Wl,--build-id=none', '-Wl,-e,_start',
            *(['-mbig-endian', '-Wl,--be8'] if order == 'big' else []),
            repository / 'src/test/fixtures/arm-pcs-start.S',
            repository / 'src/test/fixtures/arm-pcs-call-reference.c', '-o', case / 'reference'])
        before[str(case / 'reference')] = digest(case / 'reference')
        run(case, 'elf', ['readelf', '-hASW', case / 'reference'])
        run(case, 'dwarf', ['readelf', '--debug-dump=info', case / 'reference'])
        run(case, 'llvm', ['llvm-dwarfdump', '--verify', case / 'reference'])
        assert 'No errors.' in (case / 'llvm.log').read_text()
        run(case, 'strict', ['python3', source / 'check-dwarfdump.py', case / 'reference', case / 'strict-report.log'])
        for operation, modes in [('finish', ('auto', 'softvfp', 'vfp')),
                ('inject', ('auto', 'softvfp', 'vfp')), ('write', ('auto',))]:
            for mode in modes:
                label = operation + '-' + mode
                run(case, label + '-driver', ['bash', source / 'arm-pcs-call-reference-runtime.sh',
                    case, operation, mode, emulator, gdb, data])
                result = json.loads((case / (label + '.json')).read_text())
                assert result['status'] == 'OBSERVED' and result['exitCode'] == 0
                assert (case / (label + '.qemu.status')).read_text() == 'exit=0\n'
                assert not (case / (label + '.qemu.stderr')).read_bytes()
                stderr = (case / (label + '.stderr')).read_text()
                if operation == 'write':
                    wire = re.findall(r'Sending packet: \$P[0-9a-f]+=([0-9a-f]+)#', stderr)
                    assert wire == ['3ff4000000000000' if order == 'big' else '000000000000f43f'], wire
                    assert result['registerBytes'] == '000000000000f43f'
                    assert (result['registerValue'] == 1.25) == (order == 'little')
                    result['wireBytes'] = wire[0]
                else:
                    warnings = stderr.splitlines()
                    assert all(re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index',
                        line) for line in warnings), warnings
                    rows = result['observations']
                    assert [r['function'] for r in rows] == ['base_sum', 'vfp_sum']
                    for index, row in enumerate(rows):
                        expected = 3.75 if index == 0 else 7.75
                        selected = (index == 0) == (mode == 'softvfp')
                        if operation == 'finish':
                            assert row['arguments'] == ([1.25, 2.5] if index == 0 else [3.25, 4.5])
                            assert (row['returned'] == expected) == selected, row
                            assert row['r0'] == 0x40700000
                            assert row['s0'] == (0.0 if index == 0 else 7.75)
                        else:
                            correct = [row['seenFirst'], row['seenSecond'], row['returned']] == row['expected']
                            assert correct == (selected and (order == 'little' or index == 0)), row
                observations.append({'order': order, **result})
    after = {path: digest(Path(path)) for path in before}
    assert before == after
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_REFERENCE_LIMITATIONS',
        'scope': 'compiler-only calibration; no Forge support claim', 'observations': observations,
        'protectedBefore': before, 'protectedAfter': after}, indent=4) + '\n')
    print('arm-pcs-call-reference=PASS_REFERENCE_LIMITATIONS ' + str(root))


if __name__ == '__main__':
    main()

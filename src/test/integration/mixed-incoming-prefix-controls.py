#!/usr/bin/env python3
"""Require actual GDB rejection of early/late gaps and an incorrect raw carrier."""
import hashlib
import ast
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(root):
    receipt = json.loads((root / 'acceptance.json').read_text())
    assert receipt['status'] == 'PASS' and len(receipt['cases']) == 12
    protected = [Path(__file__), source / 'mixed-incoming-prefix-gdb.py',
        source / 'mixed_incoming_contract.py', source / 'qemu-socket.sh', root / 'acceptance.json']
    for role in ('exec', 'pie'):
        protected += [root / role / name for name in ('mixed.stripped', 'mixed.reference', 'mixed.dbg',
            'mixed.dbg.c', 'labels.txt', 'custom/repeat/model.json')]
    before = {str(path): digest(path) for path in protected}
    output = Path(tempfile.mkdtemp(prefix='oracle-controls.', dir=root))
    script = (source / 'mixed-incoming-prefix-gdb.py').read_text()
    results = []
    for role in ('exec', 'pie'):
        case = root / role
        for name, old, new, offset in (
                ('early-gap', 'compiler or offset < 24', 'compiler or offset < 8', 8),
                ('late-gap', 'compiler or offset < 24', 'compiler or offset < 28', 24),
                ('wrong-carrier', "gdb.parse_and_eval('$r2')", "gdb.parse_and_eval('$r1')", 20)):
            directory = output / (role + '-' + name)
            directory.mkdir()
            assert script.count(old) == 1
            helper = directory / 'gdb.py'
            helper.write_text(script.replace(old, new))
            shutil.copy2(source / 'mixed_incoming_contract.py', directory / 'mixed_incoming_contract.py')
            environment = dict(os.environ, FORGE_MIXED_CASE=str(case), FORGE_MIXED_MODE='forge',
                FORGE_MIXED_MODEL=str(case / 'custom/repeat/model.json'),
                FORGE_MIXED_RESULT=str(directory / 'unexpected-success.json'))
            command = ['bash', '-c', '''set -euo pipefail
source "$1"
trap qemu_socket_cleanup EXIT
sysroot=${FORGE_ARM32_SYSROOT:-/usr/arm-linux-gnueabihf}
qemu_socket_start "$3/qemu" qemu-arm-static "$sysroot" "$2/mixed.stripped"
status=0
FORGE_MIXED_REMOTE="$qemu_socket_path" timeout 45s gdb-multiarch -q -nx -batch \\
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set debuginfod enabled off' \\
    -ex 'set auto-solib-add off' -ex "set sysroot $sysroot" \\
    -ex "file $2/mixed.stripped" -ex "symbol-file $2/mixed.dbg" -x "$3/gdb.py" || status=$?
printf '%s\\n' "$status" >"$3/gdb-exit.txt"
qemu_socket_wait || true
exit "$status"
''', 'mixed-control', str(source / 'qemu-socket.sh'), str(case), str(directory)]
            (directory / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
            process = subprocess.run(command, env=environment, capture_output=True, timeout=60)
            (directory / 'stdout').write_bytes(process.stdout)
            (directory / 'stderr').write_bytes(process.stderr)
            assert process.returncode == 1 and (directory / 'gdb-exit.txt').read_text() == '1\n'
            error = process.stderr.decode()
            message, = re.findall(r"^Python Exception <class 'AssertionError'>: (\{.*\})$", error, re.M)
            point = ast.literal_eval(message)
            assert point['offset'] == offset and point['available'] == (name != 'late-gap')
            assert point['machine'] == {'low': 2 if name == 'wrong-carrier' else 0x12345678, 'high': -1234567}
            assert not (directory / 'unexpected-success.json').exists()
            qemu_error = (directory / 'qemu.stderr').read_text()
            assert qemu_error in ('', 'qemu-arm-static: QEMU: Terminated via GDBstub\n'), qemu_error
            assert (directory / 'qemu.status').read_text() == 'exit=0\n'
            warnings = re.findall(r'^warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index\n',
                (case / 'compiler-gdb.txt').read_text(), re.M)
            warning, = warnings
            assert error == warning + "Python Exception <class 'AssertionError'>: " + message + '\n' + \
                'Error occurred in Python: ' + message + '\n' + qemu_error, error
            endpoint = dict(line.split('=', 1) for line in (directory / 'qemu.endpoint').read_text().splitlines())
            assert not Path(endpoint['socket']).exists() and not Path(endpoint['socket']).parent.exists()
            results.append({'role': role, 'control': name, 'offset': offset, 'status': 'REJECTED',
                'stderrSha256': digest(directory / 'stderr')})
    assert before == {path: digest(Path(path)) for path in before}
    (output / 'result.json').write_text(json.dumps({'status': 'PASS', 'results': results,
        'protectedHashes': before}, indent=4) + '\n')
    print('mixed-incoming-prefix-controls=PASS', output)


if __name__ == '__main__':
    main(Path(sys.argv[1]).resolve(strict=True))

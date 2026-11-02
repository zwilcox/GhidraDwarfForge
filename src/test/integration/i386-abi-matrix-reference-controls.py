#!/usr/bin/env python3
"""Replay the compiler-vector consumer error with an owned, deterministic register control."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(baseline):
    baseline = baseline.resolve(strict=True)
    reference = baseline / 'profile.reference'
    before = digest(reference)
    root = Path(tempfile.mkdtemp(prefix='reference-controls.', dir=baseline))
    rows = []
    for mode in ('unreadable-eax', 'wrong-vector'):
        case = root / mode
        case.mkdir()
        shutil.copy2(reference, case / 'profile.reference')
        (case / 'profile.reference').chmod(0o755)
        # This is a debugger-only control on an owned compiler reference. The
        # exact four-byte callee does not use EAX and still computes its real
        # vector result. Normal production/compiler runs do not alter registers.
        hook = case / 'control.py'
        hook.write_text('''import gdb
import json
from pathlib import Path

def control(event, output=Path(__file__).with_suffix('.json')):
    if int(gdb.parse_and_eval('$pc')) != int(gdb.parse_and_eval('&vector_add')):
        return
    entry = int(gdb.parse_and_eval('$pc'))
    code = bytes(gdb.selected_inferior().read_memory(entry, 4)).hex()
    assert code == '0f58c1c3', code
    gdb.execute('set $eax = 1')
''' + ("    gdb.execute('set $xmm0.v4_float[0] = 0.0')\n" if mode == 'wrong-vector' else '') + '''    output.write_text(json.dumps({'entry': entry, 'code': code,
        'eax': int(gdb.parse_and_eval('$eax'))}))
    gdb.events.stop.disconnect(control)

gdb.events.stop.connect(control)
''')
        command = ['gdb', '-q', '-nx', '-batch', '-ex', 'source ' + str(hook),
            '-x', str(HERE / 'i386-abi-matrix-gdb.py')]
        environment = dict(os.environ, I386_CASE=str(case), I386_VARIANT='compiler')
        environment.pop('I386_ABI_FAILED_FUNCTION', None)
        run = subprocess.run(command, env=environment, capture_output=True, timeout=120)
        (case / 'gdb.log').write_bytes(run.stdout)
        (case / 'gdb.stderr').write_bytes(run.stderr)
        (case / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
        observed = json.loads((case / 'compiler-gdb.json').read_text())
        injected = json.loads(hook.with_suffix('.json').read_text())
        assert injected['eax'] == 1 and injected['code'] == '0f58c1c3'
        vector, = [row for row in observed['rows'] if row['function'] == 'vector_add']
        if mode == 'unreadable-eax':
            assert run.returncode == 0 and not run.stderr, run.stderr
            assert observed['status'] == 'PASS' and len(observed['rows']) == 11
            assert observed['exitCode'] == 0
            diagnostic = vector['finishDiagnostic']
            assert diagnostic['eax'] == 1 and diagnostic['typedReturnValidated'] is False
            assert vector['returned'] is None and vector['rawReturned'] == [1.5, 3.5, 5.5, 7.5]
        else:
            assert observed['status'] == 'FAIL' and 'AssertionError' in observed['error']
            assert 'AssertionError' in run.stderr.decode()
            assert vector['rawArguments']['a'] == [0., 2., 3., 4.]
            assert 'finishDiagnostic' not in vector
        assert digest(case / 'profile.reference') == before
        rows.append({'mode': mode, 'result': observed, 'injection': injected})
    assert digest(reference) == before
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'originalHash': before,
        'rows': rows}, indent=4) + '\n')
    print('i386-abi-matrix-reference-controls=PASS ' + str(root))


if __name__ == '__main__':
    main(Path(sys.argv[1]))

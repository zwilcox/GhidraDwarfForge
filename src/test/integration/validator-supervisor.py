#!/usr/bin/env python3
"""Native supervisor behavior, process cleanup and exact argument controls."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def alive(pid):
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x100000, False, pid)
        if not handle:
            require(ctypes.get_last_error() == 87, 'could not establish child exit')
            return False
        try:
            observed = kernel.WaitForSingleObject(handle, 0)
            require(observed in (0, 258), 'could not wait on the observed child handle')
            return observed == 258
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


CHILD = r'''
import json, os, signal, subprocess, sys, time
from pathlib import Path
mode = sys.argv[1]
root = Path(sys.argv[2])
if mode == 'arguments':
    sys.stdout.buffer.write(json.dumps(sys.argv[3:], ensure_ascii=True).encode('ascii'))
    sys.stderr.buffer.write(b'expected-stderr\x00bytes')
elif mode == 'error':
    print('intentional tool failure', flush=True)
    sys.exit(7)
elif mode == 'signal':
    os.kill(os.getpid(), signal.SIGTERM)
elif mode.startswith('flood'):
    descriptor = 1 if mode == 'flood-out' else 2
    while True:
        os.write(descriptor, b'x' * 16384)
elif mode == 'leaf':
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root / 'leaf-ready').write_text(str(os.getpid()))
    while True:
        time.sleep(.02)
elif mode == 'branch':
    leaf = subprocess.Popen([sys.executable, __file__, 'leaf', str(root)],
                            start_new_session=os.name != 'nt', close_fds=False)
    while not (root / 'leaf-ready').exists():
        time.sleep(.01)
    temporary = root / 'pids.tmp'
    temporary.write_text(json.dumps([os.getpid(), leaf.pid]))
    temporary.replace(root / 'pids.json')
elif mode in ('orphan', 'orphan-closed'):
    options = {'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL} if mode == 'orphan-closed' else {}
    branch = subprocess.Popen([sys.executable, __file__, 'branch', str(root)],
                              start_new_session=os.name != 'nt', close_fds=False, **options)
    branch.wait(timeout=5)
elif mode in ('hang', 'cancel', 'term'):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    leaf = subprocess.Popen([sys.executable, __file__, 'leaf', str(root)],
                            start_new_session=os.name != 'nt', close_fds=False)
    while not (root / 'leaf-ready').exists():
        time.sleep(.01)
    temporary = root / 'pids.tmp'
    temporary.write_text(json.dumps([os.getpid(), leaf.pid]))
    temporary.replace(root / 'pids.json')
    while True:
        time.sleep(.02)
elif mode == 'breakaway':
    try:
        subprocess.Popen([sys.executable, __file__, 'leaf', str(root)], creationflags=0x01000000)
    except OSError as error:
        assert error.winerror == 5, error
        print('breakaway=refused', flush=True)
    else:
        raise AssertionError('child escaped the Windows job')
else:
    raise AssertionError(mode)
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    helper = args.helper.resolve(strict=True)
    helper_hash = hashlib.sha256(helper.read_bytes()).hexdigest()
    child = root / 'child with spaces é.py'
    child.write_text(CHILD)
    version = subprocess.run([str(helper), '--version'], capture_output=True, timeout=5, check=True)
    (root / 'version.txt').write_bytes(version.stdout + version.stderr)
    require(version.stdout.startswith(b'forge-validator-supervisor 1 '), 'wrong helper version')
    cases = []
    arguments = ['', 'a b', 'é', 'line\nsecond', '\\', 'trailing\\', 'a"b', '\\"', '\\\\"', '$(ignored)', '`literal`']

    def run(mode, expected, timeout=5000, extra=None, collision=None):
        directory = root / mode
        directory.mkdir()
        status = directory / 'status.json'
        out, err = directory / 'stdout.bin', directory / 'stderr.bin'
        if collision:
            collision(directory)
        command = [str(helper), str(timeout), '65536', str(status), str(out), str(err), '--',
                   sys.executable, str(child), mode, str(directory), *(extra or [])]
        (directory / 'argv.json').write_text(json.dumps(command, indent=4) + '\n')
        started = time.monotonic()
        with (directory / 'helper.stdout').open('wb') as helper_out, (directory / 'helper.stderr').open('wb') as helper_err:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=helper_out, stderr=helper_err)
            try:
                if mode in ('cancel', 'term'):
                    deadline = time.monotonic() + 5
                    while not (directory / 'pids.json').exists():
                        require(process.poll() is None and time.monotonic() < deadline, 'child never became ready')
                        time.sleep(.01)
                    if mode == 'cancel':
                        process.stdin.close()
                    else:
                        process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=12)
            finally:
                if not process.stdin.closed:
                    process.stdin.close()
                if process.poll() is None:
                    process.wait(timeout=7)
        require(time.monotonic() - started < 12, 'supervisor exceeded outer bound')
        if expected == 'rejected':
            require(code != 0, 'unsafe/invalid invocation succeeded')
            require(not (directory / 'pids.json').exists(), 'rejected invocation launched child')
            cases.append({'mode': mode, 'exit': code, 'reason': 'rejected'})
            return
        require(not (directory / 'helper.stdout').read_bytes() and not (directory / 'helper.stderr').read_bytes(),
                'unexpected supervisor diagnostics')
        record = json.loads(status.read_text())
        require(record['schemaVersion'] == 1 and record['reason'] == expected and record['cleanupComplete'],
                'wrong supervisor outcome: ' + repr(record))
        require((code == 0) == (expected == 'completed'), 'exit code contradicts status')
        for name, path in [('stdout', out), ('stderr', err)]:
            require(path.stat().st_size == record[name + 'Retained'] <= 65536 and
                    record[name + 'Observed'] >= record[name + 'Retained'], 'stream bounds/counts disagree')
        if (directory / 'pids.json').exists():
            for pid in json.loads((directory / 'pids.json').read_text()):
                require(not alive(pid), 'supervised descendant survived: ' + str(pid))
        cases.append({'mode': mode, 'exit': code, 'record': record, 'elapsed': time.monotonic() - started})

    run('arguments', 'completed', extra=arguments)
    require(json.loads((root / 'arguments/stdout.bin').read_bytes()) == arguments, 'argument codec changed bytes')
    require((root / 'arguments/stderr.bin').read_bytes() == b'expected-stderr\x00bytes', 'stderr bytes changed')
    run('error', 'tool_error')
    require(cases[-1]['record']['exitCode'] == 7, 'child exit status lost')
    if os.name != 'nt':
        run('signal', 'tool_error')
        require(cases[-1]['record']['exitSignal'] == signal.SIGTERM, 'child signal lost')
    run('flood-out', 'output_limit')
    run('flood-err', 'output_limit')
    run('orphan', 'descendants')
    run('orphan-closed', 'descendants')
    run('hang', 'timeout', timeout=1000)
    run('cancel', 'cancelled')
    if os.name != 'nt':
        run('term', 'cancelled')
    else:
        run('breakaway', 'completed')
        require((root / 'breakaway/stdout.bin').read_bytes().strip() == b'breakaway=refused', 'breakaway was not refused')
    sentinel = b'original must remain unchanged\n'
    run('existing-status', 'rejected', collision=lambda directory: (directory / 'status.json').write_bytes(sentinel))
    require((root / 'existing-status/status.json').read_bytes() == sentinel, 'status collision truncated input')
    run('existing-output', 'rejected', collision=lambda directory: (directory / 'stdout.bin').write_bytes(sentinel))
    require((root / 'existing-output/stdout.bin').read_bytes() == sentinel, 'output collision truncated input')
    if os.name != 'nt':
        selected = root / 'protected-original'
        selected.write_bytes(sentinel)
        run('linked-output', 'rejected', collision=lambda directory: (directory / 'stdout.bin').symlink_to(selected))
        require(selected.read_bytes() == sentinel, 'symlink collision truncated input')
    require(hashlib.sha256(helper.read_bytes()).hexdigest() == helper_hash, 'helper changed')
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'host': sys.platform,
        'helperSha256': helper_hash, 'cases': cases}, indent=4) + '\n')
    print('validator-supervisor=PASS cases=' + str(len(cases)))


if __name__ == '__main__':
    main()

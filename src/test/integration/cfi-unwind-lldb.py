#!/usr/bin/env python3
"""Compare production unwind exports with compiler traces in pinned LLDB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import shlex
import socket
import subprocess
import time


SCRIPTS = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trace(original, symbols, target, output, debugger):
    output.mkdir()
    commands = ['target create ' + shlex.quote(str(original)),
        'target symbols add --shlib ' + shlex.quote(str(original)) + ' ' + shlex.quote(str(symbols)),
        'log enable -f ' + shlex.quote(str(output / 'unwind.log')) + ' lldb unwind',
        'breakpoint set --name cfi_main --skip-prologue false']
    qemu = None
    qlog = None
    try:
        if target == 'aarch64':
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            qcommand = ['qemu-aarch64-static', '-g', str(port), str(original)]
            (output / 'qemu-command.json').write_text(json.dumps(qcommand, indent=4) + '\n')
            qlog = (output / 'qemu.log').open('w')
            qemu = subprocess.Popen(qcommand, stdout=qlog, stderr=subprocess.STDOUT)
            time.sleep(0.2)
            assert qemu.poll() is None, 'QEMU exited before LLDB connected'
            commands.extend(['gdb-remote 127.0.0.1:' + str(port), 'continue'])
        else:
            commands.extend(['settings set target.disable-aslr false', 'run'])
        commands.extend(['image show-unwind -n cfi_main',
            'script exec(open(' + repr(str(SCRIPTS / 'cfi-boundaries-lldb.py')) + ').read())'])
        command = [debugger, '--no-lldbinit', '--batch']
        for item in commands:
            command.extend(['-o', item])
        (output / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
        result_path = output / 'trace.json'
        with (output / 'lldb.log').open('w') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                env=dict(os.environ, FORGE_LLDB_TRACE=str(result_path),
                    FORGE_LLDB_WITNESS='r12' if target == 'x86_64' else 'x19'),
                start_new_session=True)
            try:
                status = process.wait(timeout=90)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        text = (output / 'lldb.log').read_text()
        # LLDB's Python command can print an assertion and still return zero.
        assert status == 0 and result_path.exists(), text[-4000:]
        assert 'Traceback' not in text and 'FORGE_LLDB_BOUNDARIES_PASS' in text
        if qemu is not None:
            assert qemu.wait(timeout=5) == 0
        assert 'using DWARF CFI UnwindPlan' in (output / 'unwind.log').read_text()
        return json.loads(result_path.read_text())
    finally:
        if qemu is not None and qemu.poll() is None:
            qemu.terminate()
            try:
                qemu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                qemu.kill()
                qemu.wait()
        if qlog is not None:
            qlog.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('compiler_cases', type=Path)
    parser.add_argument('production_exports', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--lldb', default='lldb-18')
    parser.add_argument('--target', choices=('all', 'x86_64', 'aarch64'), default='all')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    version = subprocess.check_output([args.lldb, '--version'], text=True).strip()
    assert version == 'lldb version 18.1.3', version
    qemu_version = subprocess.check_output(['qemu-aarch64-static', '--version'], text=True).splitlines()[0]
    prior = json.loads((args.production_exports / 'result.json').read_text())
    assert prior['status'] == 'PASS_PRODUCTION_UNWIND'
    results = []
    for item in prior['cases']:
        target, role = item['target'], item['role']
        assert target in ('x86_64', 'aarch64') and role == 'exec', 'Initial LLDB CFI lane is non-PIE only'
        compiler = args.compiler_cases.resolve() / (target + '-' + role) / 'compiler'
        original, reference = compiler / 'without-cfi', compiler / 'reference'
        artifacts = args.production_exports.resolve() / (target + '-' + role)
        paths = [original, reference, artifacts / 'conditioned.dbg', artifacts / 'compressed.dbg']
        protected = {str(path): digest(path) for path in paths}
        assert all(protected[str(path)] == prior['protectedSha256'][str(path)] for path in (original, reference))
        for mode in ('conditioned', 'compressed'):
            expected, = [row for row in item['artifacts'] if row['mode'] == mode]
            assert protected[str(artifacts / (mode + '.dbg'))] == expected['sha256']
        baseline = trace(original, reference, target, output / (target + '-reference'), args.lldb)
        assert all('witness' in row for frames in baseline['trace'] for row in frames)
        for mode in ('conditioned', 'compressed'):
            observed = trace(original, artifacts / (mode + '.dbg'), target,
                output / (target + '-' + mode), args.lldb)
            assert observed == baseline, (target, mode, 'compiler and Forge instruction traces differ')
        assert protected == {path: digest(Path(path)) for path in protected}
        results.append({'target': target, 'role': role, 'boundaries': len(baseline['trace']),
            'sessions': 3, 'protectedSha256': protected})
    expected_targets = {'x86_64', 'aarch64'} if args.target == 'all' else {args.target}
    assert {row['target'] for row in results} == expected_targets
    (output / 'result.json').write_text(json.dumps({'status': 'PASS_LLDB_CFI_BOUNDARIES',
        'lldb': version, 'transport': qemu_version, 'cases': results,
        'scope': 'Ordinary compiler CFI traces versus plain/compressed production sidecars; non-PIE only. '
            'Does not complete the source/type/location/PIE/shared/sectionless LLDB matrix.'}, indent=4) + '\n')
    print('lldb-cfi-boundaries=PASS')


if __name__ == '__main__':
    main()

"""Process isolation and retained commands for the pinned ELF LLDB consumers."""
import json
import os
import shlex
import signal
import socket
import subprocess
import time


def versions(debugger, target):
    version = subprocess.check_output([debugger, '--version'], text=True).strip()
    assert version == 'lldb version 18.1.3', version
    assert target in ('x86_64', 'aarch64')
    transport = subprocess.check_output(['qemu-aarch64-static', '--version'], text=True).splitlines()[0] \
        if target == 'aarch64' else 'native Linux'
    return {'debugger': version, 'transport': transport}


def run(original, symbols, output, debugger, target, before, after, environment,
        stop_at_entry=False, separate_symbol_module=False):
    """Run commands at fresh CLI boundaries; callers validate their JSON result."""
    output.mkdir()
    symbol_command = ('target modules add ' + shlex.quote(str(symbols)) if separate_symbol_module else
        'target symbols add --shlib ' + shlex.quote(str(original)) + ' ' + shlex.quote(str(symbols)))
    commands = ['target create ' + shlex.quote(str(original)), symbol_command, *before]
    qemu = None
    qlog = None
    try:
        if target == 'aarch64':
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            qcommand = ['qemu-aarch64-static', '-L', '/usr/aarch64-linux-gnu', '-g', str(port), str(original)]
            (output / 'qemu-command.json').write_text(json.dumps(qcommand, indent=4) + '\n')
            qlog = (output / 'qemu.log').open('w')
            qemu = subprocess.Popen(qcommand, stdout=qlog, stderr=subprocess.STDOUT)
            time.sleep(0.2)
            assert qemu.poll() is None, 'QEMU exited before LLDB connected'
            commands.append('gdb-remote 127.0.0.1:' + str(port))
            if not stop_at_entry:
                commands.append('continue')
        else:
            assert target == 'x86_64'
            commands.extend(['settings set target.disable-aslr false',
                'process launch --stop-at-entry' if stop_at_entry else 'run'])
        commands.extend(after)
        command = [debugger, '--no-lldbinit', '--batch']
        for item in commands:
            command.extend(['-o', item])
        (output / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
        (output / 'environment.json').write_text(json.dumps(environment, indent=4) + '\n')
        with (output / 'lldb.log').open('w') as log:
            process = subprocess.Popen(command, cwd=output, stdout=log, stderr=subprocess.STDOUT,
                env=dict(os.environ, **environment), start_new_session=True)
            try:
                status = process.wait(timeout=120)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        transcript = (output / 'lldb.log').read_text()
        assert status == 0 and 'Traceback' not in transcript, transcript[-5000:]
        assert not any(line.startswith(('error:', 'warning:')) for line in transcript.splitlines()), transcript[-5000:]
        if qemu is not None:
            assert qemu.wait(timeout=5) == 0
        return transcript
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

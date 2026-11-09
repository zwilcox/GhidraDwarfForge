#!/usr/bin/env python3
"""Run the same Cortex-M firmware with compiler or Forge symbols over QEMU remote."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent


def debugger(case, symbols, output, variant):
    assert variant in ('compiler', 'forge')
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cortex-m-') as temporary:
        socket = Path(temporary) / 'gdb'
        command = ['qemu-system-arm', '-M', 'lm3s6965evb', '-cpu', 'cortex-m3',
            '-kernel', str(case / 'original.elf'), '-display', 'none', '-serial', 'none',
            '-monitor', 'none', '-nic', 'none', '-S',
            '-gdb', 'unix:' + str(socket) + ',server=on,wait=off']
        (output / (variant + '-qemu-command.json')).write_text(json.dumps(command, indent=4) + '\n')
        with (output / (variant + '-qemu.log')).open('w') as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert socket.exists() and process.poll() is None, 'QEMU failed to start'
                argv = ['gdb-multiarch', '-q', '-nx', '-batch', '-x', str(HERE / 'cortex-m-gdb.py')]
                (output / (variant + '-gdb-command.json')).write_text(json.dumps(argv, indent=4) + '\n')
                with (output / (variant + '-gdb.log')).open('w') as gout:
                    completed = subprocess.run(argv, stdout=gout, stderr=subprocess.STDOUT, timeout=90,
                        env=dict(os.environ, FORGE_CORTEX_CASE=str(case), FORGE_CORTEX_SOCKET=str(socket),
                            FORGE_CORTEX_SYMBOLS=str(symbols), FORGE_CORTEX_OUTPUT=str(output),
                            FORGE_CORTEX_VARIANT=variant))
                observed = json.loads((output / (variant + '-gdb.json')).read_text())
                assert completed.returncode == 0 and observed['status'] == 'PASS', observed.get('error', observed)
                assert len(observed['exceptions']) == 2 and process.poll() is None
                return observed
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    parser.add_argument('--symbols', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variant', choices=('compiler', 'forge'), required=True)
    args = parser.parse_args()
    debugger(args.case.resolve(strict=True), args.symbols.resolve(strict=True), args.output.resolve(), args.variant)
    print('cortex-m-runtime=PASS ' + args.variant)


if __name__ == '__main__':
    main()

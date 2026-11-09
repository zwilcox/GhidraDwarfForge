#!/usr/bin/env python3
"""Compile and debug the standalone Cortex-M3 ELF before testing Forge output."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / 'fixtures'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='cortex-m3.', dir=args.results.resolve()))
    print('cortex-m-reference-results=' + str(root), flush=True)
    sources = [FIXTURES / name for name in ('cortex-m-profile.c', 'cortex-m-start.S', 'cortex-m.ld')]
    protected = {str(p): digest(p) for p in sources}
    commands = []

    def run(label, argv, **kwargs):
        argv = list(map(str, argv))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as output:
            subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT,
                check=True, timeout=90, **kwargs)
        return (root / (label + '.log')).read_text()

    cc = shutil.which('arm-none-eabi-gcc')
    assert cc, 'arm-none-eabi-gcc is required on PATH'
    reference, original = root / 'reference.elf', root / 'original.elf'
    versions = {tool: run(tool + '-version', [tool, '--version']).splitlines()[0]
        for tool in ('arm-none-eabi-gcc', 'arm-none-eabi-objcopy', 'qemu-system-arm', 'gdb-multiarch')}
    run('compile', [cc, '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft',
        '-O1', '-g', '-gdwarf-5', '-ffreestanding', '-fno-builtin', '-fno-common',
        '-fno-omit-frame-pointer', '-fno-optimize-sibling-calls', '-Wall', '-Wextra', '-Werror',
        '-nostdlib', '-static', '-Wl,--build-id=sha1', '-Wl,-z,noexecstack', '-Wl,-T,' + str(sources[2]),
        sources[1], sources[0], '-o', reference])
    run('strip', ['arm-none-eabi-objcopy', '--strip-all', reference, original])
    protected.update({str(p): digest(p) for p in (reference, original)})
    attributes = run('attributes', ['arm-none-eabi-readelf', '-hAlSW', reference])
    assert 'Tag_CPU_arch: v7' in attributes and 'Tag_CPU_arch_profile: Microcontroller' in attributes
    assert 'Tag_THUMB_ISA_use: Thumb-2' in attributes
    assert 'Tag_ARM_ISA_use: Yes' not in attributes
    assert 'Tag_FP_arch:' not in attributes and 'Tag_ABI_VFP_args: VFP registers' not in attributes
    symbols = run('symbols', ['arm-none-eabi-nm', '-n', reference])
    labels = {parts[2]: int(parts[0], 16) for line in symbols.splitlines()
        if len(parts := line.split()) == 3}
    assert labels['cortex_vectors'] == 0 and labels['_stack_top'] == 0x20010000
    assert labels['_psp_top'] == 0x2000f000
    assert labels['_sidata'] < 0x40000 and labels['_sdata'] == 0x20000000
    assert labels['_sdata'] < labels['_edata'] <= labels['_sbss'] < labels['_ebss']
    run('disassembly', ['arm-none-eabi-objdump', '-d', reference])
    run('llvm', ['llvm-dwarfdump', '--verify', reference])
    (root / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    (root / 'profile.json').write_text(json.dumps({'core': 'Cortex-M3', 'isa': 'ARMv7-M',
        'board': 'lm3s6965evb', 'abi': 'AAPCS32 base PCS', 'byteOrder': 'little',
        'versions': versions, 'inputSha256': protected[str(original)]}, indent=4) + '\n')
    with tempfile.TemporaryDirectory(prefix='cortex-m-') as temporary:
        socket = Path(temporary) / 'gdb'
        command = ['qemu-system-arm', '-M', 'lm3s6965evb', '-cpu', 'cortex-m3',
            '-kernel', str(original), '-display', 'none', '-serial', 'none',
            '-monitor', 'none', '-nic', 'none', '-S',
            '-gdb', 'unix:' + str(socket) + ',server=on,wait=off']
        (root / 'qemu-command.json').write_text(json.dumps(command, indent=4) + '\n')
        with (root / 'qemu.log').open('w') as output:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while not socket.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.05)
                assert socket.exists() and process.poll() is None, 'QEMU failed to start'
                run('gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-x', HERE / 'cortex-m-gdb.py'],
                    env=dict(os.environ, FORGE_CORTEX_CASE=str(root), FORGE_CORTEX_SOCKET=str(socket)))
                assert process.poll() is None
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
    observed = json.loads((root / 'compiler-gdb.json').read_text())
    assert observed['status'] == 'PASS' and len(observed['exceptions']) == 2
    assert all(digest(Path(path)) == before for path, before in protected.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_COMPILER_CORTEX_M_REFERENCE',
        'profile': 'Cortex-M3/lm3s6965evb/base-PCS', 'protectedSha256': protected,
        'versions': versions, 'scope': 'Compiler reference only; Forge export remains unverified.'}, indent=4) + '\n')
    print('cortex-m-reference=PASS ' + str(root))


if __name__ == '__main__':
    main()

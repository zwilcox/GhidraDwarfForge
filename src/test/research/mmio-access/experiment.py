#!/usr/bin/env python3
"""Observe GDB reads against a source-modeled peripheral, using compiler DWARF.

The first profile is x86-64 little endian. This is not a Forge-export test or a
physical bus claim. RSP requests and device callbacks are recorded separately.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading

REPOSITORY = Path(__file__).resolve().parents[4]
BASE = 0x40000000
INITIAL = 0xa5a5e28d


class Device:
    """Two aligned 32-bit registers with separately observed side effects."""
    def __init__(self, initial, byteorder='little'):
        self.initial = initial
        self.byteorder = byteorder
        self.storage = bytearray(initial)
        self.accesses = []

    def read(self, address, width, phase):
        offset = address - BASE
        accepted = width == 4 and offset in (0, 4)
        event = {'phase': phase, 'address': hex(address), 'width': width, 'accepted': accepted}
        self.accesses.append(event)
        if not accepted:
            raise ValueError('device requires aligned 32-bit reads')
        result = bytes(self.storage[offset:offset + 4])
        event['value'] = int.from_bytes(result, self.byteorder)
        if offset == 0:
            self.storage[:4] = bytes(4)
            event['effect'] = 'read-clear'
        else:
            self.storage[4:] = ((event['value'] + 1) & 0xffffffff).to_bytes(4, self.byteorder)
            event['effect'] = 'read-increment'
        return result

    def reset(self):
        self.storage[:] = self.initial


class Target:
    """Bounded single-client RSP test target; no running program or host writes."""
    def __init__(self, device, entry, backend):
        self.device, self.entry, self.backend = device, entry, backend
        self.phase = 'connect'
        self.requests, self.errors = [], []

    def reply(self, command):
        if command.startswith('qSupported'):
            return 'PacketSize=4000'
        fixed = {'?': 'S05', 'qfThreadInfo': 'm1', 'qsThreadInfo': 'l',
            'qC': 'QC1', 'qAttached': '1'}
        if command in fixed:
            return fixed[command]
        if command.startswith('H') or command.startswith('qSymbol'):
            return 'OK'
        if command.startswith('qRcmd,'):
            self.phase = bytes.fromhex(command.split(',')[1]).decode('ascii')
            if self.phase.startswith('reset-'):
                self.device.reset()
            return 'OK'
        if command == 'g':
            # Explicit x86-64 legacy register packet, not generic target logic.
            registers = bytearray(536)
            registers[16 * 8:17 * 8] = self.entry.to_bytes(8, 'little')
            return registers.hex()
        if command.startswith('m'):
            address, size = (int(value, 16) for value in command[1:].split(','))
            if not 0 < size <= 16384:
                return 'E01'
            if address < BASE or address >= BASE + 8:
                return '00' * size
            before = self.device.storage.hex()
            response = 'E01'
            if address + size <= BASE + 8:
                try:
                    # A request is not a transaction: these transport models
                    # deliberately split the same packet into different widths.
                    width = 4 if self.backend == 'word32' else 1
                    data = bytearray()
                    for done in range(0, size, width):
                        data += self.device.read(address + done, min(width, size - done), self.phase)
                    response = data.hex()
                except ValueError:
                    pass
            self.requests.append({'phase': self.phase, 'address': hex(address),
                'size': size, 'response': response, 'before': before, 'after': self.device.storage.hex()})
            return response
        if command == 'D' or command.startswith('D;'):
            return 'OK'
        # Unsupported operations (including writes and execution) never succeed.
        return ''

    def serve(self, listener):
        try:
            with listener.accept()[0] as client:
                client.settimeout(20)
                with client.makefile('rb', buffering=0) as stream:
                    while True:
                        start = stream.read(1)
                        if not start:
                            return
                        if start != b'$':
                            continue
                        payload = bytearray()
                        while (byte := stream.read(1)) != b'#':
                            if not byte or len(payload) >= 16384:
                                raise ValueError('invalid RSP request length')
                            payload += byte
                        checksum = stream.read(2)
                        if len(checksum) != 2 or int(checksum, 16) != sum(payload) & 255:
                            raise ValueError('invalid RSP checksum')
                        client.sendall(b'+')
                        command = payload.decode('ascii')
                        response = self.reply(command).encode('ascii')
                        client.sendall(b'$' + response + b'#' + f'{sum(response) & 255:02x}'.encode())
                        if command == 'D' or command.startswith('D;'):
                            return
        except Exception as error:
            self.errors.append(repr(error))


def run_case(root, elf, initial, entry, backend, cache):
    device = Device(initial)
    target = Target(device, entry, backend)
    name = backend + '-' + cache
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(25)
        worker = threading.Thread(target=target.serve, args=(listener,))
        worker.start()
        commands = ['set pagination off', 'set confirm off', 'set auto-load off',
            'set auto-solib-add off', 'file ' + json.dumps(str(elf)),
            'target remote 127.0.0.1:' + str(listener.getsockname()[1]),
            'set mem inaccessible-by-default off', 'mem 0x40000000 0x40000008 ro 32 ' + cache, 'info mem',
            'monitor ptype', 'ptype peripheral',
            'python print("TYPE_WIDTHS", gdb.lookup_type("unsigned int").sizeof, '
            'gdb.lookup_type("struct ByteFields").sizeof, gdb.lookup_type("union Register").sizeof)',
            'monitor bit-a', 'printf "FIELD_A=%u\\n", peripheral.status.bits.a',
            'monitor bit-b', 'printf "FIELD_B=%u\\n", peripheral.status.bits.b',
            'monitor reset-packed', 'print peripheral.status.byte',
            'monitor reset-cross', 'print peripheral.status.cross',
            'monitor reset-union', 'print peripheral.status',
            'monitor reset-structure', 'print peripheral',
            'monitor reset-snapshot',
            'python raw=bytes(gdb.selected_inferior().read_memory(0x40000000,4)); '
            'n=int.from_bytes(raw,"little"); print("SNAPSHOT", n & 7, (n >> 3) & 31)', 'detach']
        argv = ['gdb', '-nx', '-nh', '-batch']
        for command in commands:
            argv += ['-ex', command]
        (root / (name + '-command.json')).write_text(json.dumps(argv, indent=4) + '\n')
        try:
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        finally:
            worker.join(timeout=25)
        assert not worker.is_alive() and not target.errors, target.errors
    text = completed.stdout + completed.stderr
    (root / (name + '.log')).write_text(text)
    record = {'backend': backend, 'cache': cache, 'returnCode': completed.returncode,
        'requests': target.requests, 'deviceAccesses': device.accesses}
    (root / (name + '.json')).write_text(json.dumps(record, indent=4) + '\n')
    assert not any(row['phase'] == 'ptype' for row in device.accesses)
    assert 'TYPE_WIDTHS 4 1 4' in completed.stdout
    assert 'ro 32 ' + cache in completed.stdout, 'selected GDB memory policy is not active'
    if backend == 'byte-split':
        # GDB can exit zero after command errors followed by successful detach.
        assert device.accesses and all(not row['accepted'] for row in device.accesses)
        assert 'Cannot access memory' in completed.stderr and 'SNAPSHOT' not in completed.stdout
    else:
        assert completed.returncode == 0, text
        if cache == 'nocache':
            rejected = [row for row in device.accesses if not row['accepted']]
            assert len(rejected) == 1 and rejected[0]['phase'] == 'reset-packed' and rejected[0]['width'] == 1
            assert all(row['width'] == 4 for row in device.accesses if row['accepted'])
            assert 'SNAPSHOT 5 17' in completed.stdout
            assert 'FIELD_A=5\n' in completed.stdout and 'FIELD_B=0\n' in completed.stdout
            field_reads = [row for row in device.accesses if row['phase'] in ('bit-a', 'bit-b')]
            assert [row['value'] for row in field_reads] == [INITIAL, 0]
            assert all(row['effect'] == 'read-clear' for row in field_reads)
            assert [row['width'] for row in device.accesses if row['phase'] == 'reset-snapshot'] == [4]
            assert [row['width'] for row in device.accesses if row['phase'] == 'reset-structure'] == [4, 4]
            # The remote path still requests a byte for this packed view despite
            # the GDB region's 32-bit attribute. Treat direct printing as unsafe.
            packed, = [row for row in target.requests if row['phase'] == 'reset-packed']
            assert packed['size'] == 1 and packed['response'] == 'E01' and packed['before'] == packed['after']
            assert 'Cannot access memory' in completed.stderr
            assert 'a = 5, b = 17' in completed.stdout
            assert 'sign = -1' in completed.stdout
            assert 'prefix = 13, cross = 10, sign = -1, reserved = 42405' in completed.stdout
            assert 'STATUS_READY | STATUS_BUSY | STATUS_ERROR | unknown: 0xa5a5e204' in completed.stdout
        else:
            assert all(row['width'] == 4 and row['accepted'] for row in device.accesses)
            assert [row['width'] for row in device.accesses if row['phase'] == 'bit-a'] == [4, 4]
            assert 'FIELD_A=5\n' in completed.stdout and 'FIELD_B=17\n' in completed.stdout
            assert not any(row['phase'] == 'bit-b' for row in device.accesses)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source = REPOSITORY / 'src/test/fixtures/mmio-registers.c'
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    elf = root / 'reference.elf'
    command = ['gcc', '-g', '-gdwarf-5', '-O0', '-fno-pie', '-no-pie', '-Wall', '-Wextra', '-Werror',
        '-Wl,--section-start=.mmio=0x40000000', str(source), '-o', str(elf)]
    subprocess.run(command, check=True)
    original_hash = hashlib.sha256(elf.read_bytes()).hexdigest()
    (root / 'compile-command.json').write_text(json.dumps(command, indent=4) + '\n')
    inspected = root / 'inspection-copy.elf'
    subprocess.run(['objcopy', '--dump-section', '.mmio=' + str(root / 'registers.bin'),
        str(elf), str(inspected)], check=True)
    inspected.unlink()
    initial = (root / 'registers.bin').read_bytes()
    assert initial == INITIAL.to_bytes(4, 'little') + (17).to_bytes(4, 'little')
    symbols = subprocess.check_output(['nm', str(elf)], text=True)
    entry = int(next(line.split()[0] for line in symbols.splitlines() if line.endswith(' T main')), 16)
    verified = subprocess.run(['llvm-dwarfdump', '--verify', str(elf)], capture_output=True, text=True)
    (root / 'llvm.log').write_text(verified.stdout + verified.stderr)
    assert verified.returncode == 0 and 'No errors.' in verified.stdout
    cases = [run_case(root, elf, initial, entry, backend, cache) for backend, cache in (
        ('word32', 'nocache'), ('word32', 'cache'), ('byte-split', 'nocache'))]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    assert hashlib.sha256(elf.read_bytes()).hexdigest() == original_hash
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MMIO_ACCESS_REFERENCE',
        'scope': 'x86-64 compiler DWARF and emulated device callbacks only; no Forge or physical bus claim',
        'sourceSha256': source_hash, 'referenceSha256': original_hash,
        'compiler': subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0],
        'gdb': subprocess.check_output(['gdb', '--version'], text=True).splitlines()[0],
        'cases': cases}, indent=4) + '\n')
    print('mmio-access-reference=PASS')


if __name__ == '__main__':
    main()

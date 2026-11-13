#!/usr/bin/env python3
"""Compare compiler/Forge snapshots with exact byte, halfword and doubleword callbacks."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading

from experiment import Device, INITIAL, REPOSITORY
from helper import ProfileTarget, digest, profile
from layout import PROFILES

BASE = 0x40001000
REGISTERS = ((0, 1, 0xd3, 'read-clear'), (8, 2, 0xb6d5, 'none'),
    (16, 8, 0x89abcdef01234567, 'read-increment'), (24, 8, 17, 'read-clear'))
LOADER_WARNING = ('warning: Unable to find dynamic linker breakpoint function.\n'
    'GDB will be unable to debug shared library initializers\n'
    'and track explicitly loaded dynamic code.\n')


class WidthDevice:
    def __init__(self, initial, byteorder):
        self.storage = bytearray(initial)
        self.byteorder = byteorder
        self.accesses = []

    def read(self, address, size, phase):
        entry = next((r for r in REGISTERS if BASE + r[0] == address and r[1] == size), None)
        event = {'phase': phase, 'address': hex(address), 'width': size, 'accepted': entry is not None}
        self.accesses.append(event)
        if entry is None:
            raise ValueError('wrong device address/width')
        offset, width, _, effect = entry
        result = bytes(self.storage[offset:offset + width])
        value = int.from_bytes(result, self.byteorder)
        event.update(value=value, effect=effect)
        if effect == 'read-clear':
            self.storage[offset:offset + width] = bytes(width)
        elif effect == 'read-increment':
            self.storage[offset:offset + width] = ((value + 1) % (1 << (width * 8))).to_bytes(width, self.byteorder)
        return result


class WidthTarget(ProfileTarget):
    def __init__(self, device, architecture, bad_width):
        super().__init__(Device(INITIAL.to_bytes(4, 'little') + bytes(4)), 'word32', architecture)
        self.width_device = device
        self.bad_width = bad_width

    def reply(self, command):
        if command.startswith('m'):
            address, size = (int(v, 16) for v in command[1:].split(','))
            if BASE <= address < BASE + 32:
                response = 'E01'
                before = self.width_device.storage.hex()
                try:
                    # Wrong transport uses one byte, even for half/doubleword requests.
                    data = self.width_device.read(address, 1 if self.bad_width else size, self.phase)
                    response = data.hex()
                except ValueError:
                    pass
                self.requests.append({'phase': self.phase, 'address': hex(address), 'size': size,
                    'response': response, 'before': before, 'after': self.width_device.storage.hex()})
                return response
        return super().reply(command)


def observe(root, target_name, original, sidecar, selected, raw, helper, bad_width=False):
    root.mkdir(parents=True, exist_ok=False)
    selection_path = root / 'profile.json'
    selection_path.write_text(json.dumps(selected, indent=4) + '\n')
    device = WidthDevice(raw, PROFILES[target_name][2])
    target = WidthTarget(device, selected['architecture'], bad_width)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(20)
        worker = threading.Thread(target=target.serve, args=(listener,))
        worker.start()
        commands = ['set pagination off', 'set confirm off', 'set auto-load off',
            'set debuginfod enabled off', 'set sysroot /', 'set auto-solib-add off',
            'file ' + json.dumps(str(original)), 'symbol-file ' + json.dumps(str(sidecar)),
            'target remote 127.0.0.1:' + str(listener.getsockname()[1]),
            'set mem inaccessible-by-default off', 'mem 0x40001000 0x40001020 ro 32 cache',
            'monitor load', 'source ' + str(helper),
            'forge-mmio load ' + json.dumps(str(selection_path)) + ' ' + json.dumps(str(sidecar))]
        for offset, width, value, effect in REGISTERS[:3]:
            for index in range(2):
                commands += ['monitor read-' + str(width) + '-' + str(index),
                    'forge-mmio snapshot reg' + str(width * 8) + ' ' + selected['transport']['id']]
        commands += ['detach']
        argv = ['gdb-multiarch', '-nx', '-nh', '-batch']
        for command in commands:
            argv += ['-ex', command]
        (root / 'command.json').write_text(json.dumps(argv, indent=4) + '\n')
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=25)
        finally:
            worker.join(timeout=22)
        assert not worker.is_alive() and not target.errors, target.errors
    (root / 'gdb.log').write_text(result.stdout + result.stderr)
    warnings = [LOADER_WARNING] if target_name.startswith('mips') and LOADER_WARNING in result.stderr else []
    stderr = result.stderr.replace(LOADER_WARNING, '', 1) if warnings else result.stderr
    snapshots = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"address":')]
    assert not target.device.accesses, 'unexpected read in the other peripheral bank'
    assert [r['size'] for r in target.requests] == [1, 1, 2, 2, 8, 8], target.requests
    assert [r['phase'] for r in device.accesses] == ['read-1-0', 'read-1-1', 'read-2-0', 'read-2-1', 'read-8-0', 'read-8-1']
    assert device.storage[24:] == raw[24:], 'snapshot reached adjacent read-clear register'
    if bad_width:
        assert [r['accepted'] for r in device.accesses] == [True, True, False, False, False, False]
        assert len(snapshots) == 2 and [s['views']['scalar'] for s in snapshots] == [0xd3, 0]
        assert stderr.count('no retry') == 4 and len(stderr.splitlines()) == 4, stderr
        assert device.storage[8:24] == raw[8:24], 'rejected reads changed device state'
    else:
        assert result.returncode == 0 and not stderr, stderr
        assert [r['width'] for r in device.accesses] == [1, 1, 2, 2, 8, 8]
        assert all(r['accepted'] for r in device.accesses)
        assert [s['views']['scalar'] for s in snapshots] == [0xd3, 0, 0xb6d5, 0xb6d5,
            0x89abcdef01234567, 0x89abcdef01234568], snapshots
        for snapshot, (_, width, _, _) in zip(snapshots, [r for r in REGISTERS[:3] for _ in range(2)]):
            assert len(bytes.fromhex(snapshot['raw'])) == width
    record = {'status': 'PASS', 'requests': target.requests, 'callbacks': device.accesses,
        'snapshots': snapshots, 'warnings': warnings}
    (root / 'result.json').write_text(json.dumps(record, indent=4) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True, choices=tuple(PROFILES))
    for option in ('original', 'sidecar', 'profile', 'reference', 'results', 'helper'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    original, sidecar, reference, helper = (getattr(args, n).resolve(strict=True) for n in ('original', 'sidecar', 'reference', 'helper'))
    protected = {str(p): digest(p) for p in (original, sidecar, reference, args.profile, helper)}
    copy = root / 'inspection.elf'
    raw_path = root / 'registers.bin'
    subprocess.run([PROFILES[args.target][1], '--dump-section', '.mmio_widths=' + str(raw_path), str(reference), str(copy)], check=True)
    copy.unlink()
    raw = raw_path.read_bytes()
    expected = bytearray(32)
    for offset, width, value, effect in REGISTERS:
        expected[offset:offset + width] = value.to_bytes(width, PROFILES[args.target][2])
    assert raw == expected, raw.hex()
    selected = json.loads(args.profile.read_text())
    compiler = profile(reference, args.target)
    compiler['transport'] = selected['transport']
    compiler['registers'] = [{'name': 'reg' + str(w * 8), 'address': hex(BASE + offset), 'width': w,
        'read_effect': effect, 'views': [{'name': 'scalar', 'type': 'word' + str(w * 8), 'offset': 0}]}
        for offset, w, _, effect in REGISTERS[:3]]
    cases = {
        'compiler': observe(root / 'compiler', args.target, reference, reference, compiler, raw, helper),
        'forge': observe(root / 'forge', args.target, original, sidecar, selected, raw, helper),
        'wrong-width': observe(root / 'wrong-width', args.target, original, sidecar, selected, raw, helper, True)}
    assert cases['compiler']['snapshots'] == cases['forge']['snapshots']
    assert all(c['warnings'] == cases['compiler']['warnings'] for c in cases.values())
    assert all(digest(Path(p)) == value for p, value in protected.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MMIO_WIDTHS', 'target': args.target,
        'scope': 'instrumented callbacks, not physical bus behavior or instruction execution',
        'preservedSha256': protected, 'cases': cases}, indent=4) + '\n')
    print('mmio-widths=PASS', args.target)


if __name__ == '__main__':
    main()

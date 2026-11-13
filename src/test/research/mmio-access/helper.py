#!/usr/bin/env python3
"""Exercise explicit MMIO snapshots against an instrumented remote peripheral."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import threading

from experiment import Device, Target, BASE, INITIAL, REPOSITORY
from layout import PROFILES


class ProfileTarget(Target):
    """Explicit test register packets; no instruction execution or CPU claim."""
    def __init__(self, device, backend, architecture):
        super().__init__(device, 0, 'word32' if backend == 'partial-reply' else backend)
        self.partial_reply = backend == 'partial-reply'
        self.architecture = architecture
        self.xml = None
        if architecture.startswith('mips'):
            groups = [('cpu', [*(f'r{i}' for i in range(32)), 'lo', 'hi', 'pc']),
                ('cp0', ['status', 'badvaddr', 'cause']),
                ('fpu', [*(f'f{i}' for i in range(32)), 'fcsr', 'fir'])]
            self.xml = '<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target>' + \
                '<architecture>mips:isa32r2</architecture>' + ''.join(
                    '<feature name="org.gnu.gdb.mips.' + group + '">' + ''.join(
                        '<reg name="' + register + '" bitsize="32"/>' for register in registers) + '</feature>'
                    for group, registers in groups) + '</target>'

    def reply(self, command):
        if self.xml is not None:
            if command.startswith('qSupported'):
                return 'PacketSize=4000;qXfer:features:read+'
            if command.startswith('qXfer:features:read:target.xml:'):
                offset, size = (int(v, 16) for v in command.rsplit(':', 1)[1].split(','))
                return ('l' if offset + size >= len(self.xml) else 'm') + self.xml[offset:offset + size]
            if command == 'g':
                return bytes(72 * 4).hex()
        response = super().reply(command)
        if self.partial_reply and command.startswith('m') and response != 'E01' and \
                BASE <= int(command[1:].split(',')[0], 16) < BASE + 8:
            response = response[:-2]
            self.requests[-1]['response'] = response
        return response


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile(sidecar, target):
    return {'schema': 1, 'sidecar_sha256': digest(sidecar),
        'architecture': 'i386:x86-64' if target == 'x86_64' else 'mips:isa32r2',
        'address_bits': 64 if target == 'x86_64' else 32, 'byteorder': PROFILES[target][2],
        'transport': {'id': 'instrumented-word32', 'evidence':
            'Source-modeled Target/Device in experiment.py: one aligned word32 callback per four-byte packet. No physical bus claim.'},
        'registers': [{'name': 'status', 'address': hex(BASE), 'width': 4, 'read_effect': 'read-clear',
            'views': [{'name': 'register', 'type': 'union Register', 'offset': 0},
                {'name': 'packed', 'type': 'struct ByteFields', 'offset': 0}]}]}


def run_case(root, original, sidecar, backend, target_name, helper, negative=None):
    name = negative or backend
    case = root / name
    case.mkdir()
    data = profile(sidecar, target_name)
    contract = 'instrumented-word32'
    if negative == 'unknown':
        data['registers'][0]['read_effect'] = 'unknown'
    elif negative == 'write-only':
        data['registers'][0]['read_effect'] = 'write-only'
    elif negative == 'stale':
        data['sidecar_sha256'] = '0' * 64
    elif negative == 'unaligned':
        data['registers'][0]['address'] = hex(BASE + 1)
    elif negative == 'wide-view':
        data['registers'][0]['views'][0]['type'] = 'struct Device'
    elif negative == 'transport':
        contract = 'unverified-transport'
    elif negative == 'byteorder':
        data['byteorder'] = 'big' if data['byteorder'] == 'little' else 'little'
    elif negative == 'architecture':
        data['architecture'] = 'unsupported-architecture'
    profile_path = case / 'profile.json'
    profile_path.write_text(json.dumps(data, indent=4) + '\n')
    byteorder = PROFILES[target_name][2]
    device = Device(INITIAL.to_bytes(4, byteorder) + (17).to_bytes(4, byteorder), byteorder)
    target = ProfileTarget(device, backend, data['architecture'] if negative != 'architecture'
        else profile(sidecar, target_name)['architecture'])
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(20)
        worker = threading.Thread(target=target.serve, args=(listener,))
        worker.start()
        commands = ['set pagination off', 'set confirm off', 'set auto-load off',
            'set debuginfod enabled off', 'set sysroot /',
            'set auto-solib-add off', 'file ' + json.dumps(str(original)),
            'symbol-file ' + json.dumps(str(sidecar)),
            'target remote 127.0.0.1:' + str(listener.getsockname()[1]),
            # Cache settings must not change this explicit single-packet path.
            'set mem inaccessible-by-default off', 'mem 0x40000000 0x40000008 ro 32 cache',
            'monitor load', 'source ' + str(helper),
            'forge-mmio load ' + json.dumps(str(profile_path)) + ' ' + json.dumps(str(sidecar)),
            'monitor snapshot', 'forge-mmio snapshot status ' + contract]
        if negative is None and backend == 'word32':
            commands += ['monitor second', 'forge-mmio snapshot status ' + contract]
        commands += ['detach']
        argv = ['gdb-multiarch', '-nx', '-nh', '-batch']
        for command in commands:
            argv += ['-ex', command]
        (case / 'command.json').write_text(json.dumps(argv, indent=4) + '\n')
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        finally:
            worker.join(timeout=22)
        assert not worker.is_alive() and not target.errors, target.errors
    (case / 'gdb.log').write_text(result.stdout + result.stderr)
    loader_warning = ('warning: Unable to find dynamic linker breakpoint function.\n'
        'GDB will be unable to debug shared library initializers\n'
        'and track explicitly loaded dynamic code.\n')
    warnings = []
    stderr = result.stderr
    if target_name.startswith('mips') and loader_warning in stderr:
        # This peripheral-only stub does not emulate a process or dynamic loader.
        # Main separately requires the identical warning on the compiler original.
        warnings.append(loader_warning)
        stderr = stderr.replace(loader_warning, '', 1)
    record = {'requests': target.requests, 'accesses': device.accesses, 'returnCode': result.returncode,
        'warnings': warnings}
    (case / 'trace.json').write_text(json.dumps(record, indent=4) + '\n')
    outputs = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{"address":')]
    assert not any(r['phase'] == 'load' for r in device.accesses)
    if negative:
        assert not device.accesses and not target.requests and not outputs, (name, record, result.stdout, result.stderr)
        expected = {'unknown': 'register read policy prohibits access', 'write-only': 'register read policy prohibits access',
            'stale': 'stale or mismatched MMIO sidecar', 'unaligned': 'unaligned or overflowing register',
            'wide-view': 'view extends beyond selected register', 'transport': 'explicit transport contract selection required',
            'byteorder': 'profile disagrees with ELF identity', 'architecture': 'target architecture mismatch'}
        assert stderr == expected[negative] + '\n' + ('load an MMIO profile first\n'
            if negative in ('stale', 'unaligned', 'byteorder', 'architecture') else ''), stderr
    elif backend == 'byte-split':
        assert len(target.requests) == len(device.accesses) == 1 and not device.accesses[0]['accepted'], record
        assert not outputs and 'no retry' in stderr, stderr
    elif backend == 'partial-reply':
        assert len(target.requests) == len(device.accesses) == 1 and device.accesses[0]['accepted'], record
        assert len(target.requests[0]['response']) == 6, record
        assert not outputs and 'no retry' in stderr and device.storage[:4] == bytes(4), stderr
    else:
        assert result.returncode == 0 and not stderr, result.stdout + stderr
        assert len(outputs) == len(target.requests) == len(device.accesses) == 2, record
        assert all(r['size'] == 4 for r in target.requests)
        assert all(r['width'] == 4 and r['address'] == hex(BASE) and r['accepted'] for r in device.accesses)
        assert [r['value'] for r in device.accesses] == [INITIAL, 0], record
        first = outputs[0]['views']
        assert first['register']['raw'] == INITIAL
        assert first['register']['flags'] == INITIAL
        fields = PROFILES[target_name][3]
        assert [first['register']['bits'][n] for n in ('a', 'b')] == fields[:2]
        assert first['register']['cross'] == dict(zip(('prefix', 'cross', 'sign', 'reserved'), fields[2:]))
        assert first['packed'] == dict(zip(('a', 'b'), fields[:2]))
        assert outputs[1]['views']['register']['raw'] == 0
        assert device.storage[4:] == (17).to_bytes(4, byteorder), 'adjacent register was read'
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--sidecar', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--target', choices=tuple(PROFILES), required=True)
    parser.add_argument('--helper', type=Path, default=REPOSITORY / 'support/mmio/forge_mmio.py')
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    original, sidecar, reference = args.original.resolve(), args.sidecar.resolve(), args.reference.resolve()
    before = {str(p): digest(p) for p in (original, sidecar, reference)}
    compiler_root = root / 'compiler'
    compiler_root.mkdir()
    helper = args.helper.resolve(strict=True)
    compiler = run_case(compiler_root, reference, reference, 'word32', args.target, helper)
    cases = {backend: run_case(root, original, sidecar, backend, args.target, helper)
        for backend in ('word32', 'byte-split', 'partial-reply')}
    for negative in ('unknown', 'write-only', 'stale', 'unaligned', 'wide-view', 'transport', 'byteorder', 'architecture'):
        cases[negative] = run_case(root, original, sidecar, 'word32', args.target, helper, negative)
    assert all(case['warnings'] == compiler['warnings'] for case in cases.values()), 'uncorroborated debugger warning'
    assert all(digest(Path(p)) == value for p, value in before.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MMIO_HELPER',
        'scope': 'loaded sidecar with instrumented RSP callbacks; no execution or physical bus claim', 'target': args.target,
        'preservedSha256': before, 'helperSha256': digest(helper),
        'compiler': compiler, 'cases': cases}, indent=4) + '\n')
    print('mmio-helper=PASS')


if __name__ == '__main__':
    main()

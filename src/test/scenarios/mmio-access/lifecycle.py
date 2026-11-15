#!/usr/bin/env python3
"""Check profile replacement and failed admissions without peripheral accesses."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import threading

from experiment import Device, INITIAL
from helper import ProfileTarget, digest, run_case
from layout import PROFILES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', choices=tuple(PROFILES), required=True)
    for name in ('original', 'sidecar', 'profile', 'reference', 'helper', 'results'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    original, sidecar, profile, reference, helper = (getattr(args, n).resolve(strict=True)
        for n in ('original', 'sidecar', 'profile', 'reference', 'helper'))
    protected = {str(p): digest(p) for p in (original, sidecar, profile, reference, helper)}
    compiler_root = root / 'compiler'
    compiler_root.mkdir()
    compiler = run_case(compiler_root, reference, reference, 'word32', args.target, helper)
    copy = root / 'symbols.dbg'
    copy.write_bytes(sidecar.read_bytes())
    selected = json.loads(profile.read_text())
    register = selected['registers'][0]
    assert register['name'] == 'status' and register['width'] == 4
    good = root / 'good.json'
    good.write_text(json.dumps(selected))
    cases = []

    def invalid(label, mutate, message):
        data = json.loads(good.read_text())
        mutate(data)
        path = root / (label + '.json')
        path.write_text(json.dumps(data))
        cases.append((path, message))

    invalid('duplicate-register', lambda d: d['registers'].append(d['registers'][0]), 'duplicate register name')
    invalid('duplicate-view', lambda d: d['registers'][0]['views'].append(d['registers'][0]['views'][0]), 'duplicate view name')
    invalid('boolean-width', lambda d: d['registers'][0].update(width=True), 'unsupported access width')
    invalid('missing-evidence', lambda d: d['transport'].update(evidence=''), 'transport evidence is required')
    invalid('empty-inventory', lambda d: d.update(registers=[]), 'invalid register inventory')
    invalid('overflow', lambda d: d['registers'][0].update(address=hex(1 << d['address_bits'])), 'unaligned or overflowing register')
    invalid('unknown-field', lambda d: d.update(unrecognized=True), 'invalid profile fields')
    duplicate = root / 'duplicate-key.json'
    duplicate.write_text(good.read_text().replace('"schema": 1', '"schema": 1, "schema": 1', 1))
    cases.append((duplicate, 'duplicate JSON key'))
    oversized = root / 'oversized.json'
    oversized.write_text(' ' * 65537)
    cases.append((oversized, 'MMIO profile exceeds 64 KiB'))
    unknown = json.loads(good.read_text())
    unknown['registers'][0]['read_effect'] = 'unknown'
    replacement = root / 'replacement.json'
    replacement.write_text(json.dumps(unknown))
    foreign = json.loads(good.read_text())
    foreign['registers'][0]['views'] = [{'name': 'builtin', 'type': 'unsigned int', 'offset': 0}]
    foreign_path = root / 'foreign.json'
    foreign_path.write_text(json.dumps(foreign))
    byteorder = PROFILES[args.target][2]
    device = Device(INITIAL.to_bytes(4, byteorder) + (17).to_bytes(4, byteorder), byteorder)
    target = ProfileTarget(device, 'word32', selected['architecture'])
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(20)
        worker = threading.Thread(target=target.serve, args=(listener,))
        worker.start()
        # Execute actual registered commands, including failed reloads that must
        # clear the previously selected profile. No monkeypatch of production code.
        script = root / 'controls.py'
        script.write_text('''import gdb, json
from pathlib import Path
checks = []
transcript = []
def command(text):
    output = gdb.execute(text, to_string=True)
    transcript.append({'command': text, 'output': output})
    return output
def reject(text, reason):
    try:
        command(text)
    except gdb.error as error:
        assert reason in str(error), str(error)
        checks.append(reason)
    else:
        raise AssertionError('command unexpectedly succeeded: ' + text)
''' + '\n'.join('command(' + repr(c) + ')' for c in (
            'set pagination off', 'set confirm off', 'set auto-load off', 'set debuginfod enabled off',
            'set sysroot /', 'set auto-solib-add off', 'file ' + json.dumps(str(original)),
            'symbol-file ' + json.dumps(str(copy)),
            'target remote 127.0.0.1:' + str(listener.getsockname()[1]),
            'monitor admission', 'source ' + str(helper))) + '\n' +
            'sidecar = ' + repr(str(copy)) + '\n' +
            'good = ' + repr(str(good)) + '\n' +
            'snapshot = ' + repr('forge-mmio snapshot status ' + selected['transport']['id']) + '\n' +
            '''def load(path):
    return 'forge-mmio load ' + json.dumps(str(path)) + ' ' + json.dumps(sidecar)
command(load(good))
printer_calls = []
class IntrusivePrinter:
    def to_string(self):
        gdb.selected_inferior().read_memory(0x40000000, 4)
        return 'unexpected peripheral traversal'
def printer(value):
    printer_calls.append(str(value.type))
    return IntrusivePrinter()
gdb.pretty_printers.append(printer)
''' + 'cases = ' + repr([(str(p), m) for p, m in cases]) + '\n' + '''for path, reason in cases:
    reject(load(path), reason)
    reject(snapshot, 'load an MMIO profile first')
    command(load(good))
''' + 'command(load(' + repr(str(replacement)) + '))\n' +
            "reject(snapshot, 'register read policy prohibits access')\n" +
            'command(load(' + repr(str(foreign_path)) + '))\n' +
            "reject(snapshot, 'view type belongs to a different debug object')\n" +
            '''command(load(good))
reject('forge-mmio snapshot missing ' + ''' + repr(selected['transport']['id']) + ''', 'unknown register')
before = Path(sidecar).read_bytes()
try:
    Path(sidecar).write_bytes(before + b'changed after profile load')
    reject(snapshot, 'stale or mismatched MMIO sidecar')
finally:
    Path(sidecar).write_bytes(before)
command('symbol-file')
reject(snapshot, 'profile sidecar must be loaded exactly once')
command('symbol-file ' + json.dumps(sidecar))
command(load(good))
command('monitor accepted')
sample = json.loads(command(snapshot))
assert sample['views']['register']['raw'] == ''' + str(INITIAL) + '''
assert sample['width'] == 4
assert not printer_calls, printer_calls
gdb.pretty_printers.remove(printer)
command('detach')
Path(''' + repr(str(root / 'gdb-result.json')) + ''').write_text(json.dumps({'checks': checks, 'sample': sample, 'transcript': transcript}))
print('mmio-lifecycle=PASS')
''')
        try:
            result = subprocess.run(['gdb-multiarch', '-nx', '-nh', '-batch', '-x', str(script)],
                capture_output=True, text=True, timeout=35)
        finally:
            worker.join(timeout=22)
        assert not worker.is_alive() and not target.errors, target.errors
    (root / 'gdb.log').write_text(result.stdout + result.stderr)
    loader_warning = ('warning: Unable to find dynamic linker breakpoint function.\n'
        'GDB will be unable to debug shared library initializers\n'
        'and track explicitly loaded dynamic code.\n')
    assert result.returncode == 0 and 'mmio-lifecycle=PASS' in result.stdout, result.stdout + result.stderr
    controls = json.loads((root / 'gdb-result.json').read_text())
    diagnostic = result.stderr + ''.join(row['output'] for row in controls['transcript'])
    if loader_warning in diagnostic:
        assert compiler['warnings'] == [loader_warning], 'uncorroborated dynamic-loader warning'
        diagnostic = diagnostic.replace(loader_warning, '')
    assert not any(word in diagnostic.lower() for word in ('warning:', 'error:', 'traceback')), diagnostic
    assert len(controls['checks']) == 23, controls
    assert len(target.requests) == len(device.accesses) == 1 and device.accesses[0]['phase'] == 'accepted'
    assert device.accesses[0]['width'] == 4 and device.accesses[0]['value'] == INITIAL
    assert device.storage == bytes(4) + (17).to_bytes(4, byteorder)
    assert all(digest(Path(p)) == value for p, value in protected.items())
    assert digest(copy) == digest(sidecar)
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_MMIO_LIFECYCLE', 'target': args.target,
        'checks': controls['checks'], 'requests': target.requests, 'callbacks': device.accesses,
        'compiler': compiler, 'preservedSha256': protected}, indent=4) + '\n')
    print('mmio-lifecycle=PASS', args.target)


if __name__ == '__main__':
    main()

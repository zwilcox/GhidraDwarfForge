#!/usr/bin/env python3
"""Compare exact-address and real GDB/QEMU checks on metadata-only corruptions."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess

HERE = Path(__file__).resolve().parent
artifact = runpy.run_path(str(HERE / 'cortex-m-artifact.py'))
runtime = runpy.run_path(str(HERE / 'cortex-m-runtime.py'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def controls(case, sidecar, output):
    output.mkdir(parents=True, exist_ok=False)
    protected = {p: digest(p) for p in (case / 'original.elf', case / 'reference.elf', sidecar,
        Path(str(sidecar) + '.c'))}
    image, dies, _ = artifact['inspect'](case, sidecar, output / 'baseline-addresses')
    baseline = runtime['debugger'](case, sidecar, output / 'baseline', 'forge')
    assert baseline['status'] == 'PASS'
    original = sidecar.read_bytes()
    info = image['sections']['.debug_info'][0][4]

    def attr(tag, name, attribute):
        row, = [r for r in dies if r['tag'] == tag and artifact['name'](r) == name]
        return row['attrs'][attribute]

    mutations = []
    def word(label, offset, before, after, phase, reason):
        assert struct.unpack_from('<I', original, offset)[0] == before
        changed = bytearray(original)
        struct.pack_into('<I', changed, offset, after)
        mutations.append((label, changed, phase, reason, {'offset': offset, 'before': before, 'after': after}))

    low = attr('DW_TAG_subprogram', 'cortex_compute', 'DW_AT_low_pc')
    value = artifact['number'](low, 'addr')
    word('function-entry', info + low['offset'], value, value + 2, 'offline', 'function address changed')
    for name, label, clear_bit, phase, reason in (
            ('cortex_odd_byte', 'odd-data-address', True, 'globals', 'odd data address changed'),
            ('cortex_initialized', 'global-address', False, 'globals', 'AssertionError'),
            ('cortex_exception_return', 'exception-global', False, 'exception-msp', 'exception return changed')):
        location = attr('DW_TAG_variable', name, 'DW_AT_location')['offset']
        assert original[info + location:info + location + 2] == bytes((5, 3)), 'not a DW_OP_addr expression'
        value = struct.unpack_from('<I', original, info + location + 2)[0]
        word(label, info + location + 2, value, value & ~1 if clear_bit else value + 4, phase, reason)
    table = image['sections']['.symtab'][0]
    reset = json.loads((case / 'labels.json').read_text())['Reset_Handler'] & ~1
    offsets = [at + 4 for at in range(table[4], table[4] + table[5], 16)
        if original[at + 12] & 15 == 2 and struct.unpack_from('<I', original, at + 4)[0] == reset | 1]
    offset, = offsets
    word('thumb-mode', offset, reset | 1, reset, 'offline', 'offline Thumb disassembly changed')
    line, payload = image['sections']['.debug_line']
    offsets = artifact['line_addresses'](payload)
    first, = [at for at in offsets if struct.unpack_from('<I', payload, at)[0] == reset]
    word('source-entry', line[4] + first, reset, reset + 2, 'offline', 'missing entry source mapping')
    results = []
    for label, changed, phase, reason, mutation in mutations:
        folder = output / label
        folder.mkdir()
        candidate = folder / 'firmware.dbg'
        candidate.write_bytes(changed)
        assert changed != original and len(changed) == len(original)
        address_rejected = False
        try:
            artifact['inspect'](case, candidate, folder / 'addresses')
        except AssertionError:
            address_rejected = True
        assert address_rejected, 'exact artifact oracle accepted mutation: ' + label
        checked = subprocess.run(['llvm-dwarfdump', '--verify', candidate], text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        (folder / 'llvm.txt').write_text(checked.stdout)
        assert checked.returncode == 0 and 'No errors.' in checked.stdout, (label, checked.stdout)
        rejected = False
        try:
            runtime['debugger'](case, candidate, folder / 'runtime', 'forge', Path(str(sidecar) + '.c'))
        except AssertionError:
            rejected = True
        observed = json.loads((folder / 'runtime/forge-gdb.json').read_text())
        if label == 'thumb-mode':
            # GDB's M-profile selection supplies independent Thumb evidence.
            # The exact symbol check must reject this copy; runtime success is
            # recorded, not misrepresented as sensitivity to that redundant bit.
            assert not rejected and observed['status'] == 'PASS', (label, observed)
        else:
            assert rejected and observed['status'] == 'FAIL' and observed['phase'] == phase, (label, observed)
            assert reason in observed.get('error', ''), (label, observed)
        assert all(digest(p) == before for p, before in protected.items()), 'control changed protected artifacts'
        results.append({'case': label, 'mutation': mutation, 'llvm': 'PASS', 'exactAddresses': 'REJECTED',
            'gdb': 'REJECTED' if rejected else 'PASS_REDUNDANT_M_PROFILE_THUMB_EVIDENCE',
            'phase': observed['phase'], 'reason': observed.get('error'), 'sha256': digest(candidate)})
    result = {'status': 'PASS', 'controls': results, 'protectedSha256': {str(p): v for p, v in protected.items()}}
    (output / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path)
    parser.add_argument('sidecar', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = controls(args.reference.resolve(), args.sidecar.resolve(), args.output.resolve())
    print('cortex-m-runtime-controls=PASS count=' + str(len(result['controls'])))


if __name__ == '__main__':
    main()

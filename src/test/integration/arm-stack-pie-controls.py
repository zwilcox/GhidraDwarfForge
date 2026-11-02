#!/usr/bin/env python3
"""Corrupt isolated PIE test copies and require exact runtime-oracle failures."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('driver', source / 'arm-stack-aggregates.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
facts = driver.load('elf', source / 'arm-thumb-mode-check.py')
contract = driver.load('contract', source / 'arm_stack_aggregate_contract.py')


def write(path, value):
    path.write_text(json.dumps(value, indent=4) + '\n')


def main(baseline):
    baseline = baseline.resolve(strict=True)
    profile = json.loads((baseline / 'profile.json').read_text())
    assert profile['role'] == 'pie' and profile['availabilityContract'] == 'audited-prefix'
    assert json.loads((baseline / 'result.json').read_text())['status'] == 'PASS'
    root = Path(tempfile.mkdtemp(prefix='pie-controls.', dir=baseline))
    files = ('calls.input', 'calls.reference', 'calls.dbg', 'calls.dbg.c', 'profile.json',
        'labels.json', 'instruction-inventory.json', 'parameter-locations.json')
    helpers = ('arm-stack-aggregates-gdb.py', 'arm-stack-aggregates-reference.py', 'arm_stack_aggregate_contract.py')
    protected = {str(baseline / name): driver.digest(baseline / name) for name in files}
    protected.update({str(source / name): driver.digest(source / name) for name in (*helpers, Path(__file__).name)})
    rows = []
    for control in ('load-bias', 'global-address', 'literal-pool', 'physical-carrier', 'early-gap', 'late-gap'):
        case = root / control
        case.mkdir()
        for name in files:
            shutil.copy2(baseline / name, case / name)
        for name in helpers:
            shutil.copy2(source / name, case / name)
        expected = None
        if control == 'load-bias':
            changed = dict(profile, elfEntry=profile['elfEntry'] + 4)
            write(case / 'profile.json', changed)
            expected = 'AssertionError()'
        elif control == 'global-address':
            labels = json.loads((case / 'labels.json').read_text())
            labels['seen_leading'] += 4
            write(case / 'labels.json', labels)
            expected = 'wrong PIC global address'
        elif control == 'literal-pool':
            # Modify a copied inferior's actual pool, leaving its compiler and
            # Forge symbol files untouched. Detection must read live memory.
            image = facts.elf(case / 'calls.input', allow_big_endian=True)
            inventory = json.loads((case / 'instruction-inventory.json').read_text())
            section = facts.section(image, '.text')['row']
            offset = section[4] + inventory['base_pair']['entry'] - section[3] + contract.literal_offset('base_pair', profile['order'])
            data = bytearray(image['data'])
            data[offset] ^= 1
            (case / 'calls.input').write_bytes(data)
            expected = 'wrong PIC global address'
        elif control == 'physical-carrier':
            locations = json.loads((case / 'parameter-locations.json').read_text())
            piece, = locations['base_pair']['a'][0]['pieces']
            assert piece['kind'] == 'register' and piece['register'] == 0
            piece['register'] = 2
            write(case / 'parameter-locations.json', locations)
            expected = 'raw carrier'
        else:
            path = case / 'arm_stack_aggregate_contract.py'
            text = path.read_text()
            before = "'pair': 40, 'packed': 40"
            assert text.count(before) == 1
            boundary = 36 if control == 'early-gap' else 44
            path.write_text(text.replace(before, "'pair': " + str(boundary) + ", 'packed': 40"))
            expected = 'location crosses required gap' if control == 'early-gap' else 'unexpected physical-location gap'
        command = ['bash', source / 'arm-pcs-profile-runtime.sh', case, 'forge', profile['qemu'],
            profile['gdb'], profile['gdbData'], case / 'arm-stack-aggregates-gdb.py']
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=90)
        (case / 'runner.log').write_text(result.stdout + result.stderr)
        observed = json.loads((case / 'forge-gdb.json').read_text())
        assert result.returncode != 0 and observed['status'] == 'FAIL' and expected in observed['error'], (control, observed.get('error'))
        termination = (case / 'forge.qemu.stderr').read_text()
        assert termination in ('', Path(profile['qemu']).name + ': QEMU: Terminated via GDBstub\n'), termination
        endpoint = dict(line.split('=', 1) for line in (case / 'forge.qemu.endpoint').read_text().splitlines())
        assert not Path(endpoint['socket']).exists() and not Path(endpoint['socket']).parent.exists()
        if control == 'load-bias':
            assert not observed['entry'] and 'loadBias' not in observed
        assert not (case / 'forge.qemu.status').exists(), 'failed oracle must not report normal completion'
        unchanged = set(files) - {'profile.json' if control == 'load-bias' else 'labels.json' if control == 'global-address'
            else 'calls.input' if control == 'literal-pool' else 'parameter-locations.json' if control == 'physical-carrier' else ''}
        assert all(driver.digest(case / name) == protected[str(baseline / name)] for name in unchanged)
        rows.append({'control': control, 'command': list(map(str, command)), 'exit': result.returncode,
            'error': observed['error'], 'termination': termination, 'socketRemoved': True})
    assert protected == {path: driver.digest(Path(path)) for path in protected}
    write(root / 'result.json', {'status': 'PASS', 'order': profile['order'], 'controls': rows, 'protected': protected})
    print('arm-stack-pie-controls=PASS cases=' + str(len(rows)) + ' ' + str(root))


if __name__ == '__main__':
    main(Path(sys.argv[1]))

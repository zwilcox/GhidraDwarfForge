#!/usr/bin/env python3
"""Require exact failures for copied shared-library oracle and live GOT corruptions."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('driver', source / 'arm-stack-aggregates.py')
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def write(path, value):
    path.write_text(json.dumps(value, indent=4) + '\n')


def replace(path, before, after):
    text = path.read_text()
    assert text.count(before) == 1, before
    path.write_text(text.replace(before, after))


def main(baseline):
    baseline = baseline.resolve(strict=True)
    profile = json.loads((baseline / 'profile.json').read_text())
    assert profile['layout'] == 'shared' and profile['availabilityContract'] == 'audited-prefix'
    assert json.loads((baseline / 'result.json').read_text())['status'] == 'PASS'
    root = Path(tempfile.mkdtemp(prefix='shared-controls.', dir=baseline))
    files = ('calls.input', 'calls.reference', 'calls.driver', 'calls.dbg', 'calls.dbg.c',
        'profile.json', 'labels.json', 'instruction-inventory.json', 'parameter-locations.json')
    helpers = ('arm-stack-aggregates-gdb.py', 'arm-stack-aggregates-reference.py',
        'arm_stack_aggregate_contract.py', 'arm_stack_shared_contract.py')
    protected = {str(baseline / name): driver.digest(baseline / name) for name in files}
    protected.update({str(source / name): driver.digest(source / name) for name in (*helpers, Path(__file__).name)})
    rows = []
    for control in ('load-bias', 'got-base', 'global-address', 'live-got', 'physical-carrier',
            'early-gap', 'late-gap', 'compiler-carrier'):
        case = root / control
        case.mkdir()
        for name in files:
            shutil.copy2(baseline / name, case / name)
        for name in helpers:
            shutil.copy2(source / name, case / name)
        variant = 'compiler' if control == 'compiler-carrier' else 'forge'
        changed = None
        if control in ('load-bias', 'got-base'):
            field = 'textAddress' if control == 'load-bias' else 'gotAddress'
            write(case / 'profile.json', dict(profile, **{field: profile[field] + 4}))
            expected = 'AssertionError()' if control == 'load-bias' else 'wrong shared GOT base'
            changed = 'profile.json'
        elif control == 'global-address':
            labels = json.loads((case / 'labels.json').read_text())
            labels['seen_leading'] += 4
            write(case / 'labels.json', labels)
            expected, changed = 'wrong shared GOT target', 'labels.json'
        elif control == 'live-got':
            replace(case / 'arm-stack-aggregates-gdb.py', "            code = memory(entry, inventory[name]['size'])",
                "            if name == 'base_pair':\n"
                "                slot = inventory[name]['gotSlots'][0]['slot'] + bias\n"
                "                old = int.from_bytes(memory(slot, 4), 'little')\n"
                "                gdb.selected_inferior().write_memory(slot, (old ^ 4).to_bytes(4, 'little'))\n"
                "            code = memory(entry, inventory[name]['size'])")
            expected = 'wrong shared GOT target'
        elif control == 'physical-carrier':
            locations = json.loads((case / 'parameter-locations.json').read_text())
            piece, = locations['base_pair']['a'][0]['pieces']
            assert piece['kind'] == 'register' and piece['register'] == 0
            piece['register'] = 2
            write(case / 'parameter-locations.json', locations)
            expected, changed = 'raw carrier', 'parameter-locations.json'
        elif control in ('early-gap', 'late-gap'):
            boundary = 44 if control == 'early-gap' else 52
            replace(case / 'arm_stack_shared_contract.py', "'pair': 48, 'packed': 48",
                "'pair': " + str(boundary) + ", 'packed': 48")
            expected = 'location crosses required gap' if control == 'early-gap' else 'unexpected physical-location gap'
        else:
            # A wrong current carrier must not silently excuse the compiler's
            # typed error. d6 holds source-known a=1, while b must equal2 in d7.
            replace(case / 'arm-stack-aggregates-reference.py', "register('d7')", "register('d6')")
            expected = "'base_floats', 56, 'b', 1.0, 2"
        command = ['bash', source / 'arm-stack-shared-runtime.sh', case, variant, profile['qemu'],
            profile['gdb'], profile['gdbData'], case / 'arm-stack-aggregates-gdb.py']
        outcome = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=90,
            env={**os.environ, 'FORGE_ARM32_SYSROOT': profile['sysroot'], 'FORGE_STACK_REFERENCE_CALIBRATION': '1'})
        (case / 'runner.log').write_text(outcome.stdout + outcome.stderr)
        observed = json.loads((case / (variant + '-gdb.json')).read_text())
        assert outcome.returncode != 0 and observed['status'] == 'FAIL' and expected in observed['error'], (control, observed.get('error'))
        termination = (case / (variant + '.qemu.stderr')).read_text()
        assert termination in ('', Path(profile['qemu']).name + ': QEMU: Terminated via GDBstub\n'), termination
        endpoint = dict(line.split('=', 1) for line in (case / (variant + '.qemu.endpoint')).read_text().splitlines())
        assert not Path(endpoint['socket']).exists() and not Path(endpoint['socket']).parent.exists()
        assert not (case / (variant + '.qemu.status')).exists()
        assert all(driver.digest(case / name) == protected[str(baseline / name)] for name in files if name != changed)
        rows.append({'control': control, 'variant': variant, 'command': list(map(str, command)),
            'exit': outcome.returncode, 'error': observed['error'], 'termination': termination, 'socketRemoved': True})
    assert protected == {path: driver.digest(Path(path)) for path in protected}
    write(root / 'result.json', {'status': 'PASS', 'controls': rows, 'protected': protected})
    print('arm-stack-shared-controls=PASS cases=' + str(len(rows)) + ' ' + str(root))


if __name__ == '__main__':
    main(Path(sys.argv[1]))

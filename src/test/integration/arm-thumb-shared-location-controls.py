#!/usr/bin/env python3
"""Require the shared Thumb runtime oracle to reject structurally valid wrong carriers."""
import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('helper', source / 'arm-thumb-mode-check.py')
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', type=Path)
    args = parser.parse_args()
    base = args.case.resolve(strict=True)
    assert json.loads((base / 'result.json').read_text())['status'] == 'PASS'
    labels = json.loads((base / 'labels.json').read_text())
    assert labels['shared'] and labels['thumb_add']['codeSize'] == 44
    before = {str(p): digest(p) for p in base.rglob('*') if p.is_file()}
    vdso = re.compile(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index')
    reference_warnings = (base / 'compiler-calls.stderr').read_text().splitlines()
    assert all(vdso.fullmatch(line) for line in reference_warnings), reference_warnings
    reference_warnings = Counter(vdso.sub('<oracle-vdso>', line) for line in reference_warnings)
    root = Path(tempfile.mkdtemp(prefix='shared-location-controls.', dir=base.parent))
    image = helper.elf(base / 'thumb.dbg')
    section = helper.section(image, '.debug_loclists')
    info = (base / 'forge-info.stdout').read_text()
    dies = re.split(r'(?=^\s*<\d+><[0-9a-f]+>:)', info, flags=re.M)
    owner, = [i for i, die in enumerate(dies) if 'DW_TAG_subprogram' in die and
        re.search(r'DW_AT_name\s*:.*\brecovered_thumb_add\s*$', die, re.M)]
    children = []
    for die in dies[owner + 1:]:
        depth = re.match(r'\s*<(\d+)>', die)
        if depth and int(depth[1]) <= 1:
            break
        children.append(die)
    offsets = {}
    for name in ('left', 'right'):
        formal, = [d for d in children if 'DW_TAG_formal_parameter' in d and
            re.search(r'DW_AT_name\s*:.*\b' + name + r'\s*$', d, re.M)]
        location = re.search(r'DW_AT_location\s*:\s*(0x[0-9a-f]+) \(location list\)', formal)
        assert location
        offsets[name] = int(location[1], 16)
    # All entries use DW_LLE_start_end with 32-bit addresses and short expr lengths.
    # Validate the exact selected expression before changing its final carrier byte.
    mutation_offsets = {'wrong-right-slot': offsets['right'] + 12 + 10 + 2,
        'wrong-left-register': offsets['left'] + 12 + 10 + 1}
    expected = {'wrong-right-slot': (b'\x92\x0d\x00', 4), 'wrong-left-register': (b'\x90\x01', 0)}
    rows = []
    for variant in ('positive', 'wrong-right-slot', 'wrong-left-register'):
        case = root / variant
        case.mkdir()
        (case / 'empty-debug').mkdir()
        for leaf in ('thumb.stripped', 'thumb.reference', 'thumb.driver', 'thumb.dbg.c',
                'labels.json', 'compiler-calls.json'):
            shutil.copy2(base / leaf, case / leaf)
        payload = bytearray(image['data'])
        if variant != 'positive':
            at = mutation_offsets[variant]
            expression, replacement = expected[variant]
            assert section['data'][at - len(expression) + 1:at + 1] == expression
            payload[section['row'][4] + at] = replacement
        (case / 'thumb.dbg').write_bytes(payload)
        check = subprocess.run(['llvm-dwarfdump', '--verify', str(case / 'thumb.dbg')], capture_output=True, timeout=30)
        (case / 'llvm.stdout').write_bytes(check.stdout)
        (case / 'llvm.stderr').write_bytes(check.stderr)
        assert check.returncode == 0 and not check.stderr and b'No errors.' in check.stdout
        sysroot = os.environ.get('FORGE_ARM32_SYSROOT', '/usr/arm-linux-gnueabihf')
        command = ['bash', '-c', '''set -euo pipefail
source "$1"
trap qemu_socket_cleanup EXIT
qemu_socket_start "$2" qemu-arm-static "$3" "$4"
export FORGE_THUMB_REMOTE="$qemu_socket_path"
shift 4
"$@"
qemu_socket_wait
''', 'shared-location-control', str(source / 'qemu-socket.sh'), str(case / 'runtime.qemu'), sysroot,
            str(case / 'thumb.driver'), 'timeout', '60s', 'gdb-multiarch', '-q', '-nx', '-batch',
            '-ex', 'set pagination off', '-ex', 'set confirm off', '-ex', 'set debuginfod enabled off',
            '-ex', 'set auto-solib-add off', '-ex', 'set debug-file-directory ' + str(case / 'empty-debug'),
            '-ex', 'set sysroot ' + sysroot, '-ex', 'set substitute-path ' + str(base) + ' ' + str(case),
            '-ex', 'file ' + str(case / 'thumb.stripped'), '-ex', 'symbol-file ' + str(case / 'thumb.dbg'),
            '-x', str(source / 'arm-thumb-mode-gdb.py')]
        env = os.environ.copy()
        env.update(FORGE_THUMB_CASE=str(case), FORGE_THUMB_VARIANT='forge', FORGE_THUMB_PHASE='calls')
        (case / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
        run = subprocess.run(command, env=env, capture_output=True, timeout=90)
        (case / 'runtime.stdout').write_bytes(run.stdout)
        (case / 'runtime.stderr').write_bytes(run.stderr)
        record = json.loads((case / 'forge-calls.json').read_text())
        diagnostics = run.stderr.decode().splitlines()
        if variant == 'positive':
            assert run.returncode == 0 and record['status'] == 'PASS', record
        else:
            stop = 'after-right-write-0' if variant == 'wrong-right-slot' else 'after-register-write-0'
            assert run.returncode != 0 and record['status'] == 'FAIL' and record['error'] == 'AssertionError()', record
            assert record['stops'][-1]['label'] == stop, record
            assert diagnostics[-2:] == ["Python Exception <class 'AssertionError'>: ", 'Error occurred in Python.'], diagnostics
            diagnostics = diagnostics[:-2]
        assert all(vdso.fullmatch(line) for line in diagnostics), diagnostics
        assert Counter(vdso.sub('<oracle-vdso>', line) for line in diagnostics) == reference_warnings
        emulator_errors = (case / 'runtime.qemu.stderr').read_text()
        # Failed assertions quit GDB while the inferior is stopped. The remote
        # kill packet produces this exact expected QEMU termination diagnostic.
        assert emulator_errors in (('',) if variant == 'positive' else
            ('', 'qemu-arm-static: QEMU: Terminated via GDBstub\n')), emulator_errors
        rows.append({'variant': variant, 'status': record['status'], 'lastStop': record['stops'][-1],
            'artifactSha256': digest(case / 'thumb.dbg')})
    assert all(digest(Path(p)) == sha for p, sha in before.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'cases': rows, 'baseUnchanged': True}, indent=4) + '\n')
    print('arm-thumb-shared-location-controls=PASS ' + str(root))


if __name__ == '__main__':
    main()

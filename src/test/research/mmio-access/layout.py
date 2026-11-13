#!/usr/bin/env python3
"""Compiler/raw-byte MMIO layout oracles; no target execution or Forge claim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REPOSITORY = Path(__file__).resolve().parents[4]
# Explicit compiler ABI profiles, not a rule for arbitrary C bitfield layouts.
PROFILES = {
    'x86_64': ('gcc', 'objcopy', 'little', [5, 17, 13, 10, -1, 42405]),
    'mips32be': ('mips-linux-gnu-gcc', 'mips-linux-gnu-objcopy', 'big', [5, 5, 41, 52, -3, 57997]),
    'mips32le': ('mipsel-linux-gnu-gcc', 'mipsel-linux-gnu-objcopy', 'little', [5, 17, 13, 10, -1, 42405]),
}


def observe(root, elf, name, sidecar=None, require_qualifiers=True):
    script = root / (name + '.gdb')
    script.write_text('set pagination off\nset confirm off\nset auto-load off\n'
        'set auto-solib-add off\nfile ' + json.dumps(str(elf)) + '\n' +
        ('symbol-file ' + json.dumps(str(sidecar)) + '\n' if sidecar else '') +
        'ptype peripheral\npython\n'
        'import json\n'
        'p=gdb.parse_and_eval("peripheral")\n'
        's=p["status"]\n'
        'fields=[int(s["bits"]["a"]),int(s["bits"]["b"])]\n'
        'fields += [int(s["cross"][n]) for n in ("prefix","cross","sign","reserved")]\n'
        'record={"address":int(p.address),"fields":fields,"raw":int(s["raw"]),'
        '"counter":int(p["counter"]),"packed":[int(s["byte"][n]) for n in ("a","b")],'
        '"widths":[gdb.lookup_type(n).sizeof for n in '
        '("unsigned int","struct ByteFields","union Register","struct Device")],'
        '"unionOffsets":[f.bitpos for f in gdb.lookup_type("union Register").fields()],'
        '"counterOffset":int(p["counter"].address)-int(p.address),'
        '"flagValues":[int(gdb.parse_and_eval(n)) for n in ("STATUS_READY","STATUS_BUSY","STATUS_ERROR")] }\n'
        'print("MMIO_JSON="+json.dumps(record,sort_keys=True))\nend\nquit\n')
    completed = subprocess.run(['gdb-multiarch', '-nx', '-nh', '-batch', '-x', str(script)],
        capture_output=True, text=True, timeout=30)
    (root / (name + '.log')).write_text(completed.stdout + completed.stderr)
    assert completed.returncode == 0, completed.stderr
    rows = [line.removeprefix('MMIO_JSON=') for line in completed.stdout.splitlines()
        if line.startswith('MMIO_JSON=')]
    assert len(rows) == 1, completed.stdout + completed.stderr
    if require_qualifiers:
        assert 'const volatile union Register status' in completed.stdout
    return json.loads(rows[0])


def expected(fields):
    return {'address': 0x40000000, 'fields': fields, 'raw': 0xa5a5e28d, 'counter': 17,
        'packed': fields[:2], 'widths': [4, 1, 4, 8], 'unionOffsets': [0] * 5,
        'counterOffset': 4, 'flagValues': [1, 8, 128]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=tuple(PROFILES), default=list(PROFILES))
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source = REPOSITORY / 'src/test/fixtures/mmio-registers.c'
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    results = {}
    for name in args.targets:
        compiler, objcopy, byte_order, fields = PROFILES[name]
        case = root / name
        case.mkdir()
        elf = case / 'reference.elf'
        command = [compiler, '-g', '-gdwarf-5', '-O0', '-fno-pie', '-no-pie',
            '-Wall', '-Wextra', '-Werror', '-Wl,--section-start=.mmio=0x40000000', str(source), '-o', str(elf)]
        subprocess.run(command, check=True)
        (case / 'compile-command.json').write_text(json.dumps(command, indent=4) + '\n')
        original = hashlib.sha256(elf.read_bytes()).hexdigest()
        verification = subprocess.run(['llvm-dwarfdump', '--verify', str(elf)], capture_output=True, text=True)
        (case / 'llvm.log').write_text(verification.stdout + verification.stderr)
        assert verification.returncode == 0 and 'No errors.' in verification.stdout
        headers = subprocess.check_output(['readelf', '-hSW', str(elf)], text=True)
        (case / 'readelf.log').write_text(headers)
        raw = case / 'registers.bin'
        copy = case / 'inspection-copy.elf'
        subprocess.run([objcopy, '--dump-section', '.mmio=' + str(raw), str(elf), str(copy)], check=True)
        copy.unlink()
        assert raw.read_bytes() == (0xa5a5e28d).to_bytes(4, byte_order) + (17).to_bytes(4, byte_order)
        observation = observe(case, elf, 'compiler')
        assert observation == expected(fields), (name, observation, expected(fields))
        # Same type metadata, wrong register bytes: ptype must not be the oracle.
        changed = bytearray(raw.read_bytes())
        changed[0] ^= 0x20
        changed_raw = case / 'changed-register.bin'
        changed_raw.write_bytes(changed)
        corrupt = case / 'changed-register.elf'
        subprocess.run([objcopy, '--update-section', '.mmio=' + str(changed_raw), str(elf), str(corrupt)], check=True)
        rejected = observe(case, corrupt, 'changed-register')
        assert rejected['widths'] == observation['widths'] and rejected['unionOffsets'] == observation['unionOffsets']
        assert rejected['fields'] != fields and rejected['raw'] != observation['raw']
        assert hashlib.sha256(elf.read_bytes()).hexdigest() == original
        results[name] = {'status': 'PASS_COMPILER_LAYOUT', 'referenceSha256': original,
            'compiler': subprocess.check_output([compiler, '--version'], text=True).splitlines()[0],
            'values': observation, 'changedBytesControl': 'REJECTED_BY_VALUES'}
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    (root / 'result.json').write_text(json.dumps({'scope': 'compiler/static memory only',
        'sourceSha256': source_hash, 'profiles': results}, indent=4) + '\n')
    print('mmio-layout-reference=PASS profiles=' + ','.join(results))


if __name__ == '__main__':
    main()

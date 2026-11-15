#!/usr/bin/env python3
"""Compare PT_DYNAMIC research inventories against independent compiler section tables."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from inventory import Inventory, Unsupported

source = Path(__file__).resolve().parent
repository = source.parents[3]
spec = importlib.util.spec_from_file_location('elf_support',
    repository / 'src/test/integration/retained-function-aliases-export.py')
elf_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_support)


def sectionless(original, output):
    data = bytearray(original.read_bytes())
    wide, order = data[4] == 2, '<' if data[5] == 1 else '>'
    struct.pack_into(order + ('Q' if wide else 'I'), data, 40 if wide else 32, 0)
    struct.pack_into(order + 'HH', data, 60 if wide else 48, 0, 0)
    output.write_bytes(data)
    output.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='inventory.', dir=args.output.resolve()))
    fixture = root / 'fixture.c'
    fixture.write_text('int exported(int value) { return value + 7; }\n'
        'int main(void) { return exported(19) != 26; }\n')
    records = []
    protected = {str(fixture): hashlib.sha256(fixture.read_bytes()).hexdigest()}
    for target, cc in (('x86_64', 'gcc'), ('aarch64', 'aarch64-linux-gnu-gcc'),
            ('mips32be', 'mips-linux-gnu-gcc'), ('mips32le', 'mipsel-linux-gnu-gcc')):
        for style in (('sysv',) if target.startswith('mips') else ('gnu', 'sysv', 'both')):
            for exported in (False, True):
                for role in ('exec', 'pie'):
                    case = root / f'{target}.{style}.{exported}.{role}'
                    case.mkdir()
                    original, binary = case / 'original', case / 'sectionless'
                    command = [cc, '-O1', '-g', '-Wl,--hash-style=' + style,
                        *(['-Wl,--export-dynamic'] if exported else []),
                        *(['-fno-pie', '-no-pie'] if role == 'exec' else ['-fPIE', '-pie']),
                        str(fixture), '-o', str(original)]
                    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                    (case / 'compile.json').write_text(json.dumps(command, indent=4) + '\n')
                    (case / 'compile.stdout').write_bytes(result.stdout)
                    (case / 'compile.stderr').write_bytes(result.stderr)
                    assert result.returncode == 0 and not result.stderr
                    sectionless(original, binary)
                    protected.update({str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (original, binary)})
                    _, _, sections = elf_support.elf(original)
                    table, payload = sections['.dynsym']
                    count = table[5] // table[9]
                    row = {'target': target, 'style': style, 'exports': exported,
                        'role': role, 'originalCount': count, 'case': str(case)}
                    try:
                        inventory = Inventory(binary)
                    except Unsupported as error:
                        assert style == 'gnu' and not exported and 'empty GNU hash' in str(error), str(error)
                        assert count > 1  # Counterexample to treating symoffset=1 as a count.
                        row.update(status='EXPLICIT_COUNT_UNAVAILABLE', diagnostic=str(error))
                    else:
                        assert inventory.count == count and inventory.raw == payload
                        assert inventory.strings == sections['.dynstr'][1]
                        row.update(status='EXACT_INVENTORY_MATCH', sources=inventory.counts)
                    records.append(row)
    # A real TLS definition is deliberately rejected until a TLS-relative mapping
    # has separate evidence. It must never be mapped as an ordinary virtual address.
    tls = root / 'tls.c'
    tls.write_text('__thread int thread_value = 7;\nint *address(void) { return &thread_value; }\n')
    original, binary = root / 'tls.so', root / 'tls.sectionless.so'
    subprocess.run(['gcc', '-shared', '-fPIC', '-Wl,--hash-style=both', str(tls), '-o', str(original)], check=True)
    sectionless(original, binary)
    try:
        Inventory(binary)
    except Unsupported as error:
        assert str(error) == 'defined TLS requires TLS-specific mapping'
    else:
        raise AssertionError('TLS was given a guessed virtual allocation')
    assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == h for p, h in protected.items())
    receipt = {'status': 'RESEARCH_COUNT_ORACLES_PASS', 'cases': records,
        'tls': 'explicit unsupported mapping', 'protected': protected}
    (root / 'result.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print(root)


if __name__ == '__main__':
    main()

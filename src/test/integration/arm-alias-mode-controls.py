#!/usr/bin/env python3
"""Reject wrong alias mode tags in sectionless GDB fixtures with no original mapping symbols."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('elf_support', source / 'retained-function-aliases-export.py')
elf_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_support)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cases', type=Path, nargs='+')
    parser.add_argument('--function-index', choices=(0, 1), type=int, default=0)
    parser.add_argument('--results-root', type=Path, default=repository / 'build/test-results/arm-alias-mode-controls')
    args = parser.parse_args()
    args.results_root.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='run.', dir=args.results_root.resolve()))
    print(root, flush=True)
    cases = [case.resolve(strict=True) for case in args.cases]
    assert len(cases) == len(set(cases))
    results = []
    for ordinal, base in enumerate(cases):
        result = json.loads((base / 'result.json').read_text())
        assert result['status'] == 'PASS'
        metadata = json.loads((base / 'metadata.json').read_text())
        assert metadata['target'] == 'arm32' and metadata['armMode'] in ('arm', 'thumb', 'mixed')
        with (base / 'aliases.input').open('rb') as stream:
            header = stream.read(52)
        assert header[:6] == b'\x7fELF\x01\x01' and struct.unpack_from('<I', header, 32)[0] == 0
        protected = [p for p in base.rglob('*') if p.is_file()]
        protected += [Path(__file__), source / 'local-symbol-merge-gdb.py', source / 'local-symbol-merge-gdb.sh',
            source / 'retained-function-aliases-export.py', source / 'qemu-socket.sh', source / 'elf-layout-gdb-oracle.sh']
        before = {str(p): digest(p) for p in protected}
        case = root / str(ordinal)
        case.mkdir()
        (case / 'protected-before.json').write_text(json.dumps(before, indent=4) + '\n')
        for name in ('aliases.input', 'aliases.dbg', 'aliases.dbg.c'):
            shutil.copy2(base / name, case / name)
        metadata['input'] = str(case / 'aliases.input')
        (case / 'metadata.json').write_text(json.dumps(metadata, indent=4) + '\n')
        ident, header, sections = elf_support.elf(case / 'aliases.dbg')
        assert ident[4:6] == bytes((1, 1)) and header[1] == 40
        table, records = sections['.symtab']
        strings = sections['.strtab'][1]
        first = metadata['functions'][args.function_index]
        selected = []
        for index in range(table[5] // 16):
            name, value, size, info, other, section = struct.unpack_from('<IIIBBH', records, index * 16)
            if strings[name:].split(b'\0', 1)[0].decode() == first['original']:
                assert info == 2 and other == 0 and section != 0 and value == first['elfSymbolValue']
                selected.append((index, value))
        (index, value), = selected
        with (case / 'aliases.dbg').open('r+b') as output:
            output.seek(table[4] + index * 16 + 4)
            output.write(struct.pack('<I', value ^ 1))
        compiler_log = Path(result['baseCase']) / 'compiler-gdb.log'
        command = ['bash', str(source / 'local-symbol-merge-gdb.sh'), str(repository), str(case), 'arm32', str(compiler_log)]
        (case / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
        completed = subprocess.run(command, capture_output=True, timeout=60)
        (case / 'driver.stdout').write_bytes(completed.stdout)
        (case / 'driver.stderr').write_bytes(completed.stderr)
        log = (case / 'forge-gdb.log').read_text()
        assert completed.returncode != 0 and 'check_instructions' in log and 'AssertionError' in log, log
        assert 'retained-function-aliases-gdb=forge PASS' not in log
        after = {str(p): digest(p) for p in protected}
        assert before == after
        (case / 'protected-after.json').write_text(json.dumps(after, indent=4) + '\n')
        results.append({'status': 'WRONG_MODE_REJECTED_BEFORE_CONTINUE', 'base': str(base), 'case': str(case),
            'armMode': metadata['armMode'], 'role': metadata['role'], 'symbol': first['original'],
            'originalValue': value, 'changedValue': value ^ 1, 'exitCode': completed.returncode})
        print('wrong-mode-rejected=' + str(base), flush=True)
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'cases': results}, indent=4) + '\n')


if __name__ == '__main__':
    main()

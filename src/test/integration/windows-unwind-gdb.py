#!/usr/bin/env python3
"""Consume native Windows GUI unwind artifacts with Linux validators and GDB."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys


def snapshot(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob('*') if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('incoming', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    source, = [path for path in args.incoming.glob('run.*') if path.is_dir()]
    record = dict(line.split('=', 1) for line in (source / 'result.txt').read_text().splitlines())
    assert record['windows-unwind-structural-validation'] == 'PASS'
    before = snapshot(source)
    assert record['source-fixture-sha256'].lower() == before['readonly/fixture']
    assert record['compiler-reference-sha256'].lower() == before['compiler-reference']
    work = args.output.resolve()
    shutil.copytree(source, work)
    assert snapshot(work) == before
    original = work / 'readonly/fixture'
    original.chmod(0o755)
    with (work / 'consumer.log').open('w') as stream:
        subprocess.run([sys.executable, str(Path(__file__).with_name('gui-unwind-evidence.py')),
            str(work), str(work / 'compiler-reference'), '--target', 'x86_64', '--dwarfdump', args.dwarfdump],
            stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=600)
    assert json.loads((work / 'unwind-result.json').read_text())['status'] == 'PASS_GUI_UNWIND'
    assert snapshot(source) == before
    # Consumer diagnostics may add files, but none of the transported evidence
    # or Windows-generated sidecars, sources and reports may be rewritten.
    after = snapshot(work)
    assert all(after[name] == digest for name, digest in before.items())
    (work / 'transport.json').write_text(json.dumps({'status': 'PASS_WINDOWS_UNWIND_GDB',
        'transportedSha256': before}, indent=4) + '\n')
    print('windows-unwind-gdb=PASS')


if __name__ == '__main__':
    main()

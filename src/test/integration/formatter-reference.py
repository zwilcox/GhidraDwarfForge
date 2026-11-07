#!/usr/bin/env python3
"""Build independent Linux ELF inputs for the native Windows formatter producer."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    fixture = Path(__file__).resolve().parents[1] / 'fixtures/formatter-values.c'
    records = []
    for role in ('exec', 'pie'):
        work = root / role
        work.mkdir()
        reference, original = work / 'compiler-reference', work / 'original'
        options = ['-fno-pie', '-no-pie'] if role == 'exec' else ['-fPIE', '-pie']
        command = ['gcc', '-gdwarf-5', '-O0', *options, str(fixture), '-o', str(reference)]
        (work / 'compiler-command.json').write_text(json.dumps(command, indent=4) + '\n')
        subprocess.run(command, check=True)
        shutil.copy2(reference, original)
        subprocess.run(['strip', '--strip-all', str(original)], check=True)
        symbols = {}
        for line in subprocess.check_output(['readelf', '-Ws', str(reference)], text=True).splitlines():
            fields = line.split()
            if len(fields) >= 8 and fields[-1].startswith('forge_'):
                symbols[fields[-1]] = fields[1]
        assert 'forge_formatter_marker' in symbols and len(symbols) >= 16
        mapping = work / 'compiler-symbols.json'
        mapping.write_text(json.dumps(symbols, indent=4) + '\n')
        records.append({'role': role, 'sha256': {path.name: digest(path) for path in (reference, original, mapping)}})
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_FORMATTER_COMPILER_INPUTS',
        'fixtureSha256': digest(fixture), 'artifacts': records,
        'compiler': subprocess.check_output(['gcc', '--version'], text=True).splitlines()[0]}, indent=4) + '\n')
    print('formatter-reference=PASS exec,pie')


if __name__ == '__main__':
    main()

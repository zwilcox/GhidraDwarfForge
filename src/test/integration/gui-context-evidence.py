#!/usr/bin/env python3
"""Compare independent line rows from the actual Script Manager context choices."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--readelf', default='readelf')
    args = parser.parse_args()
    projections, results = {}, {}
    for mode in ('off', 'assembly', 'p-code', 'both'):
        work = args.root / mode
        source = (work / 'output/fixture.dbg.c').read_text().splitlines()
        result = subprocess.run([args.readelf, '--debug-dump=decodedline', str(work / 'output/fixture.dbg')],
            capture_output=True, text=True, check=True)
        assert not result.stderr and not re.search(r'warning:|error:', result.stdout, re.I)
        (work / 'decodedline.txt').write_text(result.stdout)
        comments = set()
        for index, row in enumerate(source):
            if row.startswith('/* Ghidra instruction context '):
                end = index
                while end < len(source) and source[end].startswith('/* ') and source[end].endswith(' */'):
                    comments.add(end + 1)
                    end += 1
        assert bool(comments) == (mode != 'off')
        rows = [(int(m[2], 16), int(m[1])) for m in re.finditer(r'(?m)^\S+\s+(\d+)\s+(0x[0-9a-fA-F]+)\b', result.stdout)]
        assert rows and all(line not in comments for _, line in rows)
        projections[mode] = [(address, source[line - 1]) for address, line in rows]
        assert projections[mode] == projections['off'], 'GUI context changed executable source mapping'
        results[mode] = {'contextRows': len(comments), 'executableRows': len(rows)}
    (args.root / 'line-evidence.json').write_text(json.dumps({'status': 'PASS', 'modes': results}, indent=4) + '\n')
    print('gui-context-line-evidence=PASS')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Require native Windows pipe EOF, accounting and I/O failure regressions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--results', required=True, type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('these regressions require native Windows')
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[3]
    fixture = repo / 'src/test/native/windows-supervisor-pipe-eof.c'
    production = repo / 'native/supervisor/forge-supervisor-windows.c'
    compiler = args.compiler.resolve(strict=True)
    environment = dict(os.environ)
    environment['PATH'] = str(compiler.parent) + os.pathsep + environment.get('PATH', '')
    executable = root / 'pipe-regression.exe'
    command = [str(compiler), '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-municode', '-static-libgcc', str(fixture), '-o', str(executable)]
    with (root / 'compile.log').open('wb') as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, env=environment,
            check=True, timeout=60)
    cases = []
    report = {'productionSha256': hashlib.sha256(production.read_bytes()).hexdigest(),
        'fixtureSha256': hashlib.sha256(fixture.read_bytes()).hexdigest(),
        'compileCommand': command, 'cases': cases, 'status': 'FAIL'}
    try:
        for mode in ('race', 'data', 'capped', 'bad-read', 'bad-log'):
            with (root / (mode + '.stdout')).open('wb') as out, \
                    (root / (mode + '.stderr')).open('wb') as err:
                result = subprocess.run([str(executable), mode, str(root / (mode + '.bin'))],
                    stdout=out, stderr=err, timeout=20, env=environment)
            cases.append({'mode': mode, 'exit': result.returncode})
            if result.returncode != 0:
                raise AssertionError('Windows pipe regression failed: ' + mode)
        report['status'] = 'PASS'
    finally:
        (root / 'result.json').write_text(json.dumps(report, indent=4) + '\n')
    print('windows-supervisor-pipe=PASS cases=' + str(len(cases)))


if __name__ == '__main__':
    main()

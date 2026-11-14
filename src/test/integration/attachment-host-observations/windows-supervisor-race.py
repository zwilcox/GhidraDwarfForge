#!/usr/bin/env python3
"""Bounded diagnostic probe for the native Windows supervisor flood failure."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def instrument(original):
    source = original
    changes = [
        ('if (GetLastError() != ERROR_BROKEN_PIPE) return false;',
         'if (GetLastError() != ERROR_BROKEN_PIPE) { fprintf(stderr, "peek-error=%lu\\n", (unsigned long)GetLastError()); return false; }'),
        ('if (!ReadFile(output->pipe, bytes, available < sizeof(bytes) ? available : sizeof(bytes), &count, NULL)) return false;',
         'if (!ReadFile(output->pipe, bytes, available < sizeof(bytes) ? available : sizeof(bytes), &count, NULL)) { fprintf(stderr, "read-error=%lu available=%lu count=%lu\\n", (unsigned long)GetLastError(), (unsigned long)available, (unsigned long)count); return false; }'),
        ('if (!write_all(output->log, bytes, keep)) return false;',
         'if (!write_all(output->log, bytes, keep)) { fprintf(stderr, "write-error=%lu\\n", (unsigned long)GetLastError()); return false; }'),
    ]
    for before, after in changes:
        if source.count(before) != 1:
            raise RuntimeError('diagnostic anchor changed: ' + before)
        source = source.replace(before, after)
    source = source.replace('reason = "internal_error"; cleanup_ok = false;',
        'fprintf(stderr, "internal-line=%d error=%lu\\n", __LINE__, (unsigned long)GetLastError()); reason = "internal_error"; cleanup_ok = false;')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        raise RuntimeError('run this diagnostic on native Windows')
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    original = Path('native/supervisor/forge-supervisor-windows.c').read_text()
    source = instrument(original)
    probe = root / 'supervisor-diagnostic.c'
    probe.write_text(source)
    helper = root / 'supervisor-diagnostic.exe'
    environment = dict(os.environ)
    environment['PATH'] = str(Path(args.compiler).resolve().parent) + os.pathsep + environment.get('PATH', '')
    subprocess.run([args.compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
        '-municode', '-static-libgcc', str(probe), '-o', str(helper)], check=True, timeout=60, env=environment)
    child = root / 'flood.py'
    child.write_text('import os\nwhile True:\n    os.write(1, b"x" * 16384)\n')
    started = time.monotonic()
    cases = []
    failure = None
    for index in range(500):
        if time.monotonic() - started >= 90:
            break
        with tempfile.TemporaryDirectory(prefix='case-', dir=root) as temporary:
            case = Path(temporary)
            status = case / 'status.json'
            command = [str(helper), '5000', '4096', str(status), str(case / 'tool.stdout'),
                str(case / 'tool.stderr'), '--', sys.executable, str(child)]
            with (case / 'helper.stdout').open('wb') as out, (case / 'helper.stderr').open('wb') as err:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=out, stderr=err)
                try:
                    code = process.wait(timeout=12)
                finally:
                    process.stdin.close()
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            record = json.loads(status.read_text()) if status.exists() else None
            diagnostic = (case / 'helper.stderr').read_text()
            ok = code == 20 and record is not None and record['reason'] == 'output_limit' and record['cleanupComplete']
            cases.append({'index': index, 'exit': code, 'status': record, 'diagnostic': diagnostic})
            if not ok:
                failure = index
                for file in case.iterdir():
                    if file.is_file():
                        (root / ('failed-' + file.name)).write_bytes(file.read_bytes())
                break
    result = {'status': 'REPRODUCED' if failure is not None else 'NOT_OBSERVED',
        'sourceSha256': hashlib.sha256(original.encode()).hexdigest(),
        'elapsedSeconds': round(time.monotonic() - started, 3), 'cases': cases}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    print(json.dumps(result, indent=4))


if __name__ == '__main__':
    main()

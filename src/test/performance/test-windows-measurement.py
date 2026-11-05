#!/usr/bin/env python3
"""Native Windows accounting controls; a cross-compile is not a passing test."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('helper', type=Path)
    parser.add_argument('payload', type=Path)
    parser.add_argument('results', type=Path)
    args = parser.parse_args()
    if os.name != 'nt':
        parser.error('actual Windows execution required')
    args.results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=args.results.resolve()))
    tool_dir = case / 'tool space-\u03bb'
    tool_dir.mkdir()
    helper = tool_dir / 'measure.exe'
    payload = tool_dir / 'payload.exe'
    shutil.copyfile(args.helper, helper)
    shutil.copyfile(args.payload, payload)
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (helper, payload)}
    rows = {}
    def run(name, command, timeout=10000, expected_success=True):
        output = case / (name + '.stdout')
        errors = case / (name + '.stderr')
        metrics = case / (name + '.json')
        invocation = [str(helper), str(timeout), str(metrics), str(output), str(errors), *map(str, command)]
        (case / (name + '.command.json')).write_text(json.dumps(invocation, indent=4) + '\n')
        result = subprocess.run(invocation, capture_output=True, timeout=30)
        (case / (name + '.helper.stdout')).write_bytes(result.stdout)
        (case / (name + '.helper.stderr')).write_bytes(result.stderr)
        assert (result.returncode == 0) == expected_success, (name, result.returncode)
        row = json.loads(metrics.read_text())
        if expected_success:
            assert row['reason'] == 'completed' and row['cleanupComplete'] and row['windowsError'] == 0
            assert row['exitCode'] == 0 and row['activeProcesses'] == 0
        rows[name] = row
        return row
    complete = run('descendant', [payload, '--spawn'])
    assert complete['totalProcesses'] == 2, complete
    assert complete['userSeconds'] + complete['systemSeconds'] >= 0.18, complete
    assert complete['peakJobCommitBytes'] >= 64 * 1024 * 1024, complete
    assert complete['peakProcessCommitBytes'] >= 64 * 1024 * 1024, complete
    assert complete['elapsedSeconds'] > 0.1, complete
    assert 'root-exit' in (case / 'descendant.stdout').read_text()
    assert 'child-done:' in (case / 'descendant.stdout').read_text()
    assert (case / 'descendant.stderr').read_text() == 'child-stderr\n'
    timed_out = run('timeout', [payload, '--timeout'], timeout=2000, expected_success=False)
    assert timed_out['reason'] == 'timeout' and timed_out['cleanupComplete'], timed_out
    assert timed_out['totalProcesses'] == 2 and timed_out['activeProcesses'] == 0, timed_out
    # Independently check that the child observed in the log is no longer alive.
    child = int(re.search(r'child:(\d+)', (case / 'timeout.stdout').read_text())[1])
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, child)  # SYNCHRONIZE
    if handle:
        try:
            assert kernel.WaitForSingleObject(handle, 0) == 0, 'timed-out child survives'
        finally:
            kernel.CloseHandle(handle)
    else:
        assert ctypes.get_last_error() == 87, 'cannot establish child disappearance'
    failure = run('tool-error', [payload, '--error'], expected_success=False)
    assert failure['reason'] == 'tool_error' and failure['exitCode'] == 17 and failure['cleanupComplete']
    missing = run('missing', [tool_dir / 'missing.exe', '--spawn'], expected_success=False)
    assert missing['reason'] == 'internal_error' and missing['windowsError'] == 2
    run('arguments', [payload, '--args', 'plain', 'sp ace', 'quo"te', 'trailing\\', '', 'unicode-\u03bb'])
    assert (case / 'arguments.stdout').read_text() == 'arguments=PASS\n'
    sentinel = case / 'existing.stdout'
    sentinel.write_bytes(b'existing evidence must survive\n')
    run('existing', [payload, '--spawn'], expected_success=False)
    assert sentinel.read_bytes() == b'existing evidence must survive\n'
    assert hashes == {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (helper, payload)}
    (case / 'summary.json').write_text(json.dumps({'status': 'PASS', 'cases': rows, 'tools': hashes,
        'scope': 'Actual Windows job CPU and peak commit accounting, descendant after root exit, '
            'bounded timeout/cleanup, failing/missing tools, UTF-16/CRT argument transport and exclusive outputs. '
            'Peak commit is not resident set size. No exporter performance claim.'}, indent=4) + '\n')
    print('windows-measurement-controls=PASS ' + str(case))


if __name__ == '__main__':
    main()

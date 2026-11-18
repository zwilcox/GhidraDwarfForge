#!/usr/bin/env python3
"""Measure the existing Linux Swing oracle's main JVM, after all debugger checks pass."""
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

from integration_coverage import Collection, digest, save


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
MODES = {
    'GHIDRA_GUI_UNWIND': 'unwind',
    'GHIDRA_GUI_COMPRESSION': 'compressed',
    'GHIDRA_GUI_GDB_LOADER': 'loader',
    'GHIDRA_GUI_NATIVE_ATTACHMENT': 'native-attachment',
}


def selected_mode(environment):
    modes = []
    for key, mode in MODES.items():
        value = environment.get(key, '0')
        if value not in ('0', '1'):
            raise ValueError('GUI measurement requires explicit boolean mode selections')
        if value == '1':
            modes.append(mode)
    if len(modes) > 1:
        raise ValueError('GUI measurement requires one independently validated mode')
    return modes[0] if modes else 'default'


def verify_outcome(work, output, mode):
    result = work / 'result.txt'
    if not result.is_file() or result.is_symlink() or result.stat().st_size > 65536:
        raise ValueError('missing or excessive GUI outcome')
    lines = result.read_text().splitlines()
    if mode == 'unwind':
        required = {'installed-unwind-chooser=PASS', 'choices=7', 'exports=4', 'cancellations=3'}
        marker = 'gui-unwind-structural-and-gdb=PASS'
        path = work / 'unwind-result.json'
        if not path.is_file() or path.is_symlink() or path.stat().st_size > 65536:
            raise ValueError('missing GUI unwind validator/debugger receipt')
        evidence = json.loads(path.read_text())
        if (evidence.get('status') != 'PASS_GUI_UNWIND'
                or [row.get('mode') for row in evidence.get('cases', [])]
                != ['off', 'strict', 'conditioned-no-pointers', 'conditioned-fixed']):
            raise ValueError('incomplete GUI unwind validator/debugger receipt')
    else:
        required = {'installed-script-discovery=PASS', 'native-free-preflight-run=PASS',
            'script-manager-export-selection=PASS', 'script-manager-export-cancellation=PASS',
            'console-report-presentation=PASS', 'original-input-preservation=PASS',
            'script-manager-structural-validation=PASS', 'script-manager-gdb=PASS'}
        marker = 'gui-script-manager-integration=PASS'
    if not required.issubset(lines) or output.splitlines().count(marker) != 1:
        raise ValueError('GUI export, cancellation or complete debugger oracle did not pass')
    return {'resultSha256': digest(result), 'requiredChecks': sorted(required),
            'unwindResultSha256': digest(work / 'unwind-result.json') if mode == 'unwind' else None}


def run_script(command, environment, log, *, timeout=1200, maximum_bytes=32 * 1024 * 1024):
    # Own the shell, X server and WM together. The shell retains its normal EXIT
    # cleanup; an outer timeout must also reap its process group.
    with log.open('xb') as stream:
        child = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            deadline = time.monotonic() + timeout
            size = 0
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    if not selector.select(min(remaining, 1)):
                        continue
                    data = os.read(child.stdout.fileno(), 65536)
                    if not data:
                        break
                    allowed = min(len(data), maximum_bytes - size)
                    stream.write(data[:allowed])
                    size += allowed
                    if allowed != len(data):
                        raise RuntimeError('GUI diagnostics exceed the live byte limit; inspect ' + str(log))
            code = child.wait(timeout=max(0.1, deadline - time.monotonic()))
            if code != 0:
                raise RuntimeError('GUI oracle failed; inspect ' + str(log))
        except BaseException:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            # The shell may already have exited while a descendant still owns
            # the pipe or desktop. Retire that owned group even in that case.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=10)
            raise
        finally:
            child.stdout.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'module', 'fixture', 'reference'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    if os.name != 'posix' or os.environ.get('FORGE_GUI_COVERAGE_OPTION'):
        raise ValueError('requires a fresh Linux GUI coverage invocation')
    paths = [getattr(args, name).resolve(strict=True) for name in ('ghidra', 'module', 'fixture', 'reference')]
    ghidra, module, fixture, reference = paths
    java = Path(shutil.which(os.environ.get('JAVA_BIN', 'java')) or '').resolve(strict=True)
    if java.name != 'java' or not os.access(java, os.X_OK):
        raise ValueError('requires an explicit executable Java selection')
    mode = selected_mode(os.environ)
    suite = 'gui-script-manager' + ('' if mode == 'default' else '-' + mode)
    coverage = Collection(suite, module / 'lib/GhidraDwarfForge.jar', 'native-java')
    if not coverage.enabled:
        raise ValueError('GUI wrapper requires enabled integration measurement')
    parent = ROOT / 'build/test-results/gui-coverage'
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=suite + '-', dir=parent))
    log = root / 'oracle.log'
    sources = [Path(__file__), SCRIPTS / 'integration_coverage.py', SCRIPTS / 'gui-script-manager.sh',
        SCRIPTS / 'gui-unwind-evidence.py', SCRIPTS / 'gui-context-evidence.py',
        SCRIPTS / 'gui-attachment-verify.py', SCRIPTS / 'coverage-report-tool.py',
        SCRIPTS / 'check-dwarfdump.py', *sorted((SCRIPTS / 'gui').glob('*.java'))]
    protected = {str(path): digest(path) for path in [fixture, reference, coverage.jar,
        module / 'RELEASE-SHA256SUMS', *sources]}
    print('gui-coverage-log=' + str(log), flush=True)
    with coverage.session([str(java)], mode) as measured:
        # This option is passed as one argv element only to GuiScriptManagerSmoke.
        # Geometry helpers, report-tool children and privileged helpers remain
        # uninstrumented. No JAVA_TOOL_OPTIONS inheritance is introduced.
        environment = dict(os.environ, JAVA_BIN=str(java), FORGE_GUI_COVERAGE_OPTION=measured[1])
        run_script(['bash', str(SCRIPTS / 'gui-script-manager.sh'), *map(str, paths)], environment, log)
        if log.stat().st_size > 32 * 1024 * 1024:
            raise ValueError('excessive GUI diagnostics')
        output = log.read_text(errors='replace')
        matches = re.findall(r'^gui-script-manager-results=(.+)$', output, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError('GUI oracle did not identify exactly one result directory')
        work = Path(matches[0]).resolve(strict=True)
        expected_root = ROOT / 'build/test-results' / ('gui-unwind' if mode == 'unwind' else 'gui-script-manager')
        if work.parent != expected_root or not work.name.startswith('run.'):
            raise ValueError('GUI oracle results are outside the owned fixture root')
        outcome = verify_outcome(work, output, mode)
        if protected != {path: digest(path) for path in protected}:
            raise ValueError('GUI measurement changed a selected input, packaged JAR or oracle source')
    save(root / 'result.json', {'status': 'PASS_INTERACTIVE_GUI_MEASUREMENT', 'mode': mode,
        'mainJvmSessions': 1, 'desktop': 'owned Xvfb and Openbox; actual Swing interactions',
        'inputSha256': protected, 'oracleLogSha256': digest(log), 'outcome': outcome,
        'unmeasuredNestedJvmKinds': ['geometry calibration', 'report CLI', 'attachment helper'],
        'scope': 'Installed interactive GUI, complete structural/debugger oracles and cancellation assertions. '
            'Only the main GUI JVM is measured; nested JVM/native process behavior is required but unmeasured.'})
    coverage.finish(root / 'result.json')
    print('gui-coverage=PASS mode=' + mode + ' sessions=1', flush=True)


if __name__ == '__main__':
    main()

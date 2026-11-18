#!/usr/bin/env python3
"""Measure all six analyzer JVMs only after the existing entry/GDB oracle passes."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import json

from integration_coverage import Collection, digest, save


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
CASES = [(role, name, delta) for role in ('exec', 'pie')
    for name, delta in (('baseline', 0), ('rebased', 0x2000000), ('repeat', 0))]


def outcomes(work, aliases):
    cases = []
    for role, name, delta in CASES:
        case = work / role / name
        original = work / role / 'entry.stripped'
        sidecar, source = case / 'entry.dbg', case / 'entry.dbg.c'
        expected = [f'input_sha256={digest(original)}', f'rebase_delta={delta}',
            f'function_entry_case={role}/{name} PASS']
        if (case / 'result.txt').read_text().splitlines() != expected:
            raise ValueError('missing entry case or changed original')
        gdb = (case / 'gdb.txt').read_text()
        markers = ['static-entry-ranges-and-gap=PASS',
            'true-entry-breakpoints-backward-bodies-values-stepping=PASS']
        if any(gdb.splitlines().count(marker) != 1 for marker in markers):
            raise ValueError('missing true-entry debugger behavior')
        if re.search(r'warning:|error:|Traceback|cannot access|no line number|malformed|corrupt', gdb, re.I):
            raise ValueError('unexpected debugger diagnostic')
        strict = json.loads((case / 'dwarfdump.txt.check.json').read_text())
        index = json.loads((case / 'address-index.json').read_text())
        if (strict.get('status') != 'PASS' or strict.get('uncorroborated_errors') != 0
                or index.get('code_address_index') != 'PASS'
                or (case / 'readelf.stderr').stat().st_size != 0
                or 'No errors.' not in (case / 'llvm.txt').read_text()):
            raise ValueError('entry structural validation incomplete')
        alias_hash = None
        if aliases:
            alias_path = case / 'alias-symbols.json'
            alias = json.loads(alias_path.read_text())
            if (alias.get('status') != 'PASS' or alias.get('inputSha256') != digest(original)
                    or alias.get('sidecarSha256') != digest(sidecar)
                    or not {'secondary_below', 'secondary_middle'} <= alias.get('symbols', {}).keys()):
                raise ValueError('alias symbol binding incomplete')
            alias_hash = digest(alias_path)
        receipts = ['result.txt', 'gdb.txt', 'headless.txt', 'header.txt', 'sections.txt', 'notes.txt',
            'info.txt', 'abbrev.txt', 'aranges.txt', 'decodedline.txt', 'Ranges.txt', 'loc.txt',
            'llvm.txt', 'dwarfdump.txt', 'dwarfdump.txt.check.json', 'address-index.json']
        cases.append({'label': role + '-' + name, 'rebaseDelta': delta,
            'inputSha256': digest(original), 'sidecarSha256': digest(sidecar), 'sourceSha256': digest(source),
            'checks': markers, 'strictStatus': strict['status'], 'uncorroboratedErrors': 0,
            'aliasSha256': alias_hash, 'receipts': {receipt: digest(case / receipt) for receipt in receipts}})
    for offset in (0, 3):
        for key in ('inputSha256', 'sidecarSha256', 'sourceSha256'):
            if cases[offset][key] != cases[offset + 2][key]:
                raise ValueError('entry rerun is not deterministic')
        if cases[offset]['inputSha256'] != cases[offset + 1]['inputSha256']:
            raise ValueError('rebase used a different original')
    return cases


def run(command, environment, log):
    # The shell owns its project cleanup. On timeout, retire its analyzer group
    # too; no detached Ghidra workers or inherited agent options are introduced.
    with log.open('x') as stream:
        child = subprocess.Popen(command, env=environment, stdout=stream, stderr=subprocess.STDOUT,
            start_new_session=True)
        try:
            if child.wait(timeout=900) != 0:
                raise RuntimeError('function entry oracle failed; inspect ' + str(log))
        except BaseException:
            for action in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(child.pid, action)
                except ProcessLookupError:
                    pass
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
            raise
    if log.stat().st_size > 1024 * 1024:
        raise ValueError('excessive entry summary output')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'consumer', 'producer'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    if os.name != 'posix' or os.environ.get('FORGE_ENTRY_COVERAGE_LAUNCHERS'):
        raise ValueError('requires a fresh Linux entry coverage invocation')
    alias_mode = os.environ.get('FORGE_ENTRY_ALIASES', '0')
    if alias_mode not in ('0', '1'):
        raise ValueError('alias mode must be 0 or 1')
    aliases = alias_mode == '1'
    suite = 'function-entry-alias-export' if aliases else 'function-entry-export'
    paths = [getattr(args, name).resolve(strict=True) for name in ('ghidra', 'consumer', 'producer')]
    ghidra = paths[0]
    coverage = Collection(suite, ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar', 'headless')
    if not coverage.enabled:
        raise ValueError('entry wrapper requires enabled measurement')
    parent = ROOT / 'build/test-results/function-entry-coverage'
    parent.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=suite + '-', dir=parent))
    log = root / 'oracle.log'
    sources = [Path(__file__), SCRIPTS / 'integration_coverage.py',
        SCRIPTS.parent / 'coverage/launcher-headless.py', SCRIPTS / 'function-entry-export.sh',
        SCRIPTS / 'function-entry-gdb.py', SCRIPTS / 'function-entry-alias-check.py',
        SCRIPTS / 'retained-function-aliases-export.py', SCRIPTS / 'dynamic-composite-storage-check.py',
        SCRIPTS / 'dynamic-parameter-storage-check.py', SCRIPTS / 'check-code-address-index.py',
        SCRIPTS / 'check-dwarfdump.py', SCRIPTS / 'ghidra_scripts/PrepareFunctionEntryRanges.java',
        SCRIPTS / 'ghidra_scripts/RebaseFixtureProgram.java',
        *[SCRIPTS.parent / 'fixtures' / ('function_entry_ranges.' + suffix) for suffix in ('c', 'S')]]
    protected = {str(path): digest(path) for path in [coverage.jar, *paths[1:], *sources]}
    print('function-entry-coverage-log=' + str(log), flush=True)
    with ExitStack() as stack:
        launchers = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix='entry-', dir=coverage.root)))
        for role, name, _ in CASES:
            selected = stack.enter_context(coverage.launcher_headless(ghidra, role + '-' + name))
            (launchers / role).mkdir(exist_ok=True)
            (launchers / role / name).symlink_to(selected, target_is_directory=True)
        run(['bash', str(SCRIPTS / 'function-entry-export.sh'), *map(str, paths)],
            dict(os.environ, FORGE_ENTRY_COVERAGE_LAUNCHERS=str(launchers)), log)
        output = log.read_text()
        matches = re.findall(r'^function-entry-results=(.+)$', output, re.M)
        if len(matches) != 1 or output.splitlines().count(suite + '=PASS') != 1:
            raise ValueError('complete entry oracle did not pass')
        work = Path(matches[0]).resolve(strict=True)
        if work.parent != ROOT / 'build/test-results' / suite or not work.name.startswith('run.'):
            raise ValueError('entry results outside owned fixture root')
        cases = outcomes(work, aliases)
        if protected != {path: digest(path) for path in protected}:
            raise ValueError('entry measurement changed a native library, JAR or test source')
    save(root / 'result.json', {'status': 'PASS_FUNCTION_ENTRY_MEASUREMENT', 'aliases': aliases,
        'target': 'x86_64', 'cases': cases, 'protected': protected, 'oracleLogSha256': digest(log),
        'productionJarSha256': digest(coverage.jar), 'resultDirectory': str(work),
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'scope': 'Six actual headless exports, original preservation, deterministic reruns, '
            'true-entry breakpoints, backward bodies, discontiguous ranges, gaps, values and stepping.'})
    coverage.finish(root / 'result.json')
    print('function-entry-coverage=PASS aliases=' + alias_mode + ' sessions=6', flush=True)


if __name__ == '__main__':
    main()

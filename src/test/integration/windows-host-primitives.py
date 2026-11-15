#!/usr/bin/env python3
"""Measure existing native Windows host probes against the installed production JAR."""
import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess

from integration_coverage import Collection, digest, save


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'nt':
        raise ValueError('requires actual native Windows')
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    classes = root / 'classes'
    classes.mkdir()
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    dependencies = [jar, ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar',
        ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar']
    names = ('WindowsFileSecurityProbe', 'WindowsAttachmentPrivilegeProbe',
        'WindowsAttachmentHostSmoke', 'WindowsAttachmentTransactionSmoke', 'BuildIdFileLockSmoke')
    sources = [Path(__file__).resolve().parents[1] / 'java/ghidradwarfforge/output' / (name + '.java')
        for name in names]
    protected = {str(path): digest(path) for path in [*dependencies, *sources]}
    classpath = os.pathsep.join(map(str, [classes, *dependencies]))
    java = Path(os.environ['JAVA_HOME']) / 'bin/java.exe'
    coverage = Collection('windows-host-primitives', jar, 'windows',
        test_classes=tuple('ghidradwarfforge.output.' + name for name in names))
    commands = []

    def run(label, command, *, marker=None):
        command = list(map(str, command))
        session = coverage.session(command, label) if marker else nullcontext(command)
        with session as measured:
            with subprocess.Popen(measured, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP) as child:
                try:
                    stdout, stderr = child.communicate(timeout=180)
                except subprocess.TimeoutExpired:
                    cleanup = subprocess.run([str(Path(os.environ['SystemRoot']) / 'System32/taskkill.exe'),
                        '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=30)
                    (root / (label + '.cleanup.log')).write_bytes(cleanup.stdout + cleanup.stderr)
                    stdout, stderr = child.communicate(timeout=30)
                    (root / (label + '.stdout')).write_bytes(stdout)
                    (root / (label + '.stderr')).write_bytes(stderr)
                    raise
            (root / (label + '.stdout')).write_bytes(stdout)
            (root / (label + '.stderr')).write_bytes(stderr)
            commands.append({'label': label, 'command': measured, 'exit': child.returncode})
            save(root / 'commands.json', commands)
            if child.returncode != 0 or stderr or marker and marker.encode() not in stdout:
                raise AssertionError('Windows primitive probe failed: ' + label)

    run('compile', [java.with_name('javac.exe'), '--release', '21', '-cp', classpath,
        '-d', classes, *sources])
    prefix = [java, '--enable-native-access=ALL-UNNAMED', '-cp', classpath]
    # Match the established isolated probes' interpreter/GC settings for native
    # handle accounting. Do not inject agents into their deliberate halt children.
    stable = [java, '-Xint', '-XX:+UseSerialGC', *prefix[1:]]
    run('privilege', [*stable, 'ghidradwarfforge.output.WindowsAttachmentPrivilegeProbe'],
        marker='windows-attachment-privilege=PASS cycles=128')
    run('host', [*stable, 'ghidradwarfforge.output.WindowsAttachmentHostSmoke', root / 'owned'],
        marker='windows-attachment-host=PASS')
    run('transactions', [*prefix, 'ghidradwarfforge.output.WindowsAttachmentTransactionSmoke', root / 'transactions'],
        marker='windows-attachment-transaction=PASS')
    run('lock', [*prefix, 'ghidradwarfforge.output.BuildIdFileLockSmoke', 'exercise', root / 'owned-lock'],
        marker='build-id-file-lock=PASS host=windows')
    host = json.loads((root / 'owned/result.json').read_text(encoding='utf-8'))
    transactions = json.loads((root / 'transactions/result.json').read_text(encoding='utf-8'))
    abrupt = [row for row in transactions['outcomes'] if 'childExit' in row]
    if len(abrupt) != 8 or any(row['childExit'] != 89 for row in abrupt):
        raise AssertionError('missing interrupted-child recovery evidence')
    if protected != {path: digest(path) for path in protected}:
        raise AssertionError('probe changed production dependencies or test sources')
    save(root / 'result.json', {'status': 'PASS_NATIVE_WINDOWS_HOST_PRIMITIVES',
        'hostChecks': host['checks'], 'transactionChecks': transactions['checks'],
        'protectedSha256': protected,
        'unmeasuredNestedChildren': [{'case': row['case'], 'exitCode': row['childExit']} for row in abrupt],
        'lockContendersMeasured': False,
        'scope': 'Existing native Windows privilege/host/transaction/lock assertions over owned fixtures. '
            'Four direct JVMs measured; nested lock contenders and eight deliberate halt children remain unmeasured. '
            'No real ELF or power-loss claim; those require separate integration oracles.'})
    coverage.finish(root / 'result.json')
    print('windows-host-primitives=PASS sessions=4 abrupt-process-exits=8')


if __name__ == '__main__':
    main()

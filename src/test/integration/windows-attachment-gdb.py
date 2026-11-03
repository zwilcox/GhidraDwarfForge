#!/usr/bin/env python3
"""Run Windows-produced attachment generations on their Linux ELF target host."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import signal
import subprocess
import zlib


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--windows-results', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    require(os.name == 'posix', 'run this ELF runtime test on Linux')
    incoming = args.windows_results.resolve(strict=True)
    operation = incoming / 'attachment-operation'
    acceptance = json.loads((operation / 'result.json').read_text())
    require(acceptance['status'] == 'PASS' and 'saved-curation-refresh' in acceptance['cases'],
            'Windows attachment and saved refresh must pass first')
    work = args.results.absolute()
    work.mkdir(parents=True, exist_ok=False)
    oracle = Path(__file__).with_name('automatic-association-gdb.py').resolve(strict=True)
    reference = operation / 'provenance/semantic.exec.reference'
    first_receipt = json.loads((operation / 'owned/commit/transaction.json').read_text())
    refresh = json.loads((operation / 'owned/commit/refresh.receipt.json').read_text())
    require(refresh == acceptance['refreshReceipt'] and first_receipt['phase'] == refresh['phase'] == 'COMMITTED',
            'retained Windows receipts differ')
    require(first_receipt['hostContract'] == refresh['hostContract'] == 'windows-x64-local-ntfs-raw-security-v1',
            'artifacts did not pass the production Windows Host')
    protected = {str(path): digest(path) for path in incoming.rglob('*') if path.is_file()}
    commands = []

    def run(label, command, env=None):
        command = list(map(str, command))
        with subprocess.Popen(command, cwd=work, env=env, start_new_session=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
            timed_out = False
            try:
                stdout, stderr = child.communicate(timeout=90)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(child.pid, signal.SIGKILL)
                stdout, stderr = child.communicate(timeout=10)
        (work / (label + '.stdout')).write_bytes(stdout)
        (work / (label + '.stderr')).write_bytes(stderr)
        commands.append({'label': label, 'command': command, 'exit': child.returncode, 'timedOut': timed_out})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        require(not timed_out and child.returncode == 0, label + ' failed; inspect retained logs')
        return stdout, stderr

    symbols, _ = run('reference-symbols', ['readelf', '-Ws', reference])
    addresses = {int(fields[1], 16) for line in symbols.decode().splitlines()
        if len(fields := line.split()) >= 8 and fields[0].rstrip(':').isdigit() and fields[7] == 'recovered_add'}
    require(len(addresses) == 1, 'compiler reference function must be unique')
    function_address = hex(addresses.pop())
    run('gdb-version', ['gdb', '--version'])
    empty = work / 'empty-debug-root'
    empty.mkdir()
    outcomes = []
    for generation, receipt in [('initial', first_receipt), ('refresh', refresh)]:
        files = receipt['files']
        # Map only explicitly known fixture locations. Never follow paths from
        # downloaded JSON, and retain the original Windows artifacts unchanged.
        target_input = operation / 'owned/commit' / (
            'prior-target.backup' if generation == 'initial' else 'semantic.exec.stripped')
        sidecar_input = operation / 'owned/commit' / (
            'semantic.exec.ghidra-forge.dbg' if generation == 'initial' else 'refreshed.dbg')
        source_input = (incoming / 'work/semantic.exec.ghidra-forge.dbg.c' if generation == 'initial'
                        else operation / 'owned/commit/refreshed.dbg.c')
        for role, path in [('targetAfter', target_input), ('sidecar', sidecar_input), ('source', source_input)]:
            require(digest(path) == files[role]['sha256'] and path.stat().st_size == files[role]['bytes'],
                    'Windows generation bytes differ: ' + generation + '/' + role)
        require(PureWindowsPath(files['sidecar']['path']).name == sidecar_input.name and
                PureWindowsPath(files['source']['path']).name == source_input.name,
                'fixture basename differs from Windows receipt')
        require(zlib.crc32(sidecar_input.read_bytes()) == receipt['debuglinkCrc32'], 'Windows CRC differs')
        for corrupt in (False, True):
            label = generation + ('-bad-crc' if corrupt else '-runtime')
            directory = work / label
            directory.mkdir()
            target = directory / 'fixture'
            sidecar = directory / sidecar_input.name
            source = directory / source_input.name
            shutil.copyfile(target_input, target)
            shutil.copyfile(sidecar_input, sidecar)
            shutil.copyfile(source_input, source)
            target.chmod(0o700)  # Only the new Linux runtime copy needs execute mode.
            if corrupt:
                with sidecar.open('ab') as output:
                    output.write(b'CRC-negative-control')
                require(zlib.crc32(sidecar.read_bytes()) != receipt['debuglinkCrc32'], 'CRC control did not change')
            else:
                verified, errors = run(label + '-llvm', ['llvm-dwarfdump', '--verify', sidecar])
                require(verified.count(b'No errors.') == 1 and not errors, 'transferred DWARF did not validate')
            env = {**os.environ, 'DEBUGINFOD_URLS': '', 'FORGE_ASSOCIATION_MODE': 'absent' if corrupt else 'present',
                'FORGE_ASSOCIATION_ADDRESS': function_address, 'FORGE_ASSOCIATION_DEBUG_FILE': str(sidecar),
                'FORGE_ASSOCIATION_SOURCE': str(source), 'FORGE_ASSOCIATION_RUNTIME': '1'}
            if generation == 'refresh':
                env.update({'FORGE_ASSOCIATION_FUNCTION': 'curated_refresh_add',
                    'FORGE_ASSOCIATION_TYPE': 'curated_refresh_state', 'FORGE_ASSOCIATION_MEMBER': 'curated_refresh_member'})
            output, errors = run(label, ['gdb', '-nx', '-nh', '-batch',
                '-iex', 'set debuginfod enabled off', '-iex', 'set auto-load off',
                '-iex', 'set debug-file-directory ' + str(empty),
                '-ex', 'directory ' + str(directory), '-ex', 'file "' + str(target) + '"',
                '-ex', 'source ' + str(oracle)], env)
            if corrupt:
                require(b'automatic-association=absent PASS' in output and b'CRC mismatch' in errors,
                        'GDB did not reject the corrupted association by CRC')
            else:
                require(not errors and b'automatic-association=present PASS' in output and b'exited normally' in output,
                        'GDB did not automatically discover and execute the Windows generation')
            require(digest(target) == files['targetAfter']['sha256'] and digest(source) == files['source']['sha256'],
                    'runtime changed executable or synthetic source')
            if not corrupt:
                require(digest(sidecar) == files['sidecar']['sha256'], 'runtime changed sidecar')
            outcomes.append({'case': label, 'targetSha256': digest(target), 'sidecarSha256': digest(sidecar),
                'sourceSha256': digest(source)})
    for path, expected in protected.items():
        require(digest(Path(path)) == expected, 'consumer changed downloaded Windows evidence')
    (work / 'result.json').write_text(json.dumps({'status': 'PASS', 'outcomes': outcomes,
        'protectedWindowsArtifacts': protected,
        'scope': 'Windows-produced initial and changed-CRC refresh generations; actual Linux GDB discovery/source/types/arguments and CRC refusal; source explicitly relocated with GDB directory'}, indent=4) + '\n')
    print('windows-attachment-linux-gdb=PASS generations=2 crc-controls=2')


if __name__ == '__main__':
    main()

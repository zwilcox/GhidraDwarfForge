#!/usr/bin/env python3
"""Test LLDB and offline perf against actual production installer generations."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

import lldb_consumer


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def identity(path):
    notes = subprocess.check_output(['readelf', '-n', str(path)], text=True)
    value, = set(re.findall(r'Build ID: ([0-9a-f]+)', notes))
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['configuration', 'updated-configuration', 'mismatch-sidecar', 'mismatch-reference', 'labels', 'ghidra', 'output']:
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ['java', 'lldb', 'perf']:
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--target', required=True, choices=['x86_64', 'aarch64'])
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    scripts = Path(__file__).resolve().parent
    module = args.ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge'
    configs = [json.loads(p.read_text()) for p in [args.configuration, args.updated_configuration]]
    protected = {p: digest(p) for config in configs for p in config['files'].values()}
    protected.update({str(p): digest(p) for p in [args.labels, args.mismatch_sidecar, args.mismatch_reference,
        module / 'lib/GhidraDwarfForge.jar']})
    build_id = identity(configs[0]['files']['original'])
    assert all(identity(c['files']['original']) == identity(c['files']['sidecar']) == build_id for c in configs)
    assert identity(args.mismatch_sidecar) != build_id
    assert identity(args.mismatch_reference) == identity(args.mismatch_sidecar)
    for index, config in enumerate(configs):
        inputs = root / ('inputs-' + str(index))
        inputs.mkdir()
        for key, value in list(config['files'].items()):
            copy = inputs / Path(value).name
            shutil.copy2(value, copy)
            config['files'][key] = str(copy)
        config['tools']['helper'] = str(module / 'os/linux_x86_64/forge-validator-supervisor')
    owned = {p: digest(p) for config in configs for p in config['files'].values()}
    binary = root / 'original'
    shutil.copy2(configs[0]['files']['original'], binary)
    symfs = root / 'symfs'
    debug = symfs / 'usr/lib/debug'
    debug.mkdir(parents=True)
    mirror = symfs / str(binary).lstrip('/')
    mirror.parent.mkdir(parents=True)
    shutil.copy2(binary, mirror)
    cache = root / 'perf-cache'
    relative = Path('.build-id') / build_id[:2] / (build_id[2:] + '.debug')
    registration = debug / relative
    mismatch_symfs = root / 'mismatch-symfs'
    mismatch_debug = mismatch_symfs / 'usr/lib/debug'
    foreign = mismatch_debug / relative
    foreign.parent.mkdir(parents=True)
    shutil.copy2(args.mismatch_sidecar, foreign)
    foreign_mirror = mismatch_symfs / str(binary).lstrip('/')
    foreign_mirror.parent.mkdir(parents=True)
    shutil.copy2(binary, foreign_mirror)
    environment = dict(os.environ, DEBUGINFOD_URLS='', LC_ALL='C.UTF-8', PERF_CONFIG='/dev/null')
    commands, observations = [], []

    def run(name, command, expected=0):
        command = list(map(str, command))
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=240)
        (root / (name + '.stdout')).write_text(result.stdout)
        (root / (name + '.stderr')).write_text(result.stderr)
        commands.append({'name': name, 'command': command, 'exit': result.returncode})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        if expected is not None:
            assert result.returncode == expected, (name, result.returncode, result.stdout[-3000:], result.stderr[-3000:])
        return result

    def installer(action, index=0):
        request = {'schema': 'forge-build-id-request-v1', 'action': action, 'root': str(debug)}
        if action in ['install', 'update']:
            request.update(files=configs[index]['files'], tools=configs[index]['tools'])
        else:
            request['buildId'] = build_id
        path = root / (action + '.json')
        path.write_text(json.dumps(request, indent=4) + '\n')
        result = run(action, [module / 'support/ghidra-dwarf-forge-build-id',
            '--java=' + args.java, '--ghidra-dir=' + str(args.ghidra.resolve()),
            '--request=' + str(path), '--request-sha256=' + digest(path)])
        records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        assert all(r['modifiesOriginal'] is False for r in records)
        value = records[-1]
        assert value['outcome'] == {'install': 'INSTALLED', 'update': 'UPDATED', 'remove': 'REMOVED'}[action]
        if action != 'remove':
            assert Path(value['registration']) == registration
            assert registration.stat().st_nlink == 1
        return value

    @contextmanager
    def exports_absent():
        hidden = []
        try:
            for path in sorted({Path(c['files'][key]) for c in configs for key in ['source', 'sidecar']}):
                moved = path.with_name(path.name + '.consumer-hidden')
                assert not moved.exists()
                path.rename(moved)
                hidden.append((path, moved))
            yield
        finally:
            for path, moved in reversed(hidden):
                assert not path.exists()
                moved.rename(path)

    def perf(name, installed=None, selected_symfs=symfs, mismatched=False):
        for label, option in [('lines', '-L'), ('variables', '-V')]:
            command = [args.perf, '--buildid-dir', cache, 'probe']
            if selected_symfs is not None:
                command += ['--symfs', selected_symfs]
            result = run(name + '-perf-' + label, command + ['-x', binary, option, 'fp_float'], expected=None)
            text = result.stdout + result.stderr
            if mismatched and result.returncode == 0:
                # Some perf versions trust the build-ID pathname without checking
                # its note. Record this as a consumer limitation, not rejection.
                assert identity(foreign) != build_id
                if label == 'lines':
                    assert 'fp_float_first = first;' in text and 'fp_float_second = second;' in text
                else:
                    assert re.search(r'float\s+first\b', text) and re.search(r'float\s+second\b', text), text
            elif installed is None:
                assert result.returncode > 0 and ('file has no debug information.' in text or
                    'Failed to find debug information' in text), text
            else:
                assert result.returncode == 0, text
                if label == 'lines':
                    assert installed['source'] in text and 'fp_float_first = first;' in text
                    assert 'fp_float_second = second;' in text
                else:
                    assert re.search(r'float\s+first\b', text) and re.search(r'float\s+second\b', text), text
            observations.append({'consumer': 'perf', 'phase': name, 'check': label,
                'found': result.returncode == 0, 'mismatchedIdentityAccepted': mismatched and result.returncode == 0})

    def lldb(name, installed=None, selected_debug=debug):
        setup = ['settings set symbols.enable-external-lookup false',
            'settings set target.debug-file-search-paths ' + shlex.quote(str(selected_debug))]
        if installed is None:
            script = root / (name + '-absence.py')
            script.write_text('from pathlib import Path\nimport lldb\n'
                'target = lldb.debugger.GetSelectedTarget()\n'
                'assert target.GetNumModules() == 1\n'
                'module = target.GetModuleAtIndex(0)\n'
                'assert not module.GetSymbolFileSpec().IsValid() or Path(module.GetSymbolFileSpec().fullpath).resolve() == Path(' + repr(str(binary)) + ').resolve()\n'
                'assert module.GetNumCompileUnits() == 0\n'
                "assert target.FindFunctions('fp_float').GetSize() == 0\n"
                "print('FORGE_INSTALLED_LLDB_ABSENT')\n")
            command = [args.lldb, '--no-lldbinit', '--batch']
            for item in [*setup, 'target create ' + shlex.quote(str(binary)),
                    'script exec(open(' + repr(str(script)) + ').read())']:
                command += ['-o', item]
            result = run(name + '-lldb', command)
            text = result.stdout + result.stderr
            assert 'FORGE_INSTALLED_LLDB_ABSENT' in text and 'Traceback' not in text, text
        else:
            output = root / (name + '-lldb')
            config = root / (name + '-lldb.json')
            config.write_text(json.dumps({'mode': 'forge', 'target': args.target,
                'source': installed['source'], 'observations': str(output / 'observations.json'),
                'labels': {n: int(v, 16) for n, v in (row.split() for row in args.labels.read_text().splitlines())}}, indent=4) + '\n')
            assertion = root / (name + '-module.py')
            assertion.write_text('from pathlib import Path\nimport lldb\n'
                'target = lldb.debugger.GetSelectedTarget()\n'
                'module = target.GetModuleAtIndex(0)\n'
                'assert Path(module.GetSymbolFileSpec().fullpath).resolve() == Path(' + repr(str(registration)) + ').resolve()\n'
                "print('FORGE_INSTALLED_LLDB_MODULE')\n")
            before = ['script exec(open(' + repr(str(assertion)) + ').read())', 'source list -n fp_float'] + [
                'breakpoint set --name ' + n + ' --skip-prologue false --one-shot true'
                for n in ['fp_float', 'fp_double', 'fp_clobbered']]
            text = lldb_consumer.run(binary, None, output, args.lldb, args.target, before,
                ['script exec(open(' + repr(str(scripts / 'floating-registers-lldb-observe.py')) + ').read())'],
                {'FORGE_LLDB_FP_CONFIG': str(config), 'DEBUGINFOD_URLS': ''},
                qemu_cpu='cortex-a53' if args.target == 'aarch64' else None, setup=setup)
            assert 'FORGE_INSTALLED_LLDB_MODULE' in text and 'FORGE_LLDB_FLOATING_PASS' in text
            assert 'fp_float_first = first;' in text and 'fp_float_second = second;' in text
            assert len(json.loads((output / 'observations.json').read_text())) == 10
        observations.append({'consumer': 'lldb', 'phase': name, 'found': installed is not None})

    versions = lldb_consumer.versions(args.lldb, args.target)
    versions['perf'] = run('perf-version', [args.perf, 'version']).stdout.strip()
    with exports_absent():
        perf('empty')
        lldb('empty')
        perf('mismatched-forge', selected_symfs=mismatch_symfs, mismatched=True)
        lldb('mismatched', selected_debug=mismatch_debug)
        foreign.unlink()
        shutil.copy2(args.mismatch_reference, foreign)
        perf('mismatched-compiler', selected_symfs=mismatch_symfs, mismatched=True)
        lldb('mismatched-compiler', selected_debug=mismatch_debug)
    installed = installer('install')
    assert digest(installed['source']) == digest(configs[0]['files']['source'])
    with exports_absent():
        perf('installed', installed)
        lldb('installed', installed)
        perf('installed-unconfigured', selected_symfs=None)
    initial_hash = digest(registration)
    snapshot = root / 'perf-snapshot.debug'
    shutil.copy2(registration, snapshot)
    run('cache-add', [args.perf, '--buildid-dir', cache, 'buildid-cache', '--add', snapshot])
    cached = cache / '.build-id' / build_id[:2] / build_id[2:] / 'elf'
    assert digest(cached) == initial_hash and registration.stat().st_nlink == 1
    cache_links = {'snapshot': snapshot.stat().st_nlink, 'registration': registration.stat().st_nlink}
    with exports_absent():
        perf('cache-only', selected_symfs=None)
    # Replacing our snapshot (never truncating a possibly hard-linked inode)
    # ensures the cache cannot silently change when the installation refreshes.
    updated = installer('update', 1)
    assert installed['source'] != updated['source'] and Path(installed['source']).exists()
    assert digest(updated['source']) == digest(configs[1]['files']['source'])
    assert digest(registration) != initial_hash and digest(cached) == initial_hash
    with exports_absent():
        perf('updated', updated)
        lldb('updated', updated)
    snapshot.unlink()
    shutil.copy2(registration, snapshot)
    run('cache-update', [args.perf, '--buildid-dir', cache, 'buildid-cache', '--update', snapshot])
    assert digest(cached) == digest(registration) and registration.stat().st_nlink == 1
    installer('remove')
    assert not registration.exists() and Path(updated['source']).exists()
    with exports_absent():
        # This also checks whether perf's distinct cache supplies DWARF to probe.
        perf('removed-cache-retained')
        lldb('removed')
    run('cache-remove', [args.perf, '--buildid-dir', cache, 'buildid-cache', '--remove', snapshot])
    assert not cached.exists()
    assert protected == {p: digest(p) for p in protected}
    assert owned == {p: digest(p) for p in owned}
    assert digest(binary) == digest(mirror) == digest(configs[0]['files']['original'])
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_BUILD_ID_CONSUMERS',
        'target': args.target, 'versions': versions, 'buildId': build_id,
        'initial': installed, 'updated': updated, 'observations': observations,
        'protectedSha256': protected, 'ownedSha256': owned, 'cacheAddLinkCounts': cache_links,
        'commandsSha256': digest(root / 'commands.json'),
        'scope': 'Production install/update/remove; LLDB automatic discovery and ten runtime observations per generation; '
            'offline perf source/variable lookup through symfs; independent perf cache add/update/remove. '
            'No perf event recording or running-process probe installation claim.'}, indent=4) + '\n')
    print('build-id-consumers=PASS ' + args.target)


if __name__ == '__main__':
    main()

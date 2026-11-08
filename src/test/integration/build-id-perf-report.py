#!/usr/bin/env python3
"""Characterize real perf samples against installed, refreshed and removed DWARF."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['ghidra', 'java', 'tools-configuration', 'output', 'scratch', 'perf']:
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--role', required=True, choices=['exec', 'pie'])
    parser.add_argument('--record-with-sudo', action='store_true',
        help='Elevate only the bounded recorder; drop privilege before executing the owned target.')
    parser.add_argument('--prepare-only', action='store_true',
        help='Validate exports, installation and offline queries without claiming sample/report acceptance.')
    args = parser.parse_args()
    assert os.getuid() != 0 and os.geteuid() != 0, 'run the harness unprivileged'
    assert not (args.record_with_sudo and args.prepare_only)
    root, scratch, ghidra = args.output.resolve(), args.scratch.resolve(), args.ghidra.resolve()
    root.mkdir(parents=True, exist_ok=False)
    scratch.mkdir(parents=True, exist_ok=False)
    for name in ['project', 'tmp', 'config', 'cache']:
        (scratch / name).mkdir()
    scripts = Path(__file__).resolve().parent
    fixture = scripts.parent / 'fixtures/perf-build-id.c'
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    tools = json.loads(args.tools_configuration.read_text())['tools']
    tools['helper'] = str(module / 'os/linux_x86_64/forge-validator-supervisor')
    protected = {str(p): digest(p) for p in [fixture, Path(__file__),
        scripts / 'ghidra_scripts/PreparePerfBuildId.java', module / 'lib/GhidraDwarfForge.jar']}
    environment = dict(os.environ, LC_ALL='C.UTF-8', DEBUGINFOD_URLS='', PERF_CONFIG='/dev/null',
        JAVA_HOME=str(args.java.resolve().parent.parent),
        JAVA_TOOL_OPTIONS='-Djava.io.tmpdir=' + str(scratch / 'tmp') + ' -Djna.tmpdir=' + str(scratch / 'tmp'),
        XDG_CONFIG_HOME=str(scratch / 'config'), XDG_CACHE_HOME=str(scratch / 'cache'))
    commands, generations, observations = [], [], []

    def save(name, value):
        (root / name).write_text(json.dumps(value, indent=4) + '\n')

    def run(name, command, timeout=240):
        command = list(map(str, command))
        commands.append({'name': name, 'command': command})
        save('commands.json', commands)
        with subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                # The privileged recorder has its own shorter timeout. These
                # ordinary child processes remain owned by this unprivileged user.
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate(timeout=10)
                (root / (name + '.stdout')).write_text(stdout)
                (root / (name + '.stderr')).write_text(stderr)
                raise
        (root / (name + '.stdout')).write_text(stdout)
        (root / (name + '.stderr')).write_text(stderr)
        commands[-1]['exit'] = process.returncode
        save('commands.json', commands)
        assert process.returncode == 0, (name, process.returncode, stdout[-2000:], stderr[-2000:])
        return stdout

    versions = {name: run(name + '-version', command).splitlines()[0] for name, command in [
        ('perf', [args.perf, 'version']), ('gcc', ['gcc', '--version']),
        ('gdb', ['gdb', '--version']), ('readelf', [tools['readelf'], '--version'])]}
    reference, original = root / 'reference', root / 'original'
    flags = ['-fPIE', '-pie'] if args.role == 'pie' else ['-fno-pie', '-no-pie']
    run('compile', ['gcc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-g', '-gdwarf-5',
        '-fno-inline', '-Wl,--build-id=sha1', *flags, fixture, '-o', reference])
    run('strip', ['objcopy', '--strip-all', reference, original])
    original_hash = digest(original)
    protected.update({str(p): digest(p) for p in [original, reference]})
    assert 'FORGE_PERF_TARGET_PASS_UNPRIVILEGED' in run('unprivileged-fixture', [original], timeout=30)
    symbols = run('reference-symbols', [tools['readelf'], '-Ws', reference])
    entries = [f for line in symbols.splitlines() if len(f := line.split()) >= 8 and f[7] == 'profile_hot']
    assert len(entries) == 1 and entries[0][3] == 'FUNC'
    link = int(entries[0][1], 16)
    notes = run('original-notes', [tools['readelf'], '-n', original])
    build_id, = set(re.findall(r'Build ID: ([0-9a-f]+)', notes))
    relative = Path('.build-id') / build_id[:2] / (build_id[2:] + '.debug')
    headless = [ghidra / 'support/analyzeHeadless', scratch / 'project', 'PerfBuildId',
        '-scriptPath', scripts / 'ghidra_scripts']

    def curate(mode, name):
        return ['-postScript', 'PreparePerfBuildId.java', mode, format(link, 'x'),
            str(original), original_hash, name]

    configs = []
    for index, name in enumerate(['forge_profile_initial', 'forge_profile_curated']):
        sidecar = root / (name + '.dbg')
        if index == 0:
            action = ['-import', original, '-analysisTimeoutPerFile', '120', *curate('initial', name)]
        else:
            edited = run('edit-save', headless + ['-process', original.name, '-noanalysis', *curate('edit', name)])
            assert 'perf-build-id-program=PASS mode=edit' in edited
            action = ['-process', original.name, '-noanalysis', '-readOnly', *curate('verify', name)]
        output = run(name + '-export', headless + action + ['-postScript', 'GhidraDwarfForge.java',
            '--packaged-natives', '--output=' + str(sidecar), *curate('verify', name)])
        assert 'GhidraDwarfForge symbol export PASS' in output
        assert 'perf-build-id-program=PASS mode=verify name=' + name in output
        reports = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in output.splitlines() if 'GhidraDwarfForge report: ' in line]
        assert len(reports) == 1 and reports[0]['status'] in ['SUCCESS', 'PARTIAL']
        source = Path(str(sidecar) + '.c')
        for key, path in [('input', original), ('output', sidecar), ('source', source)]:
            assert reports[0]['artifacts'][key + 'Sha256'] == digest(path)
        report = root / (name + '.report.json')
        report.write_text(json.dumps(reports[0], indent=4) + '\n')
        configs.append({'files': {'original': str(original), 'sidecar': str(sidecar),
            'source': str(source), 'report': str(report)}, 'tools': tools})
        for path in [sidecar, source, report]:
            protected[str(path)] = digest(path)
        run(name + '-llvm', [tools['llvm'], '--verify', sidecar])
        run(name + '-strict', ['python3', scripts / 'check-dwarfdump.py', sidecar,
            root / (name + '.strict.txt'), '--original', original,
            '--tool', tools['strict'], '--configuration', tools['configuration']])
        for label, option in [('header', '-h'), ('sections', '-SW'), ('notes', '-n'),
                ('info', '--debug-dump=info'), ('lines', '--debug-dump=decodedline')]:
            run(name + '-' + label, [tools['readelf'], option, sidecar])
    assert digest(configs[0]['files']['sidecar']) != digest(configs[1]['files']['sidecar'])

    def make_symfs(name, control=None):
        symfs = root / name
        debug = symfs / 'usr/lib/debug'
        debug.mkdir(parents=True)
        mirror = symfs / str(original).lstrip('/')
        mirror.parent.mkdir(parents=True)
        shutil.copy2(original, mirror)
        protected[str(mirror)] = digest(mirror)
        if control is not None:
            registration = debug / relative
            registration.parent.mkdir(parents=True)
            shutil.copy2(control, registration)
            protected[str(registration)] = digest(registration)
        return symfs, debug

    symfs, debug = make_symfs('symfs')
    compiler_symfs, _ = make_symfs('compiler-symfs', reference)
    dwarf_only = root / 'compiler-without-hot-elf-symbol'
    run('compiler-remove-hot-symbol', ['objcopy', '--strip-symbol=profile_hot', reference, dwarf_only])
    assert not re.search(r'\bprofile_hot\b', run('compiler-remaining-symbols', [tools['readelf'], '-Ws', dwarf_only]))
    compiler_gdb = run('compiler-dwarf-control', ['gdb', '-nx', '-q', '-batch', '-ex', 'set debuginfod enabled off',
        '-ex', 'file ' + json.dumps(str(dwarf_only)), '-ex',
        'python s=gdb.lookup_global_symbol("profile_hot"); assert s is not None and s.symtab is not None; print("COMPILER_DWARF_CONTROL_PASS")'])
    assert 'COMPILER_DWARF_CONTROL_PASS' in compiler_gdb
    dwarf_symfs, _ = make_symfs('compiler-dwarf-symfs', dwarf_only)
    cache = root / 'empty-perf-cache'
    cache.mkdir()
    data = root / 'perf.data'
    hot_ips = set()
    compiler_dwarf_found = None

    def sampled(name, selected_symfs, expected_name=None):
        base = [args.perf, '--buildid-dir', cache]
        report = run(name + '-report', base + ['report', '--stdio', '--stdio-color=never',
            '-i', data, '--symfs', selected_symfs, '--no-children', '--percent-limit', '0',
            '--full-source-path', '-F', 'sample,dso,symbol,srcline', '-t', ';'])
        script = run(name + '-samples', base + ['script', '-i', data, '--symfs', selected_symfs,
            '-F', 'ip,sym,dso'])
        samples = []
        for line in script.splitlines():
            match = re.fullmatch(r'\s*([0-9a-f]+)\s+(.*?)\s+\((.*?)\)\s*', line)
            assert match, ('unexpected sample format', line)
            ip, symbol, dso = match.groups()
            if dso in [str(original), original.name]:
                samples.append((int(ip, 16), symbol))
        assert len(samples) >= 30, ('insufficient original samples', name, len(samples))
        if name == 'compiler':
            hot_ips.update(ip for ip, symbol in samples if symbol == 'profile_hot')
            assert hot_ips and sum(symbol == 'profile_hot' for _, symbol in samples) >= 30
            assert 'profile_hot' in report and str(fixture) in report
        hot = [symbol for ip, symbol in samples if ip in hot_ips]
        assert len(hot) >= 30
        found = expected_name is not None and all(symbol == expected_name for symbol in hot)
        if found:
            assert expected_name in report
        else:
            assert expected_name is None or not any(symbol == expected_name for symbol in hot), 'partial hot symbolization'
        observations.append({'phase': name, 'originalSamples': len(samples), 'hotSamples': len(hot),
            'hotSymbols': sorted(set(hot)), 'expectedName': expected_name, 'resolvedExpectedName': found})
        save('observations.json', observations)
        return found, report

    if not args.prepare_only:
        # Precreate an owned, writable data inode so sudo never leaves root-owned
        # result files. The initially empty file is opened by the recorder.
        data.touch(mode=0o600)
        command = [args.perf, '--buildid-dir', cache, 'record', '--no-buildid-cache',
            '-e', 'cpu-clock:u', '-F', '999', '-o', data, '--', original]
        if args.record_with_sudo:
            # timeout owns the recorder and its child; no global kernel policy
            # changes, system-wide recording, or privileged target execution.
            command = ['sudo', '-n', '--', 'timeout', '--kill-after=5s', '30s',
                args.perf, '--buildid-dir', cache, 'record', '--no-buildid-cache',
                '-e', 'cpu-clock:u', '-F', '999', '-o', data, '--',
                'setpriv', '--reuid', str(os.getuid()), '--regid', str(os.getgid()), '--init-groups', original]
        output = run('record', command, timeout=45)
        assert 'FORGE_PERF_TARGET_PASS_UNPRIVILEGED' in output
        assert data.stat().st_size > 0 and data.stat().st_uid == os.getuid()
        recorded = run('recorded-build-ids', [args.perf, '--buildid-dir', cache, 'buildid-list', '-i', data])
        assert re.search(r'^' + build_id + r'\s+' + re.escape(str(original)) + r'$', recorded, re.MULTILINE)
        protected[str(data)] = digest(data)
        assert sampled('compiler', compiler_symfs, 'profile_hot')[0]
        compiler_dwarf_found = sampled('compiler-dwarf-only', dwarf_symfs, 'profile_hot')[0]
        assert not sampled('empty', symfs, 'forge_profile_initial')[0]

    def installer(action, index=0):
        request = {'schema': 'forge-build-id-request-v1', 'action': action, 'root': str(debug)}
        if action != 'remove':
            request.update(configs[index])
        else:
            request['buildId'] = build_id
        path = root / (action + '.request.json')
        path.write_text(json.dumps(request, indent=4) + '\n')
        output = run(action, [module / 'support/ghidra-dwarf-forge-build-id', '--java=' + str(args.java.resolve()),
            '--ghidra-dir=' + str(ghidra), '--request=' + str(path), '--request-sha256=' + digest(path)])
        result = json.loads(output.splitlines()[-1])
        assert result['outcome'] == {'install': 'INSTALLED', 'update': 'UPDATED', 'remove': 'REMOVED'}[action]
        assert not result['modifiesOriginal'] and result['buildId'] == build_id
        if action != 'remove':
            assert Path(result['registration']) == debug / relative
            assert Path(result['registration']).stat().st_nlink == 1
            generations.append(result)
        return result

    resolved = []
    for index, name in enumerate(['forge_profile_initial', 'forge_profile_curated']):
        installed = installer('install' if index == 0 else 'update', index)
        hidden = []
        try:
            for config in configs:
                for key in ['sidecar', 'source']:
                    path = Path(config['files'][key])
                    moved = path.with_name(path.name + '.hidden')
                    assert not moved.exists()
                    path.rename(moved)
                    hidden.append((path, moved))
            probe = run(name + '-probe', [args.perf, '--buildid-dir', cache, 'probe', '--symfs', symfs,
                '-x', original, '-L', name])
            assert installed['source'] in probe
            gdb = run(name + '-gdb', ['gdb', '-nx', '-q', '-batch', '-ex', 'set debuginfod enabled off',
                '-ex', installed['gdbSetupCommand'], '-ex', 'file ' + json.dumps(str(original)), '-ex',
                'python s=gdb.lookup_global_symbol(' + repr(name) + ') or gdb.lookup_static_symbol(' + repr(name) + '); '
                'assert s is not None and s.symtab is not None; '
                'assert s.symtab.fullname() == ' + repr(installed['source']) + '; print("INSTALLED_PERF_FIXTURE_GDB_PASS")'])
            assert 'INSTALLED_PERF_FIXTURE_GDB_PASS' in gdb
            if not args.prepare_only:
                found, report = sampled(name, symfs, name)
                if found:
                    assert installed['source'] in report
                else:
                    assert not compiler_dwarf_found, 'Forge fails where equivalent compiler DWARF-only control succeeds'
                resolved.append(found)
                assert ('forge_profile_initial' if index else 'forge_profile_curated') not in report
        finally:
            for path, moved in reversed(hidden):
                moved.rename(path)
    assert generations[0]['source'] != generations[1]['source']
    installer('remove')
    if not args.prepare_only:
        found, report = sampled('removed', symfs, 'forge_profile_curated')
        assert not found and 'forge_profile_initial' not in report and 'forge_profile_curated' not in report
        assert len(set(resolved)) == 1
    assert not list(cache.iterdir()), 'record/report unexpectedly mutated the private cache'
    assert protected == {p: digest(p) for p in protected}
    save('result.json', {'status': 'PREPARED_SAMPLING_UNVERIFIED' if args.prepare_only else 'PASS_PERF_CHARACTERIZATION',
        'role': args.role, 'versions': versions, 'buildId': build_id, 'originalSha256': original_hash,
        'compilerDwarfOnlySymbolization': compiler_dwarf_found,
        'installedRecoveredSymbolization': resolved[0] if resolved else None,
        'generations': generations, 'observations': observations, 'protectedInputs': protected,
        'scope': 'Native x86-64 software CPU-clock samples; compiler ELF-symbol and DWARF-only controls; '
            'real saved analyst names, production installer, hidden exports, explicit symfs; no perf-cache installation.'})
    print('build-id-perf-report=' + ('PREPARED_SAMPLING_UNVERIFIED' if args.prepare_only else 'PASS') + ' role=' + args.role)


if __name__ == '__main__':
    main()

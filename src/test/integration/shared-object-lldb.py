#!/usr/bin/env python3
"""Compare compiler and Forge symbols attached to a relocated shared library."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import lldb_consumer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixtures', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--suffix', default='ghidra-forge.dbg')
    parser.add_argument('--lldb', default='lldb-18')
    parser.add_argument('--discovery', action='store_true',
        help='discover both driver and library symbols from a private build-ID root')
    args = parser.parse_args()
    assert Path(args.suffix).name == args.suffix and args.suffix.endswith('.dbg')
    fixture = args.fixtures.resolve() / args.target
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    versions = lldb_consumer.versions(args.lldb, args.target)
    reference = fixture / 'libsemantic.so.reference'
    library = fixture / 'libsemantic.so.stripped'
    sidecar = fixture / ('libsemantic.so.' + args.suffix)
    driver = fixture / 'semantic.shared-driver.stripped'
    driver_reference = fixture / 'semantic.shared-driver.reference'
    scripts = Path(__file__).resolve().parent
    symbols = {}
    for line in subprocess.check_output(['readelf', '-Ws', str(reference)], text=True).splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('recovered_add', 'forge_stack_normal', 'forge_stack_changed', 'fixture_sink'):
            value = int(fields[1], 16)
            assert fields[7] not in symbols or symbols[fields[7]] == value
            symbols[fields[7]] = value
    assert len(symbols) == 4
    build_ids = []
    for artifact in (reference, library, sidecar):
        notes = subprocess.check_output(['readelf', '-n', str(artifact)], text=True)
        build_id, = re.findall(r'Build ID: ([0-9a-f]+)', notes)
        build_ids.append(build_id)
    assert len(set(build_ids)) == 1
    protected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (library, reference, sidecar, Path(str(sidecar) + '.c'), driver, driver_reference)}
    results = []
    for mode in ('compiler', 'forge'):
        config_path = root / (mode + '.json')
        output = root / mode
        symbols_file = reference if mode == 'compiler' else sidecar
        loaded_library, loaded_driver = library, driver
        setup = []
        if args.discovery:
            private = root / ('inputs-' + mode)
            private.mkdir()
            loaded_library, loaded_driver = private / library.name, private / driver.name
            shutil.copy2(library, loaded_library)
            shutil.copy2(driver, loaded_driver)
            debug_root = private / 'debug-root'
            for source in (symbols_file, driver_reference):
                build_id, = re.findall(r'Build ID: ([0-9a-f]+)',
                    subprocess.check_output(['readelf', '-n', str(source)], text=True))
                installed = debug_root / '.build-id' / build_id[:2] / (build_id[2:] + '.debug')
                installed.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, installed)
                protected[str(installed)] = hashlib.sha256(source.read_bytes()).hexdigest()
                if source == symbols_file:
                    symbols_file = installed
            protected[str(loaded_library)] = protected[str(library)]
            protected[str(loaded_driver)] = protected[str(driver)]
            setup = ['settings set symbols.enable-external-lookup false',
                'settings set target.debug-file-search-paths ' + shlex.quote(str(debug_root))]
        config_path.write_text(json.dumps({'mode': mode, 'target': args.target, 'library': str(loaded_library),
            'symbolsFile': str(symbols_file), 'buildId': build_ids[0], 'symbols': symbols,
            'source': str(sidecar) + '.c', 'referenceSources': str(scripts.parent / 'fixtures'),
            'observations': str(output / 'observations.json')}, indent=4) + '\n')
        before = ['breakpoint set --name main --skip-prologue false']
        if mode == 'compiler':
            before.insert(0, 'settings set target.source-map /ghidra-dwarf-forge-fixture ' +
                shlex.quote(str(scripts.parent / 'fixtures')))
        after = [] if args.discovery else ['script modules = [m for m in lldb.target.modules if m.GetFileSpec().fullpath == ' +
                repr(str(library)) + ']; assert len(modules) == 1 and modules[0].GetNumCompileUnits() == 0',
            'target symbols add --shlib ' + shlex.quote(str(library)) + ' ' + shlex.quote(str(symbols_file))]
        after += [
            'script exec(open(' + repr(str(scripts / 'shared-object-lldb-observe.py')) + ').read())',
            'script shared_setup()', 'image lookup --name recovered_add', 'source list --name recovered_add',
            'breakpoint set --name recovered_add --skip-prologue ' + ('false' if mode == 'forge' else 'true'), 'continue',
            "script shared_check('entry')", 'thread step-over', "script shared_check('step')",
            'script shared_resume_normal()', "script shared_check('normal')", 'continue',
            "script shared_check('changed')", 'continue', "script shared_check('exit')"]
        transcript = lldb_consumer.run(loaded_driver, None if args.discovery else driver_reference,
            output, args.lldb, args.target, before, after,
            {'FORGE_LLDB_SHARED_CONFIG': str(config_path)}, setup=setup)
        assert 'FORGE_LLDB_SHARED_CHECK_PASS exit' in transcript
        rows = json.loads((output / 'observations.json').read_text())
        assert [row['phase'] for row in rows] == ['entry', 'step', 'normal', 'changed', 'exit']
        assert protected == {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in protected}
        results.append({'mode': mode, 'observations': rows})
    for phase in ('entry', 'normal', 'changed'):
        compiler, forge = ([row for row in result['observations'] if row['phase'] == phase][0] for result in results)
        assert compiler['values']['fixture_sink'] == forge['values']['fixture_sink']
        if phase == 'entry':
            assert [compiler['values'][name] for name in ('left', 'right')] == [forge['values'][name] for name in ('left', 'right')]
        else:
            assert compiler['values']['sum'] == forge['values']['analyst_stack']
            assert compiler['pc'] - compiler['bias'] == forge['pc'] - forge['bias'] == symbols['forge_stack_' + phase]
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_LLDB_SHARED', 'target': args.target,
        'versions': versions, 'cases': results, 'protectedSha256': protected,
        'scope': 'Automatic build-ID discovery from a configured private root.' if args.discovery else
            'Explicit post-map symbol loading; automatic discovery is tested separately.'}, indent=4) + '\n')
    print('lldb-shared-object=PASS ' + args.target)


if __name__ == '__main__':
    main()

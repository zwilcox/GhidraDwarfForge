#!/usr/bin/env python3
"""Check selected GNU readelf on actual Windows Unicode and long ELF paths."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ['readelf', 'mingw-readelf', 'compiler', 'results']:
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    assert os.name == 'nt', 'native Windows is required'
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    selected = args.readelf.resolve(strict=True)
    mingw = args.mingw_readelf.resolve(strict=True)
    compiler = args.compiler.resolve(strict=True)
    protected = {str(p): digest(p) for p in [selected, mingw, compiler, Path(__file__)]}
    commands = []
    # Test direct Windows process invocation, without a shell or MSYS argument
    # conversion. Do not rely on the caller having selected a UTF-8 locale.
    environment = dict(os.environ)
    for key in ['LC_ALL', 'LC_CTYPE', 'LANG', 'LANGUAGE']:
        environment.pop(key, None)

    def run(name, command, selected_environment=None):
        command = list(map(str, command))
        child_environment = environment if selected_environment is None else selected_environment
        result = subprocess.run(command, env=child_environment, capture_output=True, timeout=90)
        (root / (name + '.stdout')).write_bytes(result.stdout)
        (root / (name + '.stderr')).write_bytes(result.stderr)
        commands.append({'name': name, 'command': command, 'exit': result.returncode,
            'locale': {key: child_environment.get(key) for key in ['LC_ALL', 'LC_CTYPE', 'LANG', 'LANGUAGE']}})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n', encoding='utf-8')
        return result

    source = root / 'fixture.c'
    source.write_text('int unicode_fixture_global = 17;\n'
        'int unicode_fixture(int value) { return value + unicode_fixture_global; }\n', encoding='utf-8')
    original = root / 'fixture.o'
    compiled = run('compile', [compiler, '--target=x86_64-linux-gnu', '-gdwarf-5', '-O0', '-c', source, '-o', original])
    assert compiled.returncode == 0 and not compiled.stderr
    assert original.read_bytes()[:6] == b'\x7fELF\x02\x01'
    paths = {'ascii': original, 'unicode': root / "debug λ 雪 'quote' $literal" / 'installed.debug'}
    directory = paths['unicode'].parent
    while len(str(directory / 'installed.debug')) < 360:
        directory /= 'long generation directory 0123456789'
    paths['long-unicode'] = directory / 'installed.debug'
    for name, path in paths.items():
        if name != 'ascii':
            path.parent.mkdir(parents=True, exist_ok=False)
            shutil.copyfile(original, path)
        protected[str(path)] = digest(path)

    versions = {}
    for name, tool in [('selected', selected), ('mingw', mingw)]:
        version = run(name + '-version', [tool, '--version'])
        assert version.returncode == 0 and not version.stderr and version.stdout.startswith(b'GNU readelf ')
        versions[name] = version.stdout.decode('utf-8').splitlines()[0]
    options = ['--wide', '-h', '-S', '-n', '--debug-dump=no-follow-links',
        '--debug-dump=info,abbrev,aranges,decodedline,loc,Ranges', '--']
    outputs = {}
    for name, path in paths.items():
        result = run('selected-' + name, [selected, *options, path])
        assert result.returncode == 0 and not result.stderr, (name, result.returncode, result.stderr)
        text = result.stdout.decode('utf-8')
        for marker in ['ELF Header:', 'Section Headers:', 'Contents of the .debug_info section:',
                'Contents of the .debug_abbrev section:', 'Contents of the .debug_line section:',
                'unicode_fixture_global', 'unicode_fixture']:
            assert marker in text, (name, marker)
        outputs[name] = result.stdout
    assert outputs['ascii'] == outputs['unicode'] == outputs['long-unicode'], 'path changed GNU interpretation'
    # ValidatorSupervisor deliberately sets the C locale for stable diagnostic
    # grammar. A default-locale subprocess alone does not prove this contract.
    supervisor_environment = dict(environment, LC_ALL='C', LANG='C', LANGUAGE='C')
    for name, path in paths.items():
        result = run('supervisor-locale-' + name, [selected, *options, path], supervisor_environment)
        assert result.returncode == 0 and not result.stderr, (name, result.returncode, result.stderr)
        assert result.stdout == outputs[name], ('supervisor locale changed GNU interpretation', name)
    reference = run('mingw-ascii', [mingw, *options, original])
    assert reference.returncode == 0 and not reference.stderr
    # Different binutils versions can format reports differently. Require each
    # semantic marker, while retaining exact outputs and versions for review.
    assert b'unicode_fixture_global' in reference.stdout and b'ELF Header:' in reference.stdout
    old = run('mingw-unicode', [mingw, *options, paths['unicode']])
    if old.returncode == 0:
        assert not old.stderr and b'unicode_fixture_global' in old.stdout
    else:
        assert b'No such file' in old.stderr, old.stderr
    malformed = paths['unicode'].parent / 'invalid.debug'
    malformed.write_bytes(b'not an ELF artifact\n')
    protected[str(malformed)] = digest(malformed)
    rejected = run('selected-malformed', [selected, *options, malformed])
    assert rejected.returncode != 0 and rejected.stderr and b'ELF Header:' not in rejected.stdout
    rejected = run('supervisor-locale-malformed', [selected, *options, malformed], supervisor_environment)
    assert rejected.returncode != 0 and rejected.stderr and b'ELF Header:' not in rejected.stdout
    assert protected == {path: digest(Path(path)) for path in protected}
    result = {'status': 'PASS_NATIVE_WINDOWS_GNU_READELF_PATHS', 'versions': versions,
        'mingwUnicodeSucceeded': old.returncode == 0, 'selectedReadelf': str(selected),
        'localeProfiles': ['unset', 'supervisor-C'],
        'pathLengths': {name: len(str(path)) for name, path in paths.items()},
        'protectedInputs': protected,
        'scope': 'Direct Windows invocation, compiler ELF/DWARF, ASCII/Unicode/long-path equivalence, '
            'malformed-input refusal and unchanged files. Full Java supervisor/installer acceptance remains separate.'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n', encoding='utf-8')
    print('windows-readelf-paths=PASS')


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Bounded C++ compiler/GDB language and vtable-symbol experiment for issue #113."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=('x86_64', 'aarch64'), default=('x86_64', 'aarch64'))
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    commands, observations = [], []
    protected = {str(HERE / 'fixture.cpp'): digest(HERE / 'fixture.cpp')}

    def run(label, argv):
        command = list(map(str, argv))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=150, check=True)
        return (root / (label + '.log')).read_text()

    for target in args.targets:
        prefix = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
        for role in ('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'):
            label = target + '-' + role
            case = root / label
            case.mkdir()
            source = case / 'fixture.cpp'
            source.write_bytes((HERE / 'fixture.cpp').read_bytes())
            # A changed source suffix keeps GDB's automatic C11 experiment in C.
            # This remains compiler C++ text, never a claim of generated C source.
            (case / 'fixture.c').write_bytes(source.read_bytes())
            reference, runtime = case / 'reference.elf', case / 'runtime.elf'
            run(label + '-compile', [prefix + 'g++', '-std=c++17', '-O0', '-g', '-gdwarf-5', '-fno-inline',
                *(['-fPIE', '-pie'] if role.startswith('pie') else ['-fno-pie', '-no-pie']),
                *(['-fno-rtti'] if role.endswith('no-rtti') else []), source, '-o', reference])
            run(label + '-strip', [prefix + 'objcopy', '--strip-all', reference, runtime])
            protected.update({str(p): digest(p) for p in (reference, runtime)})
            info = run(label + '-info', ['readelf', '-W', '--debug-dump=info', reference])
            assert 'DW_TAG_inheritance' in info and 'DW_AT_vtable_elem_location' in info and 'DW_AT_virtuality' in info
            symbols = run(label + '-symbols', ['readelf', '-Ws', reference])
            assert '_ZTV' in symbols and '_ZTh' in symbols and '_ZTv' in symbols
            assert ('_ZTI' not in symbols) == role.endswith('no-rtti')
            section_text = run(label + '-reference-sections', ['readelf', '-SW', reference])
            section_addresses = {int(index): (name, int(address, 16)) for index, name, address in
                re.findall(r'\[\s*(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s', section_text)}
            vtables = []
            for address, index, name in re.findall(
                    r'^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+OBJECT\s+\S+\s+\S+\s+(\d+)\s+(_ZTV\S+)\s*$', symbols, re.M):
                # Fixture classes are global. Exclude ABI runtime type_info
                # vtables supplied by copy relocations in non-PIE executables.
                if not re.fullmatch(r'_ZTV\d+(?:Base|Single|Left|Right|Multiple|VirtualBase|VirtualLeft|VirtualRight|Diamond|Abstract|Concrete)', name):
                    continue
                section, base = section_addresses[int(index)]
                vtables.append((name, section, int(address, 16) - base))
            assert {'_ZTV6Single', '_ZTV8Multiple', '_ZTV7Diamond'} <= {row[0] for row in vtables}, vtables
            language, = re.findall(r'<([0-9a-f]+)>\s+DW_AT_language\s*:\s*\(data1\) (\d+)', info)
            sections = {}
            for name in ('.debug_info', '.debug_line_str'):
                path = case / (name + '.original')
                run(label + '-dump-' + name, [prefix + 'objcopy', '--dump-section', name + '=' + str(path),
                    reference, case / 'inspection.elf'])
                sections[name] = path.read_bytes()
            (case / 'inspection.elf').unlink()
            for variant in ('cpp', 'cpp-no-symbols', 'cpp-vtables', 'c11', 'c11-no-symbols', 'c11-vtables'):
                artifact = case / (variant + '.dbg')
                run(label + '-' + variant + '-copy', [prefix + 'objcopy', '--only-keep-debug', reference, artifact])
                if variant.startswith('c11'):
                    data = bytearray(sections['.debug_info'])
                    assert data[int(language[0], 16)] == int(language[1])
                    data[int(language[0], 16)] = 0x1d
                    strings = sections['.debug_line_str']
                    assert b'fixture.cpp\0' in strings
                    strings = strings.replace(b'fixture.cpp\0', b'fixture.c\0\0\0')
                    replacements = []
                    for name, content in (('.debug_info', data), ('.debug_line_str', strings)):
                        path = case / (variant + name)
                        path.write_bytes(content)
                        replacements += ['--update-section', name + '=' + str(path)]
                    run(label + '-' + variant + '-edit', [prefix + 'objcopy', *replacements, artifact])
                run(label + '-' + variant + '-strip-symbols', [prefix + 'objcopy',
                    *(['--strip-all', '--keep-section=.debug*'] if variant not in ('cpp', 'c11') else []),
                    '--remove-section=.eh_frame', '--remove-section=.eh_frame_hdr', artifact])
                layout = run(label + '-' + variant + '-sections', ['readelf', '-SW', artifact])
                if variant not in ('cpp', 'c11'):
                    assert not re.search(r'\s\.(?:symtab|strtab)\s', layout)
                    assert re.search(r'\s\.dynsym\s+NOBITS\s', layout)
                if variant.endswith('vtables'):
                    additions = []
                    for name, section, offset in vtables:
                        additions += ['--add-symbol', name + '=' + section + ':0x' + format(offset, 'x') + ',global,object']
                    run(label + '-' + variant + '-vtable-symbols', [prefix + 'objcopy', *additions, artifact])
                    restored = run(label + '-' + variant + '-symbol-inventory', ['readelf', '-Ws', artifact])
                    entries = re.findall(r'^\s*\d+:\s+[0-9a-f]+\s+\d+\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$', restored, re.M)
                    named = {(kind, name) for kind, name in entries if kind != 'SECTION'}
                    assert named == {('OBJECT', row[0]) for row in vtables}, named
                run(label + '-' + variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
                strict = run(label + '-' + variant + '-strict', [os.environ.get('DWARFDUMP', 'dwarfdump'), artifact])
                assert not re.search(r'warning:|error:', strict, re.I), strict
                run(label + '-' + variant + '-gdb', ['bash', HERE / 'gdb.sh', case, target, variant])
                observed = json.loads((case / (variant + '.gdb.json')).read_text())
                assert observed['status'] == 'PASS_REFERENCE_OBSERVATION'
                observations.append({'target': target, 'role': role, 'variant': variant, 'observed': observed})
    assert all(digest(Path(p)) == value for p, value in protected.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_REFERENCE_EXPERIMENT',
        'scope': 'compiler DWARF and controlled research copies, not Forge export acceptance',
        'preservedSha256': protected, 'observations': observations}, indent=4) + '\n')
    print('inheritance-reference=PASS', root)


if __name__ == '__main__':
    main()

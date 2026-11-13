#!/usr/bin/env python3
"""Package compiler inheritance DIEs through Forge's writer with proved vtable symbols."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--classpath', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    args = parser.parse_args()
    references = args.references.resolve(strict=True)
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    commands, observations, protected = [], [], {}
    java = str(Path(os.environ['JAVA_HOME']) / 'bin/java') if os.environ.get('JAVA_HOME') else 'java'

    def run(label, argv):
        command = list(map(str, argv))
        commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=150, check=True)
        return (root / (label + '.log')).read_text()

    for target in ('x86_64', 'aarch64'):
        for role in ('exec', 'pie', 'exec-no-rtti', 'pie-no-rtti'):
            label = target + '-' + role
            reference = references / label
            case = root / label
            case.mkdir()
            original = reference / 'runtime.elf'
            runtime = case / 'runtime.elf'
            shutil.copy2(original, runtime)
            protected.update({str(p): digest(p) for p in (original, runtime, reference / 'reference.elf')})
            layout = run(label + '-sections', ['readelf', '-SW', reference / 'reference.elf'])
            sections = {int(index): (name, int(address, 16)) for index, name, address in
                re.findall(r'\[\s*(\d+)\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s', layout)}
            inventory = run(label + '-reference-symbols', ['readelf', '-Ws', reference / 'reference.elf'])
            dynamic = run(label + '-dynamic-symbols', ['readelf', '--dyn-syms', '-W', runtime])
            required_objects = re.findall(
                r'^\s*\d+:\s+[0-9a-f]+\s+\d+\s+OBJECT\s+\S+\s+\S+\s+\d+\s+(\S+@[^@\s]+)(?:\s+\(\d+\))?\s*$', dynamic, re.M)
            if target == 'x86_64' and role == 'exec':
                assert required_objects, 'missing compiler copy-relocation regression'
            symbols = []
            for address, size, index, name in re.findall(
                    r'^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+OBJECT\s+\S+\s+\S+\s+(\d+)\s+(_ZTV\S+)\s*$', inventory, re.M):
                if not re.fullmatch(r'_ZTV\d+(?:Base|Single|Left|Right|Multiple|VirtualBase|VirtualLeft|VirtualRight|Diamond)', name):
                    continue
                section, base = sections[int(index)]
                symbols.append({'name': name, 'address': int(address, 16), 'size': int(size),
                    'section': section, 'sectionAddress': base})
            assert {'_ZTV6Single', '_ZTV8Multiple', '_ZTV7Diamond'} <= {r['name'] for r in symbols}
            model = case / 'symbols.json'
            model.write_text(json.dumps(sorted(symbols, key=lambda s: s['name']), indent=4) + '\n')
            for language in ('cpp', 'c11'):
                variant = language + '-vtables'
                debug = reference / (language + '-no-symbols.dbg')
                protected[str(debug)] = digest(debug)
                artifact = case / (variant + '.dbg')
                text = run(label + '-' + variant + '-package', [java, '-cp', args.classpath.read_text().strip(),
                    'ghidradwarfforge.elf.VtablePackagingProbe', runtime, debug, model, artifact])
                assert 'vtable-packaging=PASS' in text
                emitted = run(label + '-' + variant + '-elf', ['readelf', '-hSWn', '-Ws', artifact])
                static = emitted.split("Symbol table '.symtab'", 1)[1]
                for name in required_objects:
                    assert re.search(r'\s' + re.escape(name) + r'\s*$', static, re.M), name
                    assert name.replace('@', '@@') not in static, name
                for symbol in symbols:
                    assert re.search(r'\bOBJECT\s+LOCAL\s+DEFAULT\s+\d+\s+' + re.escape(symbol['name']) + r'\s*$', emitted, re.M)
                assert 'warning:' not in emitted.lower() and 'error:' not in emitted.lower()
                decoded = run(label + '-' + variant + '-gnu', ['readelf',
                    '--debug-dump=info,abbrev,aranges,decodedline', artifact])
                assert not re.search(r'warning:|error:', decoded, re.I), decoded
                verified = run(label + '-' + variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
                assert 'No errors.' in verified
                checked = run(label + '-' + variant + '-strict', [os.environ.get('DWARFDUMP', 'dwarfdump'), artifact])
                assert not re.search(r'warning:|error:', checked, re.I), checked
                run(label + '-' + variant + '-gdb', ['bash', HERE / 'gdb.sh', case, target, variant])
                actual = json.loads((case / (variant + '.gdb.json')).read_text())
                expected = json.loads((reference / (variant + '.gdb.json')).read_text())
                assert actual['status'] == 'PASS_REFERENCE_OBSERVATION'
                for field in ('dynamicTypes', 'baseValues', 'offsets', 'language'):
                    assert actual[field] == expected[field], (field, actual[field], expected[field])
                observations.append({'target': target, 'role': role, 'language': language,
                    'artifactSha256': digest(artifact), 'observed': actual})
    assert all(digest(Path(p)) == value for p, value in protected.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_PRODUCTION_VTABLE_PACKAGING',
        'scope': 'production ELF writer with compiler-owned DWARF/evidence; no Ghidra inheritance emission',
        'preservedSha256': protected, 'observations': observations}, indent=4) + '\n')
    print('inheritance-packaging=PASS', root)


if __name__ == '__main__':
    main()

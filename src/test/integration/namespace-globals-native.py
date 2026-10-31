#!/usr/bin/env python3
"""Packaged producer: cold qualified lookup, namespace ownership and collision controls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from alias_relationships import read_dies, value


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=['x86_64', 'aarch64'])
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    harness = root / 'src/test/integration'
    research = root / 'src/test/research/namespace-globals'
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar, native = module / 'lib/GhidraDwarfForge.jar', module / 'os/linux_x86_64'
    test = root / 'src/test/java/ghidradwarfforge/nativeapi/NamespaceGlobalLookupSmoke.java'
    parent = root / 'build/test-results/namespace-globals-native'
    parent.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-', dir=parent))
    print('namespace-globals-native-results=' + str(case), flush=True)
    protected = {str(p): digest(p) for p in [Path(__file__), test, research / 'fixture.cpp',
        research / 'runtime.py', research / 'runtime.sh', harness / 'qemu-socket.sh',
        harness / 'alias_relationships.py', harness / 'check-dwarfdump.py',
        *[p for p in module.rglob('*') if p.is_file()]]}
    commands = []

    def run(label, argv):
        argv = list(map(str, argv))
        commands.append({'label': label, 'argv': argv})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        result = subprocess.run(argv, capture_output=True, text=True, timeout=180)
        (case / (label + '.log')).write_text(result.stdout)
        (case / (label + '.stderr')).write_text(result.stderr)
        assert result.returncode == 0, (label, result.returncode, result.stderr)
        return result.stdout

    prefix = '' if args.target == 'x86_64' else 'aarch64-linux-gnu-'
    run('compile', [prefix + 'g++', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie',
        research / 'fixture.cpp', '-o', case / 'reference'])
    run('strip', [prefix + 'objcopy', '--strip-all', case / 'reference', case / 'input'])
    symbols = {}
    for line in run('symbols', [prefix + 'nm', '-S', '-C', case / 'reference']).splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[3] in ['left::item', 'right::item', 'left::unique_value', 'item', 'marker']:
            symbols[fields[3]] = int(fields[0], 16)
            if fields[3] == 'marker':
                symbols['marker.size'] = int(fields[1], 16)
    assert len(symbols) == 6
    (case / 'symbols.json').write_text(json.dumps(symbols, indent=4) + '\n')
    protected.update({str(p): digest(p) for p in [case / 'reference', case / 'input']})
    classes = case / 'classes'
    classes.mkdir()
    cp = os.pathsep.join(map(str, [jar, classes,
        *sorted(p for p in ghidra.rglob('*.jar') if 'Extensions' not in p.parts)]))
    run('javac', ['javac', '--release', '21', '-proc:none', '-cp', cp, '-d', classes, test])
    artifacts = []
    for variant in ['normal', 'type-short', 'enum-short', 'function-short',
            'type-full', 'enum-full', 'function-full', 'global-full']:
        artifact = case / (variant + '.dbg')
        produced = run(variant + '-producer', ['java', '--enable-native-access=ALL-UNNAMED', '-cp', cp,
            'ghidradwarfforge.nativeapi.NamespaceGlobalLookupSmoke', native / 'libdwarf.so.2.3.2',
            native / 'libdwarfp.so.2.3.2', case / 'input', artifact, case / 'symbols.json', variant])
        assert 'PASS java=21.' in produced and str(jar) in produced
        rows = read_dies(artifact, case / (variant + '-info.log'))
        parents, stack = {}, []
        for row in rows:
            stack = stack[:row['depth']]
            parents[row['offset']] = stack[-1] if stack else None
            stack.append(row)
        named = lambda row: value(row['attrs'].get('DW_AT_name', ''))
        full_conflict = variant.endswith('full')
        for name in ['left::item', 'right::item', 'left::unique_value', 'item', 'left::missing']:
            candidates = [row for row in rows if row['tag'] == 'DW_TAG_variable' and
                (name != 'item' or row['depth'] == 1) and
                (named(row) == name if name != 'left::item' or not full_conflict else
                    named(row) == 'item' and named(parents[row['offset']]) == 'left')]
            variable, = candidates
            if name == 'left::item' and full_conflict:
                assert variable['depth'] == 2
                assert 'Omitted qualified global lookup left::item' in produced
            else:
                assert variable['depth'] == 1
            if name.endswith('missing'):
                assert 'DW_AT_location' not in variable['attrs']
                assert variable['attrs']['DW_AT_declaration'] == '1'
            else:
                address = int(re.search(r'DW_OP_addr: ([0-9a-f]+)', variable['attrs']['DW_AT_location'])[1], 16)
                assert address == symbols[name]
            imports = [row for row in rows if row['tag'] == 'DW_TAG_imported_declaration' and
                int(re.match(r'<0x([0-9a-f]+)>', row['attrs']['DW_AT_import'])[1], 16) == variable['offset']]
            if '::' in name and not (name == 'left::item' and full_conflict):
                association, = imports
                assert named(parents[association['offset']]) == name.split('::')[0]
                assert set(association['attrs']) <= {'DW_AT_name', 'DW_AT_import'}
                if name.endswith('::item') or (name.endswith('unique_value') and variant.endswith('short')):
                    assert 'DW_AT_name' not in association['attrs']
            else:
                assert not imports
        for view in ['abbrev', 'aranges', 'decodedline']:
            run(variant + '-' + view, ['readelf', '--debug-dump=' + view, artifact])
        assert 'No errors.' in run(variant + '-llvm', ['llvm-dwarfdump', '--verify', artifact])
        run(variant + '-strict', ['python3', harness / 'check-dwarfdump.py', artifact,
            case / (variant + '-strict.log'), '--original', case / 'input'])
        # Each query starts a fresh debugger; preceding expansion cannot hide lookup defects.
        queries = [("print /x &'right::item'", hex(symbols['right::item'])),
            ("print /x &'left::unique_value'", hex(symbols['left::unique_value']))]
        if not full_conflict:
            queries.append(("print /x &'left::item'", hex(symbols['left::item'])))
        collision = 'left::item' if full_conflict else 'unique_value'
        if variant.startswith('type-'):
            queries.append(("ptype '" + collision + "'", 'type = int'))
        elif variant.startswith('enum-'):
            queries.append(("print (int)'" + collision + "'", '= 73'))
        elif variant.startswith('function-'):
            queries.append(("print /x &'" + collision + "'", hex(symbols['marker'])))
        elif variant == 'global-full':
            queries.append(("print /x &'left::item'", hex(symbols['left::unique_value'])))
        for index, (query, expected) in enumerate(queries):
            observed = run(variant + '-cold-' + str(index), ['gdb-multiarch', '-q', '-nx', '-batch',
                '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
                '-ex', 'file ' + str(case / 'input'), '-ex', 'symbol-file ' + str(artifact),
                '-ex', 'set language c', '-ex', query])
            assert expected in observed, (variant, query, expected, observed)
        artifacts.append({'variant': variant, 'sha256': digest(artifact), 'coldQueries': queries})
    shutil.copyfile(case / 'normal.dbg', case / 'root-qualified-import.dbg')
    for mode in ['compiler', 'selected']:
        run(mode + '-runtime', ['bash', research / 'runtime.sh', case, args.target, mode])
    compiler = json.loads((case / 'compiler-runtime.json').read_text())
    selected = json.loads((case / 'selected-runtime.json').read_text())
    assert compiler['status'] == selected['status'] == 'PASS'
    assert compiler['values'] == selected['values'] and compiler['addresses'] == selected['addresses']
    assert selected['shortUnique'] == 41 and compiler['return'] == selected['return'] == 140
    assert protected == {p: digest(Path(p)) for p in protected}
    (case / 'acceptance.json').write_text(json.dumps({'status': 'NAMESPACE_GLOBAL_NATIVE_PASS',
        'target': args.target, 'jarSha256': digest(jar), 'protected': protected,
        'artifacts': artifacts, 'compiler': compiler, 'selected': selected}, indent=4) + '\n')
    print('namespace-globals-native=PASS', flush=True)


if __name__ == '__main__':
    main()

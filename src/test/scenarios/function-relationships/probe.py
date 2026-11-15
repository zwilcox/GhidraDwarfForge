#!/usr/bin/env python3
"""Isolated production-emitter relationship experiment; no Ghidra extraction claim."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('jdk', type=Path)
    parser.add_argument('native', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', choices=['x86_64', 'aarch64'])
    parser.add_argument('--jar', type=Path, help='Test this packaged production JAR')
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    repository = directory.parents[3]
    ghidra, jdk, native = (p.resolve(strict=True) for p in [args.ghidra, args.jdk, args.native])
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (out / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (out / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=240, check=True)
        return (out / (label + '.log')).read_text()

    jar = (args.jar or repository / 'build/libs/GhidraDwarfForge.jar').resolve(strict=True)
    fixture = repository / 'src/test/fixtures/curated-thunk.c'
    sources = [repository / 'src/test/java/ghidradwarfforge' / relative for relative in
        ['types/FunctionRelationsSmoke.java', 'elf/FunctionRelationshipProducer.java']]
    protected = {str(p): digest(p) for p in [jar, fixture, *sources, *sorted(directory.iterdir())] if p.is_file()}
    classes = out / 'classes'
    classes.mkdir()
    classpath = ':'.join(map(str, [jar, classes, *sorted(p for p in ghidra.rglob('*.jar') if 'Extensions' not in p.parts)]))
    run('javac21', [jdk / 'bin/javac', '--release', '21', '-proc:none', '-cp', classpath, '-d', classes, *sources])
    run('model', [jdk / 'bin/java', '-cp', classpath, 'ghidradwarfforge.types.FunctionRelationsSmoke'])
    rows = []
    harness = repository / 'src/test/integration'
    for target in ([args.target] if args.target else ['x86_64', 'aarch64']):
        prefix = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
        for role in ['exec', 'pie']:
            case = out / (target + '-' + role)
            case.mkdir()
            name = case.name
            flags = ['-fno-pie', '-no-pie'] if role == 'exec' else ['-fPIE', '-pie']
            run(name + '-compile', [prefix + 'gcc', '-O2', '-g', '-gdwarf-5', *flags, fixture, '-o', case / 'reference'])
            run(name + '-strip', [prefix + 'objcopy', '--strip-debug', case / 'reference', case / 'input'])
            protected.update({str(p): digest(p) for p in [case / 'reference', case / 'input']})
            nm = run(name + '-symbols', [prefix + 'nm', '-S', case / 'reference'])
            symbols = {}
            for line in nm.splitlines():
                fields = line.split()
                if len(fields) == 4 and fields[-1] in ['gateway', 'implementation']:
                    symbols[fields[-1]] = {'entry': int(fields[0], 16), 'size': int(fields[1], 16)}
            assert len(symbols) == 2
            (case / 'symbols.json').write_text(json.dumps(symbols, indent=4) + '\n')
            run(name + '-disassembly', [prefix + 'objdump', '-d', case / 'reference'])
            run(name + '-compiler-llvm', ['llvm-dwarfdump', '--verify', case / 'reference'])
            for variant in ['compiler', 'plain', 'related', 'external', 'failed', 'bad-hash', 'bad-owner', 'collision']:
                if variant != 'compiler':
                    log = run(name + '-' + variant + '-producer', [jdk / 'bin/java', '--enable-native-access=ALL-UNNAMED',
                        '-cp', classpath, 'ghidradwarfforge.elf.FunctionRelationshipProducer', native / 'libdwarf.so.2.3.2',
                        native / 'libdwarfp.so.2.3.2', case / 'input', case / (variant + '.dbg'), case / 'symbols.json', variant])
                    assert 'PASS java=21.' in log
                    for view in ['info', 'abbrev', 'aranges', 'decodedline']:
                        text = run(name + '-' + variant + '-' + view, ['readelf', '--debug-dump=' + view, case / (variant + '.dbg')])
                        assert 'Warning:' not in text
                    info = (out / (name + '-' + variant + '-info.log')).read_text()
                    assert info.count('DW_AT_trampoline') == int(variant != 'plain')
                    accepted_alias = variant not in ['bad-hash', 'bad-owner', 'collision']
                    assert info.count('DW_TAG_imported_declaration') == int(accepted_alias) and info.count('DW_AT_import ') == int(accepted_alias)
                    assert 'DW_AT_abstract_origin' not in info and 'DW_AT_specification' not in info
                    assert len(re.findall(r'^ <\d+><[0-9a-f]+>: Abbrev Number: \d+ \(DW_TAG_subprogram\)', info, re.M)) == 2 + int(variant == 'external'), 'no overlapping alias definition'
                    records = []
                    for line in info.splitlines():
                        header = re.match(r'^ <(\d+)><([0-9a-f]+)>: Abbrev Number: \d+ \((DW_TAG_\w+)\)', line)
                        if header:
                            records.append({'offset': int(header[2], 16), 'tag': header[3], 'attrs': {}})
                        elif records:
                            attr = re.match(r'^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)', line)
                            if attr:
                                records[-1]['attrs'][attr[1]] = attr[2]
                    def named(tag, value):
                        row, = [r for r in records if r['tag'] == tag and
                            r['attrs'].get('DW_AT_name', '').rsplit(': ', 1)[-1] == value]
                        return row
                    destination = named('DW_TAG_subprogram', 'implementation')
                    gateway = named('DW_TAG_subprogram', 'analyst_gateway')
                    assert int(destination['attrs']['DW_AT_low_pc'], 16) == symbols['implementation']['entry']
                    assert int(gateway['attrs']['DW_AT_low_pc'], 16) == symbols['gateway']['entry']
                    if accepted_alias:
                        alias = named('DW_TAG_imported_declaration', 'analyst_alias')
                        assert set(alias['attrs']) == {'DW_AT_name', 'DW_AT_import'}, 'alias must remain addressless'
                        assert int(re.match(r'<0x([0-9a-f]+)>', alias['attrs']['DW_AT_import'])[1], 16) == destination['offset']
                    if variant != 'plain':
                        expected_target = destination
                        if variant == 'external':
                            expected_target = named('DW_TAG_subprogram', 'external_target')
                            assert expected_target['attrs']['DW_AT_declaration'] == '1'
                            assert not any(a in expected_target['attrs'] for a in ['DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges'])
                        assert int(re.match(r'<0x([0-9a-f]+)>', gateway['attrs']['DW_AT_trampoline'])[1], 16) == expected_target['offset']
                    else:
                        assert 'DW_AT_trampoline' not in gateway['attrs']
                    assert 'DW_AT_trampoline' not in destination['attrs']
                    if variant == 'failed':
                        assert not any(a in gateway['attrs'] for a in ['DW_AT_type', 'DW_AT_decl_line', 'DW_AT_decl_file'])
                        assert info.count('DW_TAG_formal_parameter') == 1, 'failed thunk must not inherit destination parameters'
                    if not accepted_alias:
                        assert 'Omitted function alias ' in log
                    assert 'No errors.' in run(name + '-' + variant + '-llvm', ['llvm-dwarfdump', '--verify', case / (variant + '.dbg')])
                    run(name + '-' + variant + '-strict', ['python3', harness / 'check-dwarfdump.py', case / (variant + '.dbg'),
                        case / (variant + '-dwarfdump.log'), '--original', case / 'input'])
                if variant not in ['compiler', 'plain', 'related']:
                    continue  # Serialization controls do not claim runtime target identity.
                log = run(name + '-' + variant + '-gdb', ['bash', directory / 'gdb-probe.sh', case, target, variant])
                assert 'function-relationships-gdb=' + variant + ' PASS' in log
            observed = [json.loads((case / (v + '-gdb.json')).read_text()) for v in ['compiler', 'plain', 'related']]
            assert all(row['argument'] == 19 and row['return'] == 39 and row['steps'] == observed[0]['steps'] for row in observed)
            if role == 'pie':
                assert all(row['bias'] != 0 for row in observed)
            def warnings(variant):
                text = (out / (name + '-' + variant + '-gdb.log')).read_text()
                return Counter(re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in text.splitlines()
                    if re.match(r'\s*(warning:|error:)', line, re.I))
            assert warnings('compiler') == warnings('plain') == warnings('related')
            rows.append({'target': target, 'role': role, 'observations': observed})
            print(name + ' PASS', flush=True)
    assert protected == {p: digest(Path(p)) for p in protected}
    (out / 'acceptance.json').write_text(json.dumps({'status': 'ISOLATED_RELATIONSHIPS_PASS', 'cases': rows, 'serializationControlsPerCase': ['external', 'failed', 'bad-hash', 'bad-owner', 'collision'],
        'protected': protected, 'savedGhidraExtraction': 'not exercised by this isolated probe', 'fullGoalComplete': False}, indent=4) + '\n')


if __name__ == '__main__':
    main()

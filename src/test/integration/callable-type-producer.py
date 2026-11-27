#!/usr/bin/env python3
"""Validate explicit variadic/unnamed callable metadata without inventing locations."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from integration_coverage import Collection


FIXTURE = '''extern _Noreturn void declared_only(int, ...);
__attribute__((noinline)) int forge_variadic(int first, ...) { return first; }
int (*forge_callback)(int, ...) = forge_variadic;
__attribute__((noinline)) int forge_probe(void) { return forge_callback(37, 9); }
int main(void) { return forge_probe() != 37; }
'''
MODES = ('normal', 'unknown', 'blocked')
SYMBOLS = ('forge_probe', 'forge_variadic', 'forge_callback')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check(nodes, mode, symbols):
    def unique(tag, name):
        matches = [n for n in nodes.values() if n['tag'] == 'DW_TAG_' + tag and n['name'] == name]
        assert len(matches) == 1, ('unique', tag, name)
        return matches[0]

    def reference(node):
        match = re.fullmatch(r'<0x([0-9a-f]+)>', node['attributes'].get('DW_AT_type', ''))
        assert match and int(match[1], 16) in nodes, 'type reference'
        return nodes[int(match[1], 16)]

    def signature(node, variadic, returned=True):
        attributes = node['attributes']
        expected = {'normal': 1, 'unknown': None, 'blocked': 3}[mode]
        actual = attributes.get('DW_AT_calling_convention')
        assert (actual is None if expected is None else actual is not None and
            int(actual.split()[0], 0) == expected), 'calling convention'
        assert attributes.get('DW_AT_prototyped') == '1', 'prototype flag'
        if returned:
            target = reference(node)
            assert target['tag'] == 'DW_TAG_base_type' and target['name'] == 'int', 'return type'
        else:
            assert 'DW_AT_type' not in attributes, 'void return invented type'
        children = [n for n in nodes.values() if n['parent'] == node['offset']]
        expected_tags = ['DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters'] if variadic else []
        assert [n['tag'] for n in children] == expected_tags, 'variadic parameter children'
        if variadic:
            parameter, unspecified = children
            assert 'DW_AT_name' not in parameter['attributes'], 'unnamed parameter acquired name'
            assert 'DW_AT_location' not in parameter['attributes'], 'unproven parameter acquired location'
            assert reference(parameter)['name'] == 'int', 'parameter type'
            assert not unspecified['attributes'], 'ellipsis acquired attributes'

    callable_type = unique('subroutine_type', 'ForgeCallback')
    signature(callable_type, True)
    declaration = unique('subprogram', 'declared_only')
    signature(declaration, True, False)
    attributes = declaration['attributes']
    assert attributes.get('DW_AT_declaration') == attributes.get('DW_AT_external') == '1', 'declaration flags'
    assert attributes.get('DW_AT_noreturn') == '1', 'noreturn flag'
    assert not set(attributes).intersection({'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_entry_pc',
        'DW_AT_ranges', 'DW_AT_location'}), 'declaration acquired address'
    for name in SYMBOLS[:2]:
        function = unique('subprogram', name)
        signature(function, name == 'forge_variadic')
        assert int(function['attributes']['DW_AT_low_pc'], 0) == symbols[name]['address'], 'function address'
        assert int(function['attributes']['DW_AT_high_pc'], 0) == symbols[name]['size'], 'function size'
    global_value = unique('variable', 'forge_callback')
    pointer = reference(global_value)
    assert pointer['tag'] == 'DW_TAG_pointer_type' and pointer['attributes'].get('DW_AT_byte_size') == '8', 'pointer shape'
    assert reference(pointer)['offset'] == callable_type['offset'], 'pointer target'
    location = global_value['attributes'].get('DW_AT_location', '')
    address = re.search(r'\(DW_OP_addr: ([0-9a-f]+)\)$', location)
    assert address and int(address[1], 16) == symbols['forge_callback']['address'], 'global address'
    return callable_type, declaration


def oracle(info, mode, symbols, parser):
    nodes = parser.read_dies(info)
    callable_type, declaration = check(nodes, mode, symbols)
    parameter = next(n for n in nodes.values() if n['parent'] == callable_type['offset'] and
        n['tag'] == 'DW_TAG_formal_parameter')
    ellipsis = next(n for n in nodes.values() if n['parent'] == callable_type['offset'] and
        n['tag'] == 'DW_TAG_unspecified_parameters')
    mutations = [
        ('ellipsis', ellipsis['offset'], None, None),
        ('unnamed', parameter['offset'], 'DW_AT_name', 'invented'),
        ('location', parameter['offset'], 'DW_AT_location', '(DW_OP_reg0)'),
        ('declaration-address', declaration['offset'], 'DW_AT_low_pc', '0x1000'),
        ('noreturn', declaration['offset'], 'DW_AT_noreturn', '0'),
        ('convention', callable_type['offset'], 'DW_AT_calling_convention', '2'),
        ('void-return', declaration['offset'], 'DW_AT_type', parameter['attributes']['DW_AT_type']),
    ]
    rejected = []
    for label, offset, attribute, value in mutations:
        changed = copy.deepcopy(nodes)
        if attribute is None:
            del changed[offset]
        else:
            changed[offset]['attributes'][attribute] = value
        try:
            check(changed, mode, symbols)
        except AssertionError:
            rejected.append(label)
        else:
            raise AssertionError('callable oracle accepted ' + label)
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('jar', 'consumer', 'producer', 'ghidra', 'java-home', 'results'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    assert sys.platform == 'linux' and os.uname().machine == 'x86_64'
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[3]
    java_source = repo / 'src/test/java/ghidradwarfforge/nativeapi/CallableTypeProducerProbe.java'
    parser_path = Path(__file__).with_name('check-object-parameters.py')
    spec = importlib.util.spec_from_file_location('callable_dies', parser_path)
    dies = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dies)
    harnesses = [java_source, Path(__file__), parser_path, Path(__file__).with_name('check-dwarfdump.py'),
        Path(__file__).with_name('integration_coverage.py')]
    protected = {str(p.resolve()): digest(p) for p in [args.jar, args.consumer, args.producer, *harnesses]}
    commands = []

    def run(label, command):
        command = list(map(str, command))
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
        (root / (label + '.stdout')).write_text(result.stdout)
        (root / (label + '.stderr')).write_text(result.stderr)
        commands.append({'label': label, 'command': command, 'exit': result.returncode})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert result.returncode == 0, (label, result.stderr)
        return result.stdout

    (root / 'fixture.c').write_text(FIXTURE)
    reference, binary = root / 'reference', root / 'input'
    run('compile', ['cc', '-std=c11', '-O0', '-gdwarf-5', '-fno-pie', '-no-pie', root / 'fixture.c', '-o', reference])
    header = reference.read_bytes()[:64]
    assert header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[16:18], 'little') == 2
    assert int.from_bytes(header[18:20], 'little') == 62
    run('strip', ['objcopy', '--strip-all', reference, binary])
    protected.update({str(p): digest(p) for p in (reference, binary)})
    symbols = {}
    for line in run('nm', ['nm', '-S', '--defined-only', reference]).splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] in SYMBOLS:
            symbols[parts[3]] = {'address': int(parts[0], 16), 'size': int(parts[1], 16)}
    assert set(symbols) == set(SYMBOLS)
    (root / 'request.json').write_text(json.dumps(symbols, indent=4) + '\n')
    classes = root / 'classes'
    classes.mkdir()
    jna, = args.ghidra.glob('Ghidra/Framework/Pty/lib/jna-[0-9]*.jar')
    gson, = args.ghidra.glob('Ghidra/Framework/Generic/lib/gson-[0-9]*.jar')
    cp = os.pathsep.join(map(str, [args.jar.resolve(), classes, jna.resolve(), gson.resolve()]))
    run('javac', [args.java_home / 'bin/javac', '--release', '25', '-cp', cp, '-d', classes, java_source])
    coverage = Collection('callable-type-producer', args.jar.resolve(), 'native-java',
        test_classes=('ghidradwarfforge.nativeapi.CallableTypeProducerProbe',))
    command = list(map(str, [args.java_home / 'bin/java', '--enable-native-access=ALL-UNNAMED', '-cp', cp,
        'ghidradwarfforge.nativeapi.CallableTypeProducerProbe', args.consumer.resolve(), args.producer.resolve(),
        binary, root, root / 'request.json']))
    with coverage.session(command, 'producer') as measured:
        assert 'callable-type-producer=PASS' in run('producer', measured)
    variants = []
    for mode in ('compiler', *MODES):
        sidecar = reference if mode == 'compiler' else root / (mode + '.dbg')
        info = run(mode + '-readelf', ['readelf', '-h', '-S', '--debug-dump=info', '--debug-dump=abbrev',
            '--debug-dump=aranges', '--debug-dump=decodedline', sidecar])
        assert not (root / (mode + '-readelf.stderr')).read_text().strip()
        controls = [] if mode == 'compiler' else oracle(info, mode, symbols, dies)
        run(mode + '-llvm', ['llvm-dwarfdump', '--verify', sidecar])
        run(mode + '-strict', [sys.executable, '-B', repo / 'src/test/integration/check-dwarfdump.py', sidecar,
            root / (mode + '-strict.log'), '--original', binary, '--tool', args.dwarfdump])
        script = root / (mode + '.gdb')
        script.write_text('set pagination off\nset confirm off\nset debuginfod enabled off\n'
            'set disable-randomization off\nset auto-solib-add off\nfile ' + json.dumps(str(reference if mode == 'compiler' else binary)) + '\n'
            + ('' if mode == 'compiler' else 'symbol-file ' + json.dumps(str(sidecar)) + '\n')
            + 'python exits=[]; gdb.events.exited.connect(lambda e: exits.append(getattr(e,"exit_code",None)))\n'
            + 'break *forge_probe\nrun\npython\n'
            + 'assert int(gdb.parse_and_eval("forge_callback")) == ' + str(symbols['forge_variadic']['address']) + '\n'
            + 'assert int(gdb.parse_and_eval("sizeof(forge_callback)")) == 8\n'
            + 'assert "int (*)(int, ...)" in gdb.execute("ptype forge_callback", to_string=True)\n'
            + 'assert "int (int, ...)" in gdb.execute("ptype forge_variadic", to_string=True)\n'
            + 'end\nfinish\npython assert int(gdb.parse_and_eval("$eax")) == 37\ncontinue\n'
            + 'python assert exits == [0]\necho CALLABLE_GDB_PASS\\n\n')
        assert 'CALLABLE_GDB_PASS' in run(mode + '-gdb', ['gdb-multiarch', '-nx', '-q', '-batch', '-x', script])
        variants.append({'mode': mode, 'negativeControls': controls, 'gdb': 'PASS',
            'validators': ['readelf', 'llvm', 'strict'], 'sidecarSha256': digest(sidecar)})
    assert all(digest(path) == value for path, value in protected.items())
    result = {'status': 'PASS_CALLABLE_TYPE_PRODUCER', 'host': 'linux', 'target': 'x86_64', 'role': 'exec',
        'productionJarSha256': digest(args.jar), 'variants': variants, 'deterministic': True,
        'inputPreserved': True, 'protected': protected,
        'nativeSha256': {'consumer': digest(args.consumer), 'producer': digest(args.producer)},
        'harnessSha256': {str(p.resolve().relative_to(repo)): digest(p) for p in harnesses},
        'scope': 'explicit fixture signatures, native serialization; no recovered parameter locations or injected-call ABI claim'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    coverage.finish(root / 'result.json')
    print('callable-type-producer=PASS')


if __name__ == '__main__':
    main()

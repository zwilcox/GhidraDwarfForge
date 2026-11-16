#!/usr/bin/env python3
"""Real Linux/x86-64 C11 values and qualified types through the native production exporter."""
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


FIXTURE = '''#include <stdatomic.h>
#include <stdint.h>
#include <uchar.h>
int forge_base = 35;
_Atomic(int) forge_atomic = 7;
const volatile int forge_cv = 19;
int *restrict forge_restrict = &forge_base;
const void *forge_void = &forge_base;
signed char forge_schar = -7;
unsigned char forge_uchar = 250;
_Bool forge_bool = 1;
char16_t forge_utf16 = 0x03bb;
char32_t forge_utf32 = 0x1f642;
float forge_float = 1.25f;
double forge_double = -2.5;
unsigned long long forge_u64 = 0xfedcba9876543210ULL;
__attribute__((noinline)) int forge_types_probe(void) { return forge_base + forge_atomic; }
int main(void) { return forge_types_probe() != 42; }
'''
GLOBALS = ('forge_base', 'forge_atomic', 'forge_cv', 'forge_restrict', 'forge_void',
    'forge_schar', 'forge_uchar', 'forge_bool', 'forge_utf16', 'forge_utf32',
    'forge_float', 'forge_double', 'forge_u64')
CHECKS = '''
python
values = {'forge_base': 35, 'forge_atomic': 7, 'forge_cv': 19, 'forge_schar': -7,
    'forge_uchar': 250, 'forge_bool': 1, 'forge_utf16': 955, 'forge_utf32': 128578,
    'forge_u64': 0xfedcba9876543210}
sizes = {'forge_base': 4, 'forge_atomic': 4, 'forge_cv': 4, 'forge_restrict': 8,
    'forge_void': 8, 'forge_schar': 1, 'forge_uchar': 1, 'forge_bool': 1,
    'forge_utf16': 2, 'forge_utf32': 4, 'forge_float': 4, 'forge_double': 8, 'forge_u64': 8}
for name, expected in values.items():
    assert int(gdb.parse_and_eval(name)) == expected, name
for name, size in sizes.items():
    assert int(gdb.parse_and_eval('sizeof(' + name + ')')) == size, name
assert float(gdb.parse_and_eval('forge_float')) == 1.25
assert float(gdb.parse_and_eval('forge_double')) == -2.5
for name in ('forge_restrict', 'forge_void'):
    assert int(gdb.parse_and_eval(name)) == int(gdb.parse_and_eval('&forge_base')), name
assert 'volatile' in gdb.execute('ptype forge_cv', to_string=True)
assert 'const' in gdb.execute('ptype forge_cv', to_string=True)
assert 'restrict' in gdb.execute('ptype forge_restrict', to_string=True)
# GDB prints void * for both compiler and exported const-void pointers.
# The separate DIE oracle must verify the retained const modifier.
assert gdb.execute('ptype forge_void', to_string=True).strip() == 'type = void *'
assert '_Atomic' in gdb.execute('ptype forge_atomic', to_string=True)
end
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_types(nodes, symbols):
    """Assert emitted type chains and storage against the explicit C fixture."""
    shapes = {
        'forge_base': (['base_type'], 5, 4),
        'forge_atomic': (['atomic_type', 'base_type'], 5, 4),
        'forge_cv': (['const_type', 'volatile_type', 'base_type'], 5, 4),
        'forge_restrict': (['restrict_type', 'pointer_type', 'base_type'], 5, 4),
        'forge_void': (['pointer_type', 'const_type'], None, None),
        'forge_schar': (['base_type'], 6, 1),
        'forge_uchar': (['base_type'], 8, 1),
        'forge_bool': (['base_type'], 2, 1),
        'forge_utf16': (['base_type'], 16, 2),
        'forge_utf32': (['base_type'], 16, 4),
        'forge_float': (['base_type'], 4, 4),
        'forge_double': (['base_type'], 4, 8),
        'forge_u64': (['base_type'], 7, 8),
    }
    globals_by_name = {name: [node for node in nodes.values()
        if node['name'] == name and node['tag'] == 'DW_TAG_variable'] for name in GLOBALS}
    chains = {}
    for name, (tags, encoding, width) in shapes.items():
        matches = globals_by_name[name]
        assert len(matches) == 1, (name, 'global missing or duplicated')
        node = matches[0]
        location = node['attributes'].get('DW_AT_location', '')
        match = re.search(r'\(DW_OP_addr: ([0-9a-f]+)\)$', location)
        assert match and int(match[1], 16) == symbols[name]['address'], (name, 'address')
        chain = []
        for tag in tags:
            reference = re.fullmatch(r'<0x([0-9a-f]+)>', node['attributes'].get('DW_AT_type', ''))
            assert reference and int(reference[1], 16) in nodes, (name, 'type reference')
            node = nodes[int(reference[1], 16)]
            assert node['tag'] == 'DW_TAG_' + tag, (name, 'type tag', node['tag'])
            chain.append(node['offset'])
            if tag == 'pointer_type':
                assert node['attributes'].get('DW_AT_byte_size') == '8', (name, 'pointer width')
        assert 'DW_AT_type' not in node['attributes'], (name, 'unexpected terminal reference')
        if encoding is not None:
            actual = re.match(r'^(\d+)(?:\s|$)', node['attributes'].get('DW_AT_encoding', ''))
            assert actual and int(actual[1]) == encoding, (name, 'base encoding')
            assert node['attributes'].get('DW_AT_byte_size') == str(width), (name, 'base width')
        chains[name] = {'global': matches[0]['offset'], 'types': chain}
    return chains


def type_oracle(info, symbols, parser_path):
    spec = importlib.util.spec_from_file_location('qualified_die_parser', parser_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    nodes = module.read_dies(info)
    chains = check_types(nodes, symbols)
    controls = []

    def reject(label, offset, field, value):
        changed = copy.deepcopy(nodes)
        target = changed[offset] if field == 'tag' else changed[offset]['attributes']
        target[field] = value
        try:
            check_types(changed, symbols)
        except AssertionError:
            controls.append(label)
        else:
            raise AssertionError('type oracle accepted corruption: ' + label)

    for name, chain in chains.items():
        reject(name + ':address', chain['global'], 'DW_AT_location', '(DW_OP_addr: 0)')
        for index, offset in enumerate(chain['types']):
            reject(name + ':tag:' + str(index), offset, 'tag', 'DW_TAG_variable')
            if nodes[offset]['tag'] == 'DW_TAG_pointer_type':
                reject(name + ':pointer-width', offset, 'DW_AT_byte_size', '4')
        terminal = chain['types'][-1]
        if nodes[terminal]['tag'] == 'DW_TAG_base_type':
            reject(name + ':encoding', terminal, 'DW_AT_encoding', '255')
            reject(name + ':width', terminal, 'DW_AT_byte_size', '99')
        else:
            # const void terminates without a type reference. GDB's display
            # alone cannot distinguish this from an unqualified void pointer.
            reject(name + ':void-target', terminal, 'DW_AT_type', '<0x0>')
    return {'globals': list(chains), 'negativeControls': controls,
        'constVoidChain': ['DW_TAG_pointer_type', 'DW_TAG_const_type'],
        'constVoidHasNoTarget': True}


def untyped_oracle(info, symbol, parser_path, source):
    spec = importlib.util.spec_from_file_location('untyped_die_parser', parser_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    nodes = module.read_dies(info)

    def check(actual):
        assert len(actual) == 2, 'untyped export invented types, variables or declarations'
        unit, = [node for node in actual.values() if node['tag'] == 'DW_TAG_compile_unit']
        function, = [node for node in actual.values() if node['tag'] == 'DW_TAG_subprogram']
        assert function['parent'] == unit['offset'] and function['name'] == symbol['name']
        attributes = function['attributes']
        assert int(attributes['DW_AT_low_pc'], 0) == symbol['address'], ('untyped', 'low-pc')
        assert int(attributes['DW_AT_high_pc'], 0) == symbol['size'], ('untyped', 'high-pc')
        for field in ('DW_AT_type', 'DW_AT_prototyped', 'DW_AT_calling_convention', 'DW_AT_noreturn', 'DW_AT_location'):
            assert field not in attributes, ('invented signature/storage', field)
        assert ('DW_AT_stmt_list' in unit['attributes']) == (source is not None)
        if source is None:
            assert 'DW_AT_decl_file' not in attributes and 'DW_AT_decl_line' not in attributes
        else:
            assert attributes['DW_AT_decl_file'] == '0'
            line = int(attributes['DW_AT_decl_line'])
            assert source.read_text().splitlines()[line - 1] == 'int forge_types_probe(void)'
        return unit, function

    unit, function = check(nodes)
    controls = []

    def reject(label, edit):
        changed = copy.deepcopy(nodes)
        edit(changed)
        try:
            check(changed)
        except AssertionError:
            controls.append(label)
        else:
            raise AssertionError('untyped oracle accepted corruption: ' + label)

    reject('name', lambda n: n[function['offset']].update(name='wrong_function'))
    for field in ('DW_AT_low_pc', 'DW_AT_high_pc'):
        reject(field, lambda n, field=field: n[function['offset']]['attributes'].update({field: '0'}))
    for field in ('DW_AT_type', 'DW_AT_prototyped', 'DW_AT_calling_convention', 'DW_AT_noreturn', 'DW_AT_location'):
        reject(field, lambda n, field=field: n[function['offset']]['attributes'].update({field: '1'}))
    reject('extra-variable', lambda n: n.update({max(n) + 1: {'tag': 'DW_TAG_variable'}}))
    reject('source-presence', lambda n: n[unit['offset']]['attributes'].pop('DW_AT_stmt_list')
        if source is not None else n[unit['offset']]['attributes'].update(DW_AT_stmt_list='0'))
    return controls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('jar', 'consumer', 'producer', 'ghidra', 'results', 'java-home'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--dwarfdump', required=True)
    args = parser.parse_args()
    assert sys.platform == 'linux' and os.uname().machine == 'x86_64', 'Linux x86-64 fixture host required'
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[3]
    java_source = repo / 'src/test/java/ghidradwarfforge/nativeapi/QualifiedTypeProducerProbe.java'
    parser_path = Path(__file__).with_name('check-object-parameters.py')
    harnesses = [java_source, Path(__file__), parser_path,
        Path(__file__).with_name('check-dwarfdump.py'), Path(__file__).with_name('integration_coverage.py')]
    paths = [p.resolve(strict=True) for p in
        (args.jar, args.consumer, args.producer, *harnesses)]
    protected = {str(p): digest(p) for p in paths}
    commands = []

    def run(label, command, coverage=None):
        command = list(map(str, command))
        from contextlib import nullcontext
        with coverage.session(command, label) if coverage else nullcontext(command) as measured:
            completed = subprocess.run(measured, capture_output=True, text=True, timeout=90)
            (root / (label + '.stdout')).write_text(completed.stdout)
            (root / (label + '.stderr')).write_text(completed.stderr)
            commands.append({'label': label, 'command': measured, 'exit': completed.returncode})
            (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
            assert completed.returncode == 0, (label, completed.stderr)
            if label in ('readelf', 'compile', 'javac') or label.endswith(('-readelf', '-sections')):
                assert not completed.stderr.strip(), (label, completed.stderr)
            return completed.stdout

    source = root / 'fixture.c'
    source.write_text(FIXTURE)
    reference = root / 'reference'
    binary = root / 'input'
    run('compile', ['cc', '-std=c11', '-O0', '-gdwarf-5', '-fno-pie', '-no-pie', source, '-o', reference])
    header = reference.read_bytes()[:64]
    assert header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[16:18], 'little') == 2
    assert int.from_bytes(header[18:20], 'little') == 62, 'explicit Linux x86-64 ET_EXEC fixture required'
    run('strip', ['objcopy', '--strip-all', reference, binary])
    protected[str(reference)] = digest(reference)
    protected[str(binary)] = digest(binary)
    symbols = {}
    for line in run('nm', ['nm', '-S', '--defined-only', reference]).splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] in (*GLOBALS, 'forge_types_probe'):
            address, size, _, name = parts
            symbols[name] = {'name': name, 'address': int(address, 16), 'size': int(size, 16)}
    assert set(symbols) == {*GLOBALS, 'forge_types_probe'}
    request = root / 'request.json'
    request.write_text(json.dumps({'function': symbols['forge_types_probe'], 'globals': [symbols[n] for n in GLOBALS]}))
    classes = root / 'classes'
    classes.mkdir()
    jna, = args.ghidra.glob('Ghidra/Framework/Pty/lib/jna-[0-9]*.jar')
    gson, = args.ghidra.glob('Ghidra/Framework/Generic/lib/gson-[0-9]*.jar')
    cp = os.pathsep.join(map(str, [args.jar.resolve(), classes, jna.resolve(), gson.resolve()]))
    run('javac', [args.java_home / 'bin/javac', '--release', '21', '-cp', cp, '-d', classes, java_source])
    coverage = Collection('qualified-type-producer', args.jar.resolve(), 'native-java',
        test_classes=('ghidradwarfforge.nativeapi.QualifiedTypeProducerProbe',))
    sidecar = root / 'input.dbg'
    marker = run('producer', [args.java_home / 'bin/java', '--enable-native-access=ALL-UNNAMED', '-cp', cp,
        'ghidradwarfforge.nativeapi.QualifiedTypeProducerProbe', args.consumer.resolve(), args.producer.resolve(),
        binary, sidecar, request], coverage)
    assert 'qualified-type-producer=PASS globals=13 deterministic=true original-preserved=true' in marker
    assert 'untyped-producer=PASS variants=2 invalid-source-names=5 deterministic=true retry=true' in marker
    info = run('readelf', ['readelf', '-h', '-S', '--debug-dump=info', '--debug-dump=abbrev',
        '--debug-dump=aranges', '--debug-dump=decodedline', sidecar])
    type_checks = type_oracle(info, symbols, parser_path)
    (root / 'type-oracle.json').write_text(json.dumps(type_checks, indent=4) + '\n')
    run('llvm', ['llvm-dwarfdump', '--verify', sidecar])
    run('compiler-llvm', ['llvm-dwarfdump', '--verify', reference])
    run('strict', [sys.executable, '-B', repo / 'src/test/integration/check-dwarfdump.py', sidecar,
        root / 'strict.log', '--original', binary, '--tool', args.dwarfdump])
    run('compiler-strict', [sys.executable, '-B', repo / 'src/test/integration/check-dwarfdump.py', reference,
        root / 'compiler-strict.log', '--original', binary, '--tool', args.dwarfdump])
    for label, executable, debug in (('compiler', reference, None), ('exported', binary, sidecar)):
        script = root / (label + '.gdb')
        script.write_text('set pagination off\nset confirm off\nset debuginfod enabled off\n'
            'set auto-solib-add off\nset disable-randomization off\nfile ' + json.dumps(str(executable)) + '\n'
            + ('symbol-file ' + json.dumps(str(debug)) + '\n' if debug else '')
            + 'python exit_codes = []; gdb.events.exited.connect(lambda event: exit_codes.append(getattr(event,"exit_code",None)))\n'
            + 'break forge_types_probe\nrun\n' + CHECKS
            + 'finish\npython assert int(gdb.parse_and_eval("$eax")) == 42\ncontinue\n'
            + 'python assert exit_codes == [0]\necho QUALIFIED_TYPE_GDB_PASS\\n\n')
        output = run(label + '-gdb', ['gdb-multiarch', '-nx', '-q', '-batch', '-x', script])
        assert 'QUALIFIED_TYPE_GDB_PASS' in output
    untyped = []
    for mode in ('symbols', 'source-only'):
        debug = Path(str(sidecar) + '.' + mode)
        source = Path(str(debug) + '.c') if mode == 'source-only' else None
        info = run(mode + '-readelf', ['readelf', '-h', '-S', '--debug-dump=info', '--debug-dump=abbrev',
            '--debug-dump=aranges', '--debug-dump=decodedline', debug])
        controls = untyped_oracle(info, symbols['forge_types_probe'], parser_path, source)
        sections = run(mode + '-sections', ['readelf', '-SW', debug])
        assert ('.debug_line ' in sections) == (source is not None)
        assert '.debug_loclists ' not in sections and '.debug_rnglists ' not in sections
        run(mode + '-llvm', ['llvm-dwarfdump', '--verify', debug])
        run(mode + '-strict', [sys.executable, '-B', repo / 'src/test/integration/check-dwarfdump.py', debug,
            root / (mode + '-strict.log'), '--original', binary, '--tool', args.dwarfdump])
        script = root / (mode + '.gdb')
        script.write_text('set pagination off\nset confirm off\nset debuginfod enabled off\n'
            'set auto-solib-add off\nset disable-randomization off\nfile ' + json.dumps(str(binary)) + '\n'
            + 'symbol-file ' + json.dumps(str(debug)) + '\n'
            + 'python exit_codes = []; gdb.events.exited.connect(lambda e: exit_codes.append(getattr(e,"exit_code",None)))\n'
            + 'break *forge_types_probe\nrun\npython\n'
            + 'assert int(gdb.parse_and_eval("$pc")) == ' + str(symbols['forge_types_probe']['address']) + '\n'
            + 'assert all(gdb.lookup_global_symbol(name) is None for name in ' + repr(list(GLOBALS)) + ')\n'
            + ('assert gdb.selected_frame().find_sal().symtab is None\n' if source is None else
                'assert gdb.selected_frame().find_sal().symtab.fullname() == ' + repr(str(source)) + '\n'
                + 'assert "return forge_base + forge_atomic;" in gdb.execute("list forge_types_probe", to_string=True)\n')
            + 'end\nfinish\npython assert int(gdb.parse_and_eval("$eax")) == 42\ncontinue\n'
            + 'python assert exit_codes == [0]\necho UNTYPED_GDB_PASS\\n\n')
        transcript = run(mode + '-gdb', ['gdb-multiarch', '-nx', '-q', '-batch', '-x', script])
        assert 'UNTYPED_GDB_PASS' in transcript
        untyped.append({'mode': mode, 'validators': ['readelf', 'llvm', 'strict'], 'gdb': 'PASS',
            'negativeControls': controls, 'sidecarSha256': digest(debug),
            'sourceSha256': digest(source) if source is not None else None,
            'deterministic': True, 'noInventedTypesOrLocations': True})
    assert all(digest(p) == sha for p, sha in protected.items())
    result = {'status': 'PASS_QUALIFIED_TYPE_PRODUCER', 'host': 'linux', 'target': 'x86_64', 'role': 'exec',
        'globals': list(GLOBALS), 'compilerGdb': 'PASS', 'exportedGdb': 'PASS',
        'typeOracle': type_checks,
        'validators': ['readelf', 'llvm', 'strict'], 'deterministic': True, 'inputPreserved': True,
        'productionJarSha256': digest(args.jar), 'sidecarSha256': digest(sidecar),
        'sourceSha256': digest(Path(str(sidecar) + '.c')), 'protected': protected,
        'untypedExports': untyped, 'invalidSourceNames': [None, '', ' ', 'nested/file.c', 'nested\\file.c'],
        'typedRetryAfterUntypedAndFailures': True,
        'harnessSha256': {str(p.resolve().relative_to(repo)): digest(p) for p in harnesses},
        'nativeSha256': {'consumer': digest(args.consumer), 'producer': digest(args.producer)},
        'scope': 'explicit compiler fixture type model; native serialization and debugger values, not Ghidra extraction'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    coverage.finish(root / 'result.json')
    print('qualified-type-producer=PASS', flush=True)


if __name__ == '__main__':
    main()

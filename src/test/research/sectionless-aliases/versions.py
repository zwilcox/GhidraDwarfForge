#!/usr/bin/env python3
"""Research sectionless GNU-versioned aliases against accepted DSO fixture artifacts."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from mirror import merge
from importlib.util import module_from_spec, spec_from_file_location

source = Path(__file__).resolve().parent
repository = source.parents[3]
spec = spec_from_file_location('fixtures', source / 'inventory-fixtures.py')
fixtures = module_from_spec(spec)
spec.loader.exec_module(fixtures)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-root', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='versions.', dir=args.output.resolve()))
    prior = args.base_root.resolve()
    module = args.ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    java = Path(os.environ['FORGE_JAVA21_HOME']) / 'bin/java'
    javac = Path(os.environ['JAVA_HOME']) / 'bin/javac'
    classes = root / 'classes'
    classes.mkdir()
    subprocess.run([str(javac), '--release', '21', '-cp', str(jar), '-d', str(classes),
        str(source / 'SectionlessSymbolProbe.java')], check=True)
    protected = {str(p): digest(p) for p in source.glob('*') if p.is_file()}
    protected.update({str(p): digest(p) for p in module.rglob('*') if p.is_file()})
    protected.update({str(p): digest(p) for p in classes.rglob('*.class')})
    protected[str(prior / 'result.json')] = digest(prior / 'result.json')
    observations = []
    for default in ('V1', 'V2'):
        base, case = prior / default, root / default
        case.mkdir()
        for name in ('versions.so', 'automatic.dbg', 'automatic.dbg.c', 'symbols.tsv'):
            protected[str(base / name)] = digest(base / name)
        binary = case / 'versions.so'
        fixtures.sectionless(base / 'versions.so', binary)
        protected[str(binary)] = digest(binary)

        def run(name, command):
            command = list(map(str, command))
            (case / (name + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            (case / (name + '.log')).write_bytes(result.stdout)
            (case / (name + '.stderr')).write_bytes(result.stderr)
            assert result.returncode == 0 and not result.stderr, (name, result.returncode, result.stderr)
            return result.stdout.decode()

        text = run('writer', [java, '-cp', str(classes) + os.pathsep + str(jar),
            'ghidradwarfforge.elf.SectionlessSymbolProbe', binary, base / 'automatic.dbg',
            base / 'symbols.tsv', case / 'unmirrored.dbg'])
        assert 'java=21.' in text and jar.as_uri() in text.replace('file:/', 'file:///')
        inventory = merge(binary, case / 'unmirrored.dbg', case / 'aliases.dbg')
        merge(binary, case / 'unmirrored.dbg', case / 'repeat.dbg')
        assert digest(case / 'aliases.dbg') == digest(case / 'repeat.dbg')
        _, _, original = fixtures.elf_support.elf(base / 'versions.so')
        assert inventory.raw == original['.dynsym'][1] and inventory.strings == original['.dynstr'][1]
        expected = next(c for c in json.loads((prior / 'result.json').read_text())['cases']
            if c['defaultVersion'] == default)
        gdb = ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set debuginfod enabled off',
            '-ex', 'set auto-solib-add off', '-ex', 'file ' + str(binary),
            '-ex', 'symbol-file ' + str(case / 'aliases.dbg')]
        for index, row in enumerate(expected['qualifiedLookup']):
            text = run('lookup-' + str(index), [*gdb, '-ex', "print/x &'" + row['name'] + "'",
                '-ex', "ptype '" + row['name'] + "'"])
            assert int(re.search(r'\$1 = (0x[0-9a-f]+)', text)[1], 16) == row['address']
            assert 'type = int (int)' in text
        for name in ('old_api', 'new_api'):
            text = run('source-' + name, [*gdb, '-ex', 'list recovered::analyst_' + name])
            assert 'value' in text and 'No such file' not in text
        loaded = ctypes.CDLL(str(binary))
        bias = ctypes.cast(loaded.old_api, ctypes.c_void_p).value - expected['nativeVersionedCalls']['V1']['address']
        loader = ctypes.CDLL(None)
        loader.dlvsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        loader.dlvsym.restype = ctypes.c_void_p
        calls = {}
        for version in ('V1', 'V2'):
            address = loader.dlvsym(loaded._handle, b'api', version.encode())
            value = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(address)(19)
            calls[version] = {'address': address - bias, 'result': value}
            assert calls[version] == expected['nativeVersionedCalls'][version]
        assert loaded.api(19) == calls[default]['result']
        for view in ('info', 'abbrev', 'aranges', 'decodedline'):
            run('dwarf-' + view, ['readelf', '--debug-dump=' + view, case / 'aliases.dbg'])
        run('headers', ['readelf', '-hSWs', case / 'aliases.dbg'])
        assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', case / 'aliases.dbg'])
        run('strict', ['python3', repository / 'src/test/integration/check-dwarfdump.py',
            case / 'aliases.dbg', case / 'strict-checks.log', '--original', binary])
        observations.append({'defaultVersion': default, 'countSources': inventory.counts,
            'lookup': expected['qualifiedLookup'], 'nativeVersionedCalls': calls,
            'sidecarSha256': digest(case / 'aliases.dbg')})
        print(default, 'PASS', flush=True)
    assert all(digest(Path(p)) == h for p, h in protected.items())
    (root / 'result.json').write_text(json.dumps({'status': 'CONSUMER_RESEARCH_PASS',
        'cases': observations, 'protected': protected}, indent=4) + '\n')
    print(root, flush=True)


if __name__ == '__main__':
    main()

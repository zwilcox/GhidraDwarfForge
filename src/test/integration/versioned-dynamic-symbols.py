#!/usr/bin/env python3
"""Verify packaged dynamic mirroring against compiler symbols, GNU versions and GDB."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

source = Path(__file__).resolve().parent
repository = source.parents[2]
spec = importlib.util.spec_from_file_location('elf_support', source / 'retained-function-aliases-export.py')
elf_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_support)
spec = importlib.util.spec_from_file_location('inventory_check', source / 'sectionless-alias-check.py')
inventory_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory_check)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('--sectionless', action='store_true')
    args = parser.parse_args()
    jar = args.ghidra.resolve(strict=True) / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    results = repository / 'build/test-results' / ('sectionless-versioned-dynamic-symbols' if args.sectionless else 'versioned-dynamic-symbols')
    results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='run.', dir=results))
    print(root, flush=True)
    classes = root / 'classes'
    classes.mkdir()
    probe = repository / 'src/test/java/ghidradwarfforge/elf/LocalSymbolMergeProbe.java'
    preparation = source / 'ghidra_scripts/PrepareVersionedAliases.java'
    protected = {str(path): digest(path) for path in (jar, probe, preparation, Path(__file__).resolve(), source / 'sectionless-alias-check.py')}
    javac = str(Path(os.environ['JAVA_HOME']) / 'bin/javac')
    java = str(Path(os.environ.get('FORGE_JAVA21_HOME', os.environ['JAVA_HOME'])) / 'bin/java')

    def run(path, command):
        result = subprocess.run(list(map(str, command)), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=240)
        path.write_bytes(result.stdout)
        path.with_suffix(path.suffix + '.stderr').write_bytes(result.stderr)
        assert result.returncode == 0, (command, result.returncode, result.stderr.decode(errors='replace'))
        if Path(command[0]).name != 'analyzeHeadless':
            assert not result.stderr, (command, result.stderr)
        return result.stdout.decode()

    run(root / 'compile-probe.log', [javac, '--release', '21', '-cp', jar, '-d', classes, probe])
    observations = []
    for default in ('V1', 'V2'):
        case = root / default
        case.mkdir()
        fixture = case / 'versions.c'
        fixture.write_text('int old_api(int value) { return value + 1; }\n'
            'int new_api(int value) { return value + 2; }\n'
            '__asm__(".symver old_api,api' + ('@@' if default == 'V1' else '@') + 'V1");\n'
            '__asm__(".symver new_api,api' + ('@@' if default == 'V2' else '@') + 'V2");\n')
        versions = case / 'versions.map'
        versions.write_text('V1 {};\nV2 {} V1;\n')
        reference, binary = case / 'versions.reference.so', case / 'versions.so'
        run(case / 'compile.log', ['gcc', '-O1', '-g3', '-gdwarf-5', '-fPIC', '-shared',
            '-Wl,--build-id=sha1', '-Wl,--version-script=' + str(versions), fixture, '-o', reference])
        run(case / 'strip.log', ['objcopy', '--strip-all', reference, binary])
        oracle = binary
        if args.sectionless:
            oracle = case / 'sectioned.so'
            shutil.copy2(binary, oracle)
            contents = bytearray(binary.read_bytes())
            struct.pack_into('<Q', contents, 40, 0)
            struct.pack_into('<HH', contents, 60, 0, 0)
            binary.write_bytes(contents)
        protected.update({str(path): digest(path) for path in (fixture, versions, reference, binary, oracle)})
        ident, header, original = elf_support.elf(oracle)
        assert ident[4:6] == b'\x02\x01' and header[1] == 62 and '.symtab' not in original
        dynamic, records = original['.dynsym']
        strings = original['.dynstr'][1]
        symbols = []
        for offset in range(0, len(records), 24):
            name, info, other, section, value, size = struct.unpack_from('<IBBHQQ', records, offset)
            spelling = strings[name:].split(b'\0', 1)[0].decode()
            symbols.append((spelling, info, other, section, value, size))
        defined = {row[0]: row for row in symbols if row[0] in ('old_api', 'new_api')}
        assert len(defined) == 2
        aliases = case / 'symbols.tsv'
        aliases.write_text(''.join('\t'.join(('recovered::alternate_' + name,
            str(row[4]), str(row[5]), str(row[3]))) + '\n' for name, row in sorted(defined.items(), key=lambda item: item[1][4])))
        project = case / 'project'
        project.mkdir()
        automatic = case / 'automatic.dbg'
        headless = args.ghidra.resolve() / 'support/analyzeHeadless'
        for mode in ('curate', 'observe'):
            operation = ['-import', binary] if mode == 'curate' else ['-process', binary.name, '-noanalysis', '-readOnly']
            text = run(case / (mode + '.log'), [headless, project, 'Versions', *operation,
                '-scriptPath', source / 'ghidra_scripts', '-postScript', preparation.name, mode, aliases,
                '-postScript', 'GhidraDwarfForge.java', '--packaged-natives', '--output=' + str(automatic)])
            assert 'versioned-alias-curation=PASS' in text and 'GhidraDwarfForge symbol export PASS' in text
            assert 'unqualified GDB lookup can differ from the loader default' in text
            report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in text.splitlines() if 'GhidraDwarfForge report: {' in line]
            assert not report['failedFunctions'] and report['failure'] is None
            current = [digest(automatic), digest(Path(str(automatic) + '.c'))]
            if mode == 'curate':
                first = current
            else:
                assert current == first
        for suffix in ('aliases.dbg', 'repeat.dbg'):
            text = run(case / (suffix + '.writer.log'), [java, '-cp', str(classes) + os.pathsep + str(jar),
                'ghidradwarfforge.elf.LocalSymbolMergeProbe', binary, automatic, aliases, case / suffix])
            assert 'java=21.' in text and 'curated-alias-writer=PASS' in text
        output = case / 'aliases.dbg'
        assert output.read_bytes() == (case / 'repeat.dbg').read_bytes()
        assert output.read_bytes() == automatic.read_bytes()
        if args.sectionless:
            inventory_check.verify(oracle, binary, output,
                [{'alias': 'recovered::alternate_' + name, 'entry': row[4], 'size': row[5]}
                    for name, row in defined.items()], case / 'raw-inventory.json')
            inventory_check.corruption_controls(oracle, binary, output,
                [{'alias': 'recovered::alternate_' + name, 'entry': row[4], 'size': row[5]}
                    for name, row in defined.items()], case / 'corruption-controls')
        _, emitted_header, emitted = elf_support.elf(output)
        assert emitted_header[4] == emitted_header[8] == emitted_header[9] == 0
        for name in ('.dynsym', '.dynstr', '.gnu.version', '.gnu.version_d', '.gnu.version_r',
                '.gnu.hash', '.dynamic', '.note.gnu.build-id'):
            if name in original:
                if args.sectionless:
                    section, payload = original[name]
                    assert output.read_bytes()[section[4]:section[4] + section[5]] == payload, name
                else:
                    assert emitted[name][1] == original[name][1], name
                    # The writer rebuilds .shstrtab; compare decoded names and original semantics.
                    assert emitted[name][0][1:4] == original[name][0][1:4], name
                    assert emitted[name][0][5:] == original[name][0][5:], name
        expected = {'old_api': defined['old_api'][4], 'new_api': defined['new_api'][4]}
        expected.update({'api' + ('@@' if default == version else '@') + version:
            defined['old_api' if version == 'V1' else 'new_api'][4] for version in ('V1', 'V2')})
        expected.update({'recovered::alternate_' + name: row[4] for name, row in defined.items()})
        expected.update({'recovered::analyst_' + name: row[4] for name, row in defined.items()})
        lookup = []
        for index, (name, address) in enumerate(expected.items()):
            text = run(case / ('lookup-' + str(index) + '.log'), ['gdb-multiarch', '-q', '-nx', '-batch',
                '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
                '-ex', 'file ' + str(binary), '-ex', 'symbol-file ' + str(output), '-ex', "print/x &'" + name + "'"])
            match = re.search(r'\$1 = (0x[0-9a-f]+)', text)
            assert match and int(match[1], 16) == address, (name, text, address)
            lookup.append({'name': name, 'address': address})
        for name in defined:
            text = run(case / ('source-' + name + '.log'), ['gdb-multiarch', '-q', '-nx', '-batch',
                '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
                '-ex', 'file ' + str(binary), '-ex', 'symbol-file ' + str(output),
                '-ex', "ptype 'recovered::analyst_" + name + "'",
                '-ex', 'list recovered::analyst_' + name])
            assert 'type = int (int)' in text and 'value' in text
        unqualified = {}
        for name, path in (('compiler', reference), ('original', oracle), ('sidecar', output)):
            text = run(case / ('unqualified-' + name + '.log'), ['gdb-multiarch', '-q', '-nx', '-batch',
                '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off',
                '-ex', 'file ' + str(binary), '-ex', 'symbol-file ' + str(path), '-ex', "print/x &'api'"])
            unqualified[name] = int(re.search(r'\$1 = (0x[0-9a-f]+)', text)[1], 16)
        assert unqualified['sidecar'] == unqualified['original'] == unqualified['compiler']
        loaded = ctypes.CDLL(str(binary))
        bias = ctypes.cast(loaded.old_api, ctypes.c_void_p).value - defined['old_api'][4]
        loader = ctypes.CDLL(None)
        loader.dlvsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        loader.dlvsym.restype = ctypes.c_void_p
        runtime = {}
        for version, function, result in (('V1', 'old_api', 20), ('V2', 'new_api', 21)):
            address = loader.dlvsym(loaded._handle, b'api', version.encode())
            assert address - bias == defined[function][4]
            value = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(address)(19)
            assert value == result
            runtime[version] = {'address': address - bias, 'result': value}
        default_offset = ctypes.cast(loaded.api, ctypes.c_void_p).value - bias
        assert default_offset == runtime[default]['address']
        assert loaded.api(19) == runtime[default]['result']
        for view in ('info', 'abbrev', 'aranges', 'decodedline'):
            run(case / ('dwarf-' + view + '.log'), ['readelf', '--debug-dump=' + view, output])
        run(case / 'headers.log', ['readelf', '-hSWs', output])
        text = run(case / 'llvm.log', ['llvm-dwarfdump', '--verify', output])
        assert 'No errors.' in text
        run(case / 'strict.log', ['python3', source / 'check-dwarfdump.py', output,
            case / 'strict-checks.log', '--original', binary])
        observations.append({'defaultVersion': default, 'qualifiedLookup': lookup, 'unqualifiedLookup': unqualified,
            'nativeLoaderDefault': default_offset, 'nativeVersionedCalls': runtime,
            'gdbDefaultMatchesLoader': unqualified['sidecar'] == default_offset,
            'sidecarSha256': digest(output)})
    assert protected == {path: digest(Path(path)) for path in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS',
        'sectionless': args.sectionless,
        'scope': 'Headless curated export, independent writer equality, qualified GDB lookup/types/source and native loader calls',
        'cases': observations, 'protected': protected}, indent=4) + '\n')
    print('versioned-dynamic-symbols=PASS ' + str(root), flush=True)


if __name__ == '__main__':
    main()

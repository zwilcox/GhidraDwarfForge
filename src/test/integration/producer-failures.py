#!/usr/bin/env python3
"""Isolated Java/native failure tests; shim faults are not upstream bug claims."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tarfile
from integration_coverage import Collection


ARCHIVE_SHA256 = '7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd'
MODES = {
    'init-error': 'dwarf_producer_init failed without Dwarf_Error',
    'init-null': 'producer debug was null',
    'string-error': 'dwarf_pro_set_default_string_form failed error=',
    'string-no-entry': 'dwarf_pro_set_default_string_form failed without Dwarf_Error',
    'die-null': 'DIE was null',
    'transform-error': 'dwarf_transform_to_disk_form_a failed without Dwarf_Error',
    'buffer-count-zero': 'invalid producer buffer count',
    'buffer-count-large': 'invalid producer buffer count',
    'section-error': 'dwarf_get_section_bytes_a failed without Dwarf_Error',
    'section-unknown': 'invalid producer section buffer',
    'section-negative-length': 'invalid producer section buffer',
    'section-large-length': 'invalid producer section buffer',
    'section-null': 'section bytes was null',
    'missing-strings': 'producer omitted required DWARF sections',
    'duplicate-section': 'duplicate section .debug_str',
    'relocation-version': 'invalid symbolic relocation metadata',
    'relocation-no-groups': 'invalid symbolic relocation metadata',
    'relocation-section': 'invalid relocation group',
    'relocation-target': 'invalid relocation group',
    'relocation-empty': 'invalid relocation group',
    'relocation-null': 'relocation records was null',
    'relocation-offset-negative': 'relocation outside target section',
    'relocation-offset-outside': 'relocation outside target section',
    'relocation-zero-width': 'relocation outside target section',
    'relocation-unknown-symbol': 'unknown producer relocation symbol',
    'relocation-address-width': 'address relocation width mismatch',
    'relocation-missing-address': 'producer address relocations do not match',
    'finish-error': 'dwarf_producer_finish_a failed without Dwarf_Error',
}


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'source-archive', 'consumer', 'producer', 'jar', 'test-classes', 'ghidra', 'java'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--mode', action='append', choices=sorted(MODES))
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source_archive, consumer, producer, jar = [p.resolve(strict=True) for p in
        (args.source_archive, args.consumer, args.producer, args.jar)]
    assert digest(source_archive) == ARCHIVE_SHA256, 'wrong pinned libdwarf source archive'
    protected = {str(p): digest(p) for p in (source_archive, consumer, producer, jar)}
    include = root / 'include'
    include.mkdir()
    headers = {}
    with tarfile.open(source_archive) as archive:
        for suffix in ('src/lib/libdwarf/libdwarf.h', 'src/lib/libdwarf/dwarf.h', 'src/lib/libdwarfp/libdwarfp.h'):
            member, = [item for item in archive.getmembers() if item.name.endswith('/' + suffix)]
            assert member.isfile() and 0 < member.size < 1024 * 1024
            data = archive.extractfile(member).read()
            path = include / Path(suffix).name
            path.write_bytes(data)
            headers[suffix] = digest(path)
    scripts = Path(__file__).resolve().parent
    repo = scripts.parents[2]
    shim_source = repo / 'src/test/native/producer-fault-shim.c'
    shim = root / 'producer-fault-shim.so'
    commands = []
    libraries = root / 'libraries'
    libraries.mkdir()
    (libraries / 'libdwarfp.so.2').symlink_to(producer)
    (libraries / 'libdwarf.so.2').symlink_to(consumer)

    def run(name, command, timeout=60):
        command = list(map(str, command))
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout)
        (root / (name + '.log')).write_text(completed.stdout + completed.stderr)
        commands.append({'name': name, 'command': command, 'exit': completed.returncode})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        assert completed.returncode == 0, name + ': inspect retained log'
        if name.endswith('-readelf'):
            assert not completed.stderr.strip(), 'readelf diagnostic: ' + completed.stderr
        return completed.stdout

    run('compile-shim', ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
        '-DFORGE_REAL_PRODUCER=' + json.dumps(str(producer)), '-I' + str(include), shim_source,
        '-Wl,--no-as-needed', producer, '-Wl,-rpath,' + str(libraries), '-ldl', '-o', shim])
    fixture = root / 'fixture.c'
    fixture.write_text('__attribute__((noinline)) int forge_probe(int value) { return value + 7; }\n'
        'int main(void) { return forge_probe(35) == 42 ? 0 : 1; }\n')
    binary = root / 'fixture'
    run('compile-fixture', ['cc', '-O0', '-g0', '-fno-pie', '-no-pie', fixture, '-o', binary])
    symbols = run('symbols', ['nm', '-S', '--defined-only', binary])
    symbol, = [line.split() for line in symbols.splitlines() if line.split()[-1] == 'forge_probe']
    address, size = int(symbol[0], 16), int(symbol[1], 16)
    protected[str(binary)] = digest(binary)
    jna, = args.ghidra.resolve().glob('Ghidra/Framework/Pty/lib/jna-[0-9]*.jar')
    classpath = os.pathsep.join(map(str, (jar, args.test_classes.resolve(), jna)))
    coverage = Collection('producer-failures', jar, 'native-java',
        test_classes=('ghidradwarfforge.nativeapi.ProducerFailureProbe',))
    results = []
    for mode in args.mode or MODES:
        directory = root / mode
        command = [str(args.java.resolve()), '--enable-native-access=ALL-UNNAMED',
            '-Djava.io.tmpdir=' + str(root), '-Djna.tmpdir=' + str(root), '-cp', classpath,
            'ghidradwarfforge.nativeapi.ProducerFailureProbe', str(consumer), str(shim), str(binary),
            str(directory), hex(address), hex(size), mode, MODES[mode]]
        with coverage.session(command, mode) as measured:
            text = run(mode, measured)
            marker, = [line for line in text.splitlines() if line.startswith('producer-failure=')]
            observed = re.fullmatch(r'producer-failure=PASS mode=([a-z-]+) faults=(\d+) starts=(\d+) finished=(\d+) '
                r'existing-preserved=true absent-preserved=true retry-identical=true', marker)
            assert observed and observed[1] == mode
            fault_count, starts, finishes = map(int, observed.group(2, 3, 4))
            assert fault_count == 2 and starts == finishes == (2 if mode.startswith('init-') else 4)
        sidecar = directory / 'fixture.dbg'
        run(mode + '-readelf', ['readelf', '-h', '-S', '--debug-dump=info', '--debug-dump=abbrev',
            '--debug-dump=aranges', '--debug-dump=decodedline', sidecar])
        run(mode + '-llvm', ['llvm-dwarfdump', '--verify', sidecar])
        run(mode + '-strict', [sys.executable, '-B', scripts / 'check-dwarfdump.py', sidecar,
            directory / 'strict.log', '--original', binary, '--tool', args.dwarfdump])
        gdb_script = directory / 'check.gdb'
        gdb_script.write_text('set pagination off\nset confirm off\nset debuginfod enabled off\n'
            'set auto-solib-add off\nset disable-randomization off\nfile ' + json.dumps(str(binary)) + '\n'
            'symbol-file ' + json.dumps(str(sidecar)) + '\n'
            'python exit_codes = []; gdb.events.exited.connect(lambda event: exit_codes.append(getattr(event, "exit_code", None)))\n'
            'info functions forge_probe\nlist forge_probe\n'
            'python assert gdb.execute("ptype forge_probe", to_string=True).strip() == "type = int (int)"\n'
            'break *forge_probe\nrun\n'
            'python assert gdb.selected_frame().find_sal().symtab.fullname() == ' + json.dumps(str(directory / 'fixture.dbg.c')) + '\n'
            f'python assert int(gdb.parse_and_eval("$pc")) == {address}\n'
            'python assert int(gdb.parse_and_eval("$edi")) == 35\n'
            'finish\npython assert int(gdb.parse_and_eval("$eax")) == 42\ncontinue\n'
            'python assert exit_codes == [0]\necho PRODUCER_FAILURE_RETRY_GDB_PASS\\n\n')
        gdb = run(mode + '-gdb', ['gdb-multiarch', '-nx', '-q', '-batch', '-x', gdb_script])
        assert 'PRODUCER_FAILURE_RETRY_GDB_PASS' in gdb and 'return value + 7' in gdb
        assert all(digest(path) == expected for path, expected in protected.items())
        results.append({'mode': mode, 'faults': fault_count, 'starts': starts, 'finishes': finishes,
            'existingPreserved': True, 'absentPreserved': True, 'retryIdentical': True,
            'validators': ['readelf', 'llvm', 'strict'], 'gdb': 'PASS',
            'sidecarSha256': digest(sidecar), 'sourceSha256': digest(directory / 'fixture.dbg.c')})
        print('producer-failure-validated=' + mode, flush=True)
    harnesses = [Path(__file__).resolve(), shim_source, repo / 'src/test/java/ghidradwarfforge/nativeapi/ProducerFailureProbe.java',
        scripts / 'check-dwarfdump.py', scripts / 'integration_coverage.py']
    result = {'status': 'PASS_ISOLATED_PRODUCER_FAILURES', 'target': 'x86_64', 'host': 'linux',
        'sourceCommit': 'af7b278c6aa2ae9daad94fb7f8bffdc0e9980993', 'sourceArchiveSha256': ARCHIVE_SHA256,
        'headersSha256': headers, 'protected': protected, 'productionJarSha256': digest(jar),
        'nativeSha256': {'consumer': digest(consumer), 'producer': digest(producer)},
        'shimSha256': digest(shim), 'controls': results,
        'harnessSha256': {p.relative_to(repo).as_posix(): digest(p) for p in harnesses},
        'scope': 'Test-only producer result faults around the real pinned library; no upstream defect or new target claim'}
    (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
    coverage.finish(root / 'result.json')


if __name__ == '__main__':
    main()

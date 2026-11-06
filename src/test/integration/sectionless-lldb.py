#!/usr/bin/env python3
"""Exercise explicit symbol loading and source steps with no ELF section table."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import struct
import subprocess
import lldb_consumer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixtures', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', required=True, choices=('x86_64', 'aarch64'))
    parser.add_argument('--suffix', default='ghidra-forge.dbg')
    parser.add_argument('--lldb', default='lldb-18')
    parser.add_argument('--mode', choices=('all', 'compiler', 'forge'), default='all')
    parser.add_argument('--loading', choices=('module', 'attached'), default='module',
        help='explicit module mapping, or direct attachment for consumer regression diagnosis')
    args = parser.parse_args()
    assert Path(args.suffix).name == args.suffix and args.suffix.endswith('.dbg')
    fixture = args.fixtures.resolve() / args.target
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    versions = lldb_consumer.versions(args.lldb, args.target)
    original = fixture / 'semantic.exec.no-sections.stripped'
    reference = fixture / 'semantic.exec.reference'
    sidecar = fixture / ('semantic.exec.no-sections.' + args.suffix)
    data = original.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01' and struct.unpack_from('<H', data, 16)[0] == 2
    assert struct.unpack_from('<Q', data, 40)[0] == 0 and struct.unpack_from('<HH', data, 60) == (0, 0)
    # Use only actually recovered functions. Ghidra does not separately discover
    # the tiny AArch64 recovered_add in this sectionless fixture; main is present.
    compiler_name = 'recovered_add' if args.target == 'x86_64' else 'main'
    entries = {int(fields[1], 16) for line in subprocess.check_output(['readelf', '-Ws', str(reference)], text=True).splitlines()
        if len(fields := line.split()) == 8 and fields[3] == 'FUNC' and fields[7] == compiler_name}
    entry, = entries
    program_offset = struct.unpack_from('<Q', data, 32)[0]
    program_size, program_count = struct.unpack_from('<HH', data, 54)
    assert program_size == 56 and program_count > 0
    candidates = []
    for index in range(program_count):
        kind, flags, offset, address, physical, file_size, memory_size, alignment = struct.unpack_from('<IIQQQQQQ', data, program_offset + index * program_size)
        if kind == 1 and flags & 1 and address <= entry and entry + 4 <= address + file_size:
            candidates.append(data[offset + entry - address:offset + entry - address + 4].hex())
    entry_bytes, = candidates
    protected = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in
        (original, reference, sidecar, Path(str(sidecar) + '.c'))}
    results = []
    scripts = Path(__file__).resolve().parent
    for mode in (('compiler', 'forge') if args.mode == 'all' else (args.mode,)):
        function = compiler_name if mode == 'compiler' else 'FUN_%08x' % entry
        symbols = reference if mode == 'compiler' else sidecar
        output = root / mode
        config_path = root / (mode + '.json')
        config_path.write_text(json.dumps({'mode': mode, 'function': function, 'entry': entry, 'entryBytes': entry_bytes,
            'original': str(original), 'module': str(symbols if args.loading == 'module' else original),
            'symbolsFile': str(symbols), 'source': str(sidecar) + '.c',
            'referenceSources': str(scripts.parent / 'fixtures'), 'observations': str(output / 'observations.json')}, indent=4) + '\n')
        before = ['script exec(open(' + repr(str(scripts / 'sectionless-lldb-observe.py')) + ').read())',
            'image lookup --name ' + function, 'source list --name ' + function,
            'breakpoint set --name ' + function + ' --skip-prologue false']
        if mode == 'compiler':
            before.insert(0, 'settings set target.source-map /ghidra-dwarf-forge-fixture ' + shlex.quote(str(scripts.parent / 'fixtures')))
        after = ["script sectionless_check('entry')", 'thread step-over',
            "script sectionless_check('step')", 'continue', "script sectionless_check('exit')"]
        if args.loading == 'module':
            # These independently checked ET_EXEC fixtures use link-time virtual
            # addresses. Do not extend a zero slide to PIE or shared libraries.
            after[:0] = ['target modules load --file ' + shlex.quote(str(symbols)) + ' --slide 0', 'continue']
        transcript = lldb_consumer.run(original, symbols, output, args.lldb, args.target, before, after,
            {'FORGE_LLDB_SECTIONLESS_CONFIG': str(config_path)}, stop_at_entry=args.loading == 'module',
            separate_symbol_module=args.loading == 'module')
        assert 'FORGE_LLDB_SECTIONLESS_CHECK_PASS exit' in transcript
        rows = json.loads((output / 'observations.json').read_text())
        assert [row['phase'] for row in rows] == ['entry', 'step', 'exit']
        results.append({'mode': mode, 'observations': rows})
        assert protected == {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in protected}
    assert all(result['observations'][0]['bytes'] == entry_bytes for result in results)
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_LLDB_SECTIONLESS', 'target': args.target,
        'versions': versions, 'loading': args.loading, 'cases': results, 'protectedSha256': protected,
        'scope': 'No original section table; actual recovered function, original code bytes, source step and exit. No curated missing types/locations fabricated.'}, indent=4) + '\n')
    print('lldb-sectionless=PASS ' + args.target)


if __name__ == '__main__':
    main()

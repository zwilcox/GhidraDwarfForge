#!/usr/bin/env python3
"""Compare incomplete original metadata with an equally covered assembler reference."""
import argparse
import json
from pathlib import Path
import re
import runpy
import sys

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'unwind-export.py'))
run, metadata, digest = (helpers[name] for name in ('run', 'metadata', 'digest'))
validate_original = runpy.run_path(str(SCRIPTS / 'check-dwarfdump.py'))['validate_output']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('recovery_cases', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--libdwarf', type=Path)
    parser.add_argument('--libdwarfp', type=Path)
    args = parser.parse_args()
    assert bool(args.libdwarf) == bool(args.libdwarfp)
    ghidra = args.ghidra.resolve(strict=True)
    natives = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/os/linux_x86_64'
    consumer = args.libdwarf or next(natives.glob('libdwarf.so.*.*.*'))
    producer = args.libdwarfp or next(natives.glob('libdwarfp.so.*.*.*'))
    source = args.recovery_cases.resolve() / 'aarch64-exec'
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    (work / 'project').mkdir()
    protected = {str(path): digest(path) for path in (source / 'reference', source / 'original',
        consumer, producer, ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar')}
    section, = [s for s in metadata(source / 'reference')['sections'] if s['name'] == '.debug_frame']
    raw = (source / 'reference').read_bytes()[section['offset']:section['offset'] + section['size']]
    cie_end = 4 + int.from_bytes(raw[:4], 'little')
    leaf_end = cie_end + 4 + int.from_bytes(raw[cie_end:cie_end + 4], 'little')
    recursive_end = leaf_end + 4 + int.from_bytes(raw[leaf_end:leaf_end + 4], 'little')
    assert 0 < cie_end < leaf_end < recursive_end < len(raw)
    for name, end in (('original', leaf_end), ('reference', recursive_end)):
        prefix = work / (name + '.frame'); prefix.write_bytes(raw[:end])
        run(['aarch64-linux-gnu-objcopy', '--add-section', '.debug_frame=' + str(prefix),
            '--set-section-alignment', '.debug_frame=8', '--set-section-flags', '.debug_frame=readonly,debug',
            source / 'original', work / name], work / (name + '-build.log'))
        protected[str(work / name)] = digest(work / name)
    artifact = work / 'forge.dbg'
    log = run([ghidra / 'support/analyzeHeadless', work / 'project', 'Incomplete', '-import', work / 'original',
        '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'ExportRecoveredFrames.java',
        consumer, producer, artifact, 'none', '0', 'none'], work / 'export.log')
    assert 'native-frame-export=PASS frames=1 ' in log
    for name, path in (('original', work / 'original'), ('reference', work / 'reference'), ('forge', artifact)):
        text = run(['readelf', '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', path], work / (name + '-gnu.log'))
        assert 'warning:' not in text.lower() and 'error:' not in text.lower()
        run(['llvm-dwarfdump', '--verify', path], work / (name + '-llvm.log'))
        frames = run([args.dwarfdump, '--no-follow-debuglink', '--print-frame', path], work / (name + '-frames.log'))
        assert '\nfde:\n' in frames and '\ncie:\n' in frames
        assert not re.search(r'DW_DLE_|\b(?:warning|error|fatal):', frames, re.IGNORECASE)
        if name == 'forge':
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', path, work / (name + '-strict.log'),
                '--tool', args.dwarfdump], work / (name + '-strict-command.log'))
        else:
            # These assembler-only input controls have no compilation units.
            # Use the checker's established original-input mode; generated
            # output still must satisfy its ordinary nonzero-CU contract.
            text = run([args.dwarfdump, '--no-follow-debuglink', '-ka', '-ki', '-kd', path],
                work / (name + '-strict.log'))
            checked = validate_original(text, original=True)
            (work / (name + '-strict.check.json')).write_text(json.dumps(checked, indent=4) + '\n')
    results, warnings = {}, {}
    for name, path in (('reference', work / 'reference'), ('forge', artifact)):
        prefix = work / ('gdb-' + name)
        run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', 'aarch64', 'none', path, work / 'original', prefix],
            work / (name + '-gdb-command.log'), {'FORGE_FRAME_GDB_SCRIPT': str(SCRIPTS / 'unwind-incomplete-gdb.py')})
        results[name] = json.loads(Path(str(prefix) + '.json').read_text())
        warnings[name] = [line for line in Path(str(prefix) + '.log').read_text().splitlines() if 'warning:' in line.lower()]
    assert results['reference'] == results['forge']
    assert warnings['reference'] == warnings['forge']
    assert all(re.fullmatch(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index', line)
        for line in warnings['reference'])
    assert protected == {name: digest(Path(name)) for name in protected}
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_INHERITED_UNAVAILABLE_CONTROL',
        'protected': protected, 'observations': results, 'warnings': warnings,
        'limit': 'The original omits x29 and outer-boundary CFI; both consumers stop at the same four frames. This is not full-chain acceptance.'}, indent=4) + '\n')
    print('inherited unavailable register matches independent reference PASS')


if __name__ == '__main__':
    main()

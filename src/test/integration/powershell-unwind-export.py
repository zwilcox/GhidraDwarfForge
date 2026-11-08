#!/usr/bin/env python3
"""Exercise the installed PowerShell unwind wrapper and retain cross-host evidence."""
import argparse
import json
import platform
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import zlib

SCRIPTS = Path(__file__).resolve().parent
helpers = runpy.run_path(str(SCRIPTS / 'unwind-export.py'))
run, digest, metadata, decode, check_description = (
    helpers[name] for name in ('run', 'digest', 'metadata', 'decode', 'check_unwind_description'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference_directory', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    parser.add_argument('--powershell', default='pwsh')
    parser.add_argument('--readelf', default='readelf')
    parser.add_argument('--llvm', default='llvm-dwarfdump')
    parser.add_argument('--libdwarf', type=Path)
    parser.add_argument('--libdwarfp', type=Path)
    args = parser.parse_args()
    assert bool(args.libdwarf) == bool(args.libdwarfp)
    prior = json.loads((args.reference_directory / 'result.json').read_text())
    assert prior['status'] == 'PASS_COMPILER_REFERENCE' and prior['target'] == 'x86_64' and prior['role'] == 'exec'
    work = args.output.resolve(); work.mkdir(parents=True, exist_ok=False)
    module = args.ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge'
    wrapper = module / 'support/ghidra-dwarf-forge-headless.ps1'
    protected = {str(path): digest(path) for path in [wrapper, module / 'lib/GhidraDwarfForge.jar',
        args.reference_directory.resolve() / 'without-cfi', args.reference_directory.resolve() / 'reference']}
    for name in ('without-cfi', 'reference'):
        source = args.reference_directory / name
        # Prior receipts contain producer-host paths; match the basename and
        # require one recorded input hash, then bind the transported bytes.
        expected, = [value for path, value in prior['protectedSha256'].items() if Path(path).name == name]
        assert digest(source) == expected
        shutil.copy2(source, work / name)
    original = work / 'without-cfi'
    reference = work / 'reference'
    symbols = run([args.readelf, '-Ws', reference], work / 'symbols.log')
    rows = [line.split() for line in symbols.splitlines() if line.split()[-1:] == ['cfi_sink']]
    candidate, = {(int(row[1], 16), int(row[2])) for row in rows}
    address, size = candidate
    assert size == 8
    condition = f'{address:x}:{address + size - 1:x}'
    common = [args.powershell, '-NoLogo', '-NoProfile', '-File', wrapper,
        '-GhidraDirectory', args.ghidra.resolve(), '-Import', original]
    if args.libdwarf:
        common += ['-Libdwarf', args.libdwarf.resolve(), '-Libdwarfp', args.libdwarfp.resolve()]
    artifacts = []
    for mode in ('off', 'strict', 'conditioned', 'compressed'):
        artifact = work / (mode + '.dbg')
        options = ['-SynthesizeUnwind', 'conditioned' if mode == 'compressed' else mode]
        if mode in ('conditioned', 'compressed'):
            options += ['-UnwindStackSeparation', condition, '-UnwindRelocatedPointers', 'fixed']
        if mode == 'compressed': options += ['-CompressDebugSections', 'zlib', '-GdbLoader']
        command = common + ['-Output', artifact, *options]
        transcript = run(command, work / (mode + '-export.log'))
        report, = re.findall(r'GhidraDwarfForge report: (\{.*\})', transcript)
        report = json.loads(report)
        assert report['status'] in ('SUCCESS', 'PARTIAL')
        assert report['artifacts']['outputSha256'] == digest(artifact)
        assert report['artifacts']['sourceSha256'] == digest(Path(str(artifact) + '.c'))
        if not args.libdwarf: assert 'verified packaged libraries' in transcript
        frames = [s for s in metadata(artifact)['sections'] if s['name'] == '.debug_frame']
        evidence_path = Path(str(artifact) + '.unwind.json')
        if mode == 'off':
            assert not evidence_path.exists() and not frames
        elif mode == 'strict':
            evidence = json.loads(evidence_path.read_text())
            assert not frames and not evidence['hasPlan'] and evidence['refusedRoots']
            assert evidence['inputSha256'] == digest(original) and evidence['sidecarSha256'] == digest(artifact)
            assert evidence['sourceSha256'] == digest(Path(str(artifact) + '.c'))
        else:
            frame, = frames
            raw = artifact.read_bytes()[frame['offset']:frame['offset'] + frame['size']]
            assert bool(frame['flags'] & 0x800) == (mode == 'compressed')
            if mode == 'compressed': raw = zlib.decompress(raw[24:])
            decoded = decode(raw, 8, 'little'); assert len(decoded) == 4
            check_description(evidence_path, artifact, original, decoded)
            evidence = json.loads(evidence_path.read_text())
            assert evidence['stackSeparation']['ranges'] == [{'first': hex(address), 'last': hex(address + size - 1)}]
            assert evidence['stackSeparation']['fixedPointers'] == []
        text = run([args.readelf, '-h', '-S', '--debug-dump=frames,info,abbrev,aranges,decodedline', artifact], work / (mode + '-gnu.log'))
        assert 'warning:' not in text.lower() and 'error:' not in text.lower()
        run([args.llvm, '--verify', artifact], work / (mode + '-llvm.log'))
        artifacts.append({'mode': mode, 'sidecarSha256': digest(artifact)})
    generation = [work / ('compressed.dbg' + suffix) for suffix in ('', '.c', '.unwind.json', '.gdb.py')]
    hashes = {path.name: digest(path) for path in generation}
    run(command, work / 'repeat.log')
    assert hashes == {path.name: digest(path) for path in generation}
    invalid = common + ['-Output', generation[0], '-SynthesizeUnwind', 'conditioned', '-UnwindStackSeparation', '200:100']
    (work / 'invalid.command.json').write_text(json.dumps(list(map(str, invalid))) + '\n')
    with (work / 'invalid.log').open('w') as stream:
        result = subprocess.run(list(map(str, invalid)), stdout=stream, stderr=subprocess.STDOUT, timeout=360)
    assert result.returncode == 10
    assert hashes == {path.name: digest(path) for path in generation}
    assert not list(work.glob('.forge-*'))
    assert protected == {path: digest(Path(path)) for path in protected}
    assert digest(original) == protected[str(args.reference_directory.resolve() / 'without-cfi')]
    assert digest(reference) == protected[str(args.reference_directory.resolve() / 'reference')]
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_POWERSHELL_UNWIND_EXPORT',
        'host': platform.system(), 'packagedNatives': not bool(args.libdwarf), 'exports': 5, 'invalidControls': 1,
        'artifacts': artifacts, 'generationSha256': hashes, 'originalSha256': digest(original),
        'referenceSha256': digest(reference), 'protectedSha256': protected,
        'gdb': 'NOT_RUN_PRODUCER_HOST', 'pinnedStrict': 'DEFERRED_TO_LINUX_CONSUMER'}, indent=4) + '\n')
    print('powershell-unwind-export=PASS host=' + platform.system())


if __name__ == '__main__':
    main()

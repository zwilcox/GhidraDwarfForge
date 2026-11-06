#!/usr/bin/env python3
"""Observe unchanged compiler global writes without accepting an unproved stack alias."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / 'src/test/integration'
helpers = runpy.run_path(str(SCRIPTS / 'cfi-encoder.py'))
run, metadata = (helpers[name] for name in ('run', 'metadata'))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--target', choices=('x86_64', 'aarch64'), required=True)
    parser.add_argument('--gradle-init', type=Path)
    parser.add_argument('--gradle-cache', type=Path)
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    prefix = '' if args.target == 'x86_64' else 'aarch64-linux-gnu-'
    source = ROOT / 'src/test/fixtures/synthetic-cfi.c'
    start = source.with_name('synthetic-cfi-start-' + args.target + '.S')
    protected = {str(path): digest(path) for path in (source, start)}
    reference, original = work / 'reference', work / 'original'
    run([prefix + 'gcc', '-O1', '-g', '-gdwarf-5', '-fomit-frame-pointer', '-fno-optimize-sibling-calls',
        '-fno-asynchronous-unwind-tables', '-fno-unwind-tables', '-fno-pie', '-no-pie', '-nostdlib', '-static',
        '-Wl,--build-id=none', source, start, '-o', reference], work / 'build.log')
    run([prefix + 'objcopy', '--strip-debug', reference, original], work / 'strip.log')
    protected.update({str(path): digest(path) for path in (original, reference)})
    info = metadata(original)
    data = original.read_bytes()
    symbols = run(['readelf', '-Ws', reference], work / 'symbols.log')
    lines = []
    for match in re.finditer(r'^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+FUNC\s+GLOBAL\s+\S+\s+\d+\s+(\S+)$', symbols, re.M):
        address, size = int(match[1], 16), int(match[2])
        section, = [section for section in info['sections'] if section['flags'] & 4 and
            section['address'] <= address and address + size <= section['address'] + section['size']]
        offset = section['offset'] + address - section['address']
        lines.append(f'{match[3]} {address:x} {data[offset:offset + size].hex()}')
    assert len(lines) == 5
    sink, = re.findall(r'^\s*\d+:\s+([0-9a-f]+)\s+8\s+OBJECT\s+GLOBAL\s+\S+\s+\d+\s+cfi_sink$', symbols, re.M)
    sink = int(sink, 16)
    functions = work / 'functions.txt'; functions.write_text('\n'.join(lines) + '\n')
    gradle = [ROOT / 'gradlew']
    if args.gradle_init:
        gradle += ['--init-script', args.gradle_init.resolve()]
    if args.gradle_cache:
        gradle += ['--project-cache-dir', args.gradle_cache.resolve()]
    observations = []
    for delta in (0, 0x400000):
        plan = work / ('plan-' + str(delta))
        refusal = 'callee store is not proved below entry stack'
        run([*gradle, 'unwindFrameRecoveryProbe', '-PframeInput=' + str(original), '-PframeFunctions=' + str(functions),
            '-PframePlan=' + str(plan), '-PframeRebase=' + str(delta), '-PframeRoot=cfi_main', '-PframeInspect=true',
            '-PframeExpectedFailure=' + refusal], work / ('probe-' + str(delta) + '.log'))
        assert not plan.exists(), 'negative fixture published a recovered frame plan'
        assert Path(str(plan) + '.refusal.txt').read_text() == refusal + '\n'
        text = Path(str(plan) + '.inspection.txt').read_text()
        assert 'Opaque[' not in text and 'omissions=[' in text
        writes = [line.split() for line in text.splitlines() if line.startswith('MEMORY_WRITE cfi_checkpoint ')]
        write, = writes
        assert write[3] == 'absolute:' + format(sink + delta, 'x') and write[4] == '8', write
        observations.append({'rebase': delta, 'globalWrite': write, 'refusal': refusal,
            'inspectionSha256': digest(Path(str(plan) + '.inspection.txt'))})
    assert protected == {path: digest(Path(path)) for path in protected}
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_OBSERVATION_AND_ALIAS_REFUSAL',
        'target': args.target, 'observations': observations, 'protectedSha256': protected,
        'scope': 'Exact compiler global-write capture; no separation assumption or generated CFI'}, indent=4) + '\n')
    print(args.target + ' compiler memory capture and conservative alias refusal PASS')


if __name__ == '__main__':
    main()

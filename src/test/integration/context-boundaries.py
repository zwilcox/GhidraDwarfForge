#!/usr/bin/env python3
"""Real ARM mode transitions and MIPS delay slots through context, native export and QEMU GDB."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from urllib.parse import unquote, urlsplit


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*')
        if p.is_file() and not p.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=['arm32', 'mips32be', 'mips32le'])
    for name in ('ghidra', 'consumer', 'producer', 'results'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    harness = Path(__file__).resolve().parent
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=args.target + '-', dir=args.results)).resolve()
    print('context-boundaries-results=' + str(root), flush=True)
    project, scripts = root / 'project', root / 'scripts'
    project.mkdir(); scripts.mkdir()
    helper = harness / 'ghidra_scripts/VerifyContextBoundaries.java'
    prepare = harness / 'ghidra_scripts/PrepareArmMixedBody.java'
    shutil.copy2(helper, scripts); shutil.copy2(prepare, scripts)
    module = args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    arm = args.target == 'arm32'
    stem = 'arm-mixed-body' if arm else 'mips-delay-context'
    sources = [harness.parent / ('fixtures/' + stem + '.S'), harness.parent /
        ('fixtures/' + ('arm-mixed-body-driver.c' if arm else stem + '.c'))]
    protected = {str(p.resolve()): digest(p) for p in [*sources, helper, prepare, Path(__file__),
        harness / 'context-boundaries-gdb.sh', harness / 'context-boundaries-gdb.py',
        module / 'lib/GhidraDwarfForge.jar', args.consumer, args.producer]}
    commands = []

    def run(label, command):
        command = list(map(str, command)); commands.append({'label': label, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as log:
            process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        assert process.returncode == 0, (label, process.returncode)
        return (root / (label + '.log')).read_text()

    prefix = {'arm32': 'arm-linux-gnueabihf-', 'mips32be': 'mips-linux-gnu-', 'mips32le': 'mipsel-linux-gnu-'}[args.target]
    flags = ['-march=armv7-a', '-marm', '-mfpu=vfpv3-d16', '-mfloat-abi=hard', '-DFORGE_MIXED_SPLIT=1'] if arm else []
    run('compile', [prefix + 'gcc', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie', *flags, *sources, '-o', root / 'reference'])
    run('strip', [prefix + 'objcopy', '--strip-debug', root / 'reference', root / 'original'])
    for p in (root / 'reference', root / 'original'): protected[str(p)] = digest(p)
    symbols = run('symbols', ['readelf', '-Ws', root / 'reference'])
    name = 'mixed_body' if arm else 'delay_context'
    entries = re.findall(r'(?m)^\s*\d+:\s+([0-9a-f]+)\s+\d+\s+FUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+' + name + r'$', symbols)
    entry, = set(int(v, 16) for v in entries)
    common = [args.ghidra / 'support/analyzeHeadless', project, 'Boundaries', '-scriptPath', scripts]
    preparation = ['-postScript', prepare.name, hex(entry), '0', 'split'] if arm else []
    log = run('import', common + ['-import', root / 'original', *preparation])
    assert 'ERROR REPORT SCRIPT ERROR' not in log
    states = [snapshot(project)]; generations = []
    for phase in ('first', 'second'):
        log = run(phase, common + ['-process', 'original', '-readOnly', '-noanalysis', '-postScript', helper.name,
            args.target, root, args.consumer, args.producer])
        assert 'context-boundaries=PASS' in log and 'ERROR REPORT SCRIPT ERROR' not in log
        generations.append({p.name: digest(p) for p in root.iterdir() if p.name.endswith(('.dbg', '.dbg.c')) or p.name == 'observations.json'})
        states.append(snapshot(project))
    assert generations[0] == generations[1]
    changed = {p for p in states[0].keys() | states[1].keys() if states[0].get(p) != states[1].get(p)}
    assert changed <= {'Boundaries.rep/idata/~index.bak', 'Boundaries.rep/idata/~journal.bak'}
    assert states[1] == states[2]
    observations = json.loads((root / 'observations.json').read_text())
    assert observations['entry'] == entry
    assert Path(unquote(urlsplit(observations['origin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    compiler_gdb = run('compiler-gdb', ['bash', harness / 'context-boundaries-gdb.sh', root, args.target, 'compiler'])
    assert 'context-boundaries-gdb=PASS' in compiler_gdb
    compiler_warnings = re.findall(r'(?m)^warning:.*$', compiler_gdb)
    for mode in (['full'] if arm else ['full', 'gap', 'partial']):
        sidecar = root / (mode + '.dbg')
        source = Path(str(sidecar) + '.c').read_text()
        assert 'DECOMPILATION_FAILURE_ENTRY_SAMPLE' in source
        if mode == 'gap':
            assert 'DELAY_SLOT_OUTSIDE_SELECTED_BODY_RANGE' in source
            assert 'raw instruction p-code' not in source and 'effective flow-override p-code' not in source
        if mode == 'partial':
            assert 'INCOMPLETE_DELAY_SLOT_CONTEXT' in source
            assert 'raw instruction p-code' not in source and 'effective flow-override p-code' not in source
        if mode == 'full': assert 'raw instruction p-code' in source and 'effective flow-override p-code' in source
        for view in ('info', 'abbrev', 'aranges', 'decodedline'):
            text = run(mode + '-' + view, ['readelf', '--debug-dump=' + view, sidecar])
            assert not re.search(r'warning:|error:', text, re.I)
        decoded = (root / (mode + '-decodedline.log')).read_text()
        assert not re.search(r'(?m)^\S+\s+\d+\s+0x[0-9a-fA-F]+\b', decoded)
        run(mode + '-identity', ['readelf', '-hSWn', root / 'original', sidecar])
        assert 'No errors.' in run(mode + '-llvm', ['llvm-dwarfdump', '--verify', sidecar])
        run(mode + '-strict', ['python3', harness / 'check-dwarfdump.py', sidecar, root / (mode + '-strict.log'), '--original', root / 'original'])
        gdb = run(mode + '-gdb', ['bash', harness / 'context-boundaries-gdb.sh', root, args.target, mode])
        assert 'context-boundaries-gdb=PASS' in gdb
        assert re.findall(r'(?m)^warning:.*$', gdb) == compiler_warnings
    assert protected == {p: digest(Path(p)) for p in protected} and snapshot(project) == states[-1]
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_CONTEXT_BOUNDARIES', 'target': args.target,
        'protectedSha256': protected, 'generations': generations, 'observations': observations,
        'corroboratedWarnings': compiler_warnings,
        'firstReopenBackups': sorted(changed), 'projectSha256': states[-1]}, indent=4) + '\n')
    print('context-boundaries-harness=PASS ' + args.target)


if __name__ == '__main__':
    main()

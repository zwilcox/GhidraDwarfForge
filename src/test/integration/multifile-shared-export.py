#!/usr/bin/env python3
"""Validate multi-file shared-object source stepping with independent runtime load bias."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

TARGETS = {
    'x86_64': ('', []),
    'aarch64': ('aarch64-linux-gnu-', []),
    'arm32': ('arm-linux-gnueabihf-', ['-march=armv7-a', '-marm', '-mfpu=vfpv3-d16']),
    'mips32be': ('mips-linux-gnu-', []),
    'mips32le': ('mipsel-linux-gnu-', []),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('--role', choices=['shared', 'shared-rebased'], default='shared')
    parser.add_argument('--java', type=Path, help='explicit Java runtime with isolated script caches')
    parser.add_argument('--dwarfdump', default=os.environ.get('DWARFDUMP', 'dwarfdump'))
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    harness = Path(__file__).resolve().parent
    repository = harness.parents[2]
    results = repository / 'build/test-results/multifile-shared'
    results.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix=args.target + '-' + args.role + '-', dir=results))
    print('multifile-results=' + str(case), flush=True)
    headless = [ghidra / 'support/analyzeHeadless']
    if args.java:
        java = args.java.resolve(strict=True)
        vmargs = subprocess.check_output([java, '-cp', ghidra / 'support/LaunchSupport.jar',
            'LaunchSupport', ghidra, '-vmargs'], text=True).splitlines()
        for name in ('java-home', 'java-tmp'):
            (case / name).mkdir()
        headless = [java, *vmargs, '-Duser.home=' + str(case / 'java-home'),
            '-Djava.io.tmpdir=' + str(case / 'java-tmp'), '-Xmx2G', '-XX:ParallelGCThreads=2',
            '-XX:CICompilerCount=2', '-Djava.awt.headless=true', '-cp',
            ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar', 'ghidra.Ghidra',
            'ghidra.app.util.headless.AnalyzeHeadless']
    commands = []

    def run(label, command):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('w') as stream:
            subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=300, check=True)

    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    source = harness / 'fixtures/multifile-source.c'
    protected_paths = [source, Path(__file__), harness / 'multifile-shared-gdb.py',
        harness / 'multifile-shared-gdb.sh', harness / 'check-multifile-semantics.py',
        harness / 'qemu-socket.sh', harness / 'check-dwarfdump.py',
        harness / 'ghidra_scripts/RebaseFixtureProgram.java',
        *[p for p in module.rglob('*') if p.is_file()]]
    protected = {str(p): digest(p) for p in protected_paths}
    prefix, flags = TARGETS[args.target]
    run('compiler-version', [prefix + 'gcc', '--version'])
    if args.java:
        run('java-version', [args.java, '-version'])
    layout = ['-fPIC', '-shared']
    reference, original = case / 'reference', case / 'original'
    run('compile', [prefix + 'gcc', '-g', '-gdwarf-5', '-O0', '-fno-omit-frame-pointer',
        '-fasynchronous-unwind-tables', *flags, *layout, source, '-o', reference])
    # Retain ELF symbol names but remove all compiler DWARF. Curated fully
    # stripped semantic fixtures are separate tests; this is a source oracle.
    run('strip', [prefix + 'objcopy', '--strip-debug', reference, original])
    protected.update({str(p): digest(p) for p in (reference, original)})
    run('original-elf', ['readelf', '-hSWn', original])
    run('compiler-llvm', ['llvm-dwarfdump', '--verify', reference])
    driver_source = case / 'driver.c'
    driver_source.write_text('''#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
volatile uintptr_t forge_library_bias;
__attribute__((noinline)) void forge_library_ready(void) {
    __asm__ volatile ("" ::: "memory");
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    struct link_map *map;
    if (!module || dlinfo(module, RTLD_DI_LINKMAP, &map)) return 3;
    int (*function)(int) = (int (*)(int))dlsym(module, "recovered_first");
    if (!function) return 4;
    forge_library_bias = (uintptr_t)map->l_addr;
    forge_library_ready();
    int value = function(5);
    return dlclose(module) == 0 && value == 10 ? 0 : 5;
}
''')
    run('driver-compile', [prefix + 'gcc', '-g', '-gdwarf-5', '-O0', '-fno-pie', '-no-pie',
        *flags, driver_source, '-ldl', '-o', case / 'driver'])
    addresses = {}
    for line in subprocess.check_output(['readelf', '-Ws', str(original)], text=True).splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in ('recovered_first', 'recovered_second'):
            addresses[fields[7]] = [int(fields[1], 16), int(fields[1], 16) + int(fields[2])]
    assert len(addresses) == 2
    (case / 'addresses.json').write_text(json.dumps(addresses, indent=4) + '\n')
    protected.update({str(p): digest(p) for p in (driver_source, case / 'driver', case / 'addresses.json')})
    run('compiler-gdb', ['bash', harness / 'multifile-shared-gdb.sh', case, args.target, 'compiler', reference])
    project = case / 'project'
    project.mkdir()
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if args.role == 'shared-rebased' else []
    run('import', [*headless, project, 'MultiFile', '-import', original, '-loader', 'ElfLoader',
        '-analysisTimeoutPerFile', '120', '-scriptPath', harness / 'ghidra_scripts', *rebase])
    before = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    sidecar = case / 'forge.dbg'
    baseline = case / 'single' / sidecar.name
    baseline.parent.mkdir()
    inventory = None
    for label, destination, options in [('single', baseline, []), ('multi', sidecar, ['--source-lines=8']),
            ('repeat', sidecar, ['--source-lines=8'])]:
        run('export-' + label, [*headless, project, 'MultiFile', '-process', 'original', '-readOnly',
            '-noanalysis', '-postScript', 'GhidraDwarfForge.java', '--packaged-natives',
            '--output=' + str(destination), *options])
        log = (case / ('export-' + label + '.log')).read_text()
        assert 'GhidraDwarfForge symbol export PASS' in log
        report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
            for line in log.splitlines() if 'GhidraDwarfForge report: {' in line]
        assert report['failure'] is None and not report['failedFunctions']
        (case / (label + '-report.json')).write_text(json.dumps(report, indent=4) + '\n')
        if options:
            current = {p.name: digest(p) for p in [sidecar, Path(str(sidecar) + '.c'), *case.glob('forge-src-*')]}
            assert inventory is None or inventory == current, 'partitioned output is not deterministic'
            inventory = current
    after = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    assert changed <= {'MultiFile.rep/idata/~index.bak', 'MultiFile.rep/idata/~journal.bak'}
    run('semantics', ['python3', harness / 'check-multifile-semantics.py', original, baseline, sidecar, case / 'semantics'])
    warnings = []
    for label, destination in [('single', baseline), ('multi', sidecar)]:
        original_header, output_header = original.read_bytes()[:64], destination.read_bytes()[:64]
        flags_offset = 48 if original_header[4] == 2 else 36
        assert original_header[:20] == output_header[:20], 'ELF target identity changed'
        assert original_header[flags_offset:flags_offset + 4] == output_header[flags_offset:flags_offset + 4], 'ABI flags changed'
        for dump in ['info', 'abbrev', 'aranges', 'decodedline', 'Ranges', 'loc']:
            run(label + '-' + dump, ['readelf', '-hSWn', '--debug-dump=' + dump, destination])
            assert not re.search(r'\b(?:warning|error):', (case / (label + '-' + dump + '.log')).read_text(), re.I)
        assert re.findall(r'Build ID: (\w+)', (case / 'original-elf.log').read_text()) == re.findall(
            r'Build ID: (\w+)', (case / (label + '-info.log')).read_text()), 'build identity changed'
        run(label + '-llvm', ['llvm-dwarfdump', '--verify', destination])
        run(label + '-strict', ['python3', harness / 'check-dwarfdump.py', destination,
            case / (label + '-dwarfdump.log'), '--tool', args.dwarfdump, '--original', original])
        run(label + '-gdb', ['bash', harness / 'multifile-shared-gdb.sh', case, args.target, label, destination])
    for label in ('compiler', 'single', 'multi'):
        text = (case / (label + '-gdb.log')).read_text()
        assert 'multifile-shared-gdb=PASS ' + label in text
        observed = [re.sub(r'0x[0-9a-f]+', 'ADDRESS', line) for line in text.splitlines()
            if re.match(r'\s*(warning:|error:)', line, re.I)]
        allowed = {'warning: BFD: warning: system-supplied DSO at ADDRESS has a corrupt string table index'} \
            if args.target in ('aarch64', 'arm32') else set()
        assert set(observed) <= allowed, observed
        warnings.append(Counter(observed))
    assert warnings[0] == warnings[1] == warnings[2]
    assert protected == {path: digest(Path(path)) for path in protected}
    (case / 'acceptance.json').write_text(json.dumps({'status': 'MULTIFILE_SHARED_PASS',
        'target': args.target, 'role': args.role, 'sourceInventory': inventory, 'protected': protected,
        'projectBackupChanges': sorted(changed),
        'arm32Sysroot': os.environ.get('FORGE_ARM32_SYSROOT'),
        'scope': 'Partially stripped DSO, independent link-map load bias, source stepping and complete semantic layout comparison.'}, indent=4) + '\n')
    print('multifile-shared-export=PASS', args.target, args.role, flush=True)


if __name__ == '__main__':
    main()

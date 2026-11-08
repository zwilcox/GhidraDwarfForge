#!/usr/bin/env python3
"""Exercise real multi-file publication interruptions, rollback, retries and GDB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess

SCRIPTS = Path(__file__).resolve().parent
TARGETS = runpy.run_path(str(SCRIPTS / 'multifile-export.py'))['TARGETS']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--java', type=Path)
    parser.add_argument('--dwarfdump', default=os.environ.get('DWARFDUMP', 'dwarfdump'))
    args = parser.parse_args()
    work = args.work.resolve(); work.mkdir(parents=True, exist_ok=False)
    artifacts = args.artifacts.resolve() if args.artifacts else work / 'artifacts'
    artifacts.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    protected = {str(path): digest(path) for path in [Path(__file__),
        SCRIPTS / 'ghidra_scripts/CheckMultiFilePublication.java',
        SCRIPTS / 'fixtures/multifile-source.c', SCRIPTS / 'multifile-target-gdb.py',
        SCRIPTS / 'multifile-target-gdb.sh', *[p for p in module.rglob('*') if p.is_file()]]}

    def run(label, command):
        command = list(map(str, command))
        (work / (label + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        with (work / (label + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=1200, check=True)
        return (work / (label + '.log')).read_text()

    headless = [ghidra / 'support/analyzeHeadless']
    if args.java:
        java = args.java.resolve(strict=True)
        vmargs = subprocess.check_output([java, '-cp', ghidra / 'support/LaunchSupport.jar',
            'LaunchSupport', ghidra, '-vmargs'], text=True).splitlines()
        (work / 'java-home').mkdir(); (artifacts / 'java-tmp').mkdir()
        headless = [java, *vmargs, '-Duser.home=' + str(work / 'java-home'),
            '-Djava.io.tmpdir=' + str(artifacts / 'java-tmp'), '-Xmx2G', '-XX:ParallelGCThreads=2',
            '-XX:CICompilerCount=2', '-Djava.awt.headless=true', '-showversion', '-cp',
            ghidra / 'Ghidra/Framework/Utility/lib/Utility.jar', 'ghidra.Ghidra',
            'ghidra.app.util.headless.AnalyzeHeadless']
    prefix, flags = TARGETS[args.target]
    original, reference = artifacts / 'original', artifacts / 'reference'
    run('compile', [prefix + 'gcc', '-g', '-gdwarf-5', '-O0', '-fno-pie', '-no-pie',
        '-fno-omit-frame-pointer', '-fasynchronous-unwind-tables', *flags,
        SCRIPTS / 'fixtures/multifile-source.c', '-o', reference])
    run('strip', [prefix + 'objcopy', '--strip-debug', reference, original])
    protected.update({str(path): digest(path) for path in (original, reference)})
    reference_gdb = run('compiler-gdb', ['bash', SCRIPTS / 'multifile-target-gdb.sh', artifacts,
        args.target, 'compiler', reference])
    project = work / 'project'; project.mkdir()
    run('import', [*headless, project, 'Publication', '-import', original, '-loader', 'ElfLoader'])
    before = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    output = artifacts / 'publication'
    transcript = run('publication', [*headless, project, 'Publication', '-process', 'original', '-readOnly',
        '-noanalysis', '-scriptPath', SCRIPTS / 'ghidra_scripts', '-postScript', 'CheckMultiFilePublication.java',
        original, output, 'zlib'])
    assert 'multifile-publication=PASS cases=28' in transcript
    result = json.loads((output / 'result.json').read_text())
    assert result['status'] == 'PASS_MULTIFILE_PUBLICATION' and len(result['cases']) == 28
    observations = []
    for item in result['cases']:
        name = item['case']; case = output / name; sidecar = case / 'target.dbg'
        for part, expected in item['successfulInventory'].items():
            assert digest(case / part) == expected
        for view in ('info', 'abbrev', 'aranges', 'decodedline'):
            text = run(name + '-' + view, ['readelf', '-hSWn', '--debug-dump=' + view, sidecar])
            assert not re.search(r'\b(?:warning|error):', text, re.I)
        run(name + '-llvm', ['llvm-dwarfdump', '--verify', sidecar])
        run(name + '-strict', ['python3', SCRIPTS / 'check-dwarfdump.py', sidecar,
            work / (name + '-dwarfdump.log'), '--tool', args.dwarfdump, '--original', original])
        # Each debugger invocation needs its own runtime/log directory. This
        # extra link is added only after the publication inventory was verified.
        os.link(original, case / 'original')
        text = run(name + '-gdb', ['bash', SCRIPTS / 'multifile-target-gdb.sh', case, args.target, 'multi', sidecar])
        assert 'multifile-target-gdb=multi PASS' in text
        def warnings(value):
            return {re.sub(r'0x[0-9a-f]+', '<address>', line) for line in value.splitlines()
                if re.match(r'\s*(warning:|error:)', line, re.I)}
        allowed = {'warning: BFD: warning: system-supplied DSO at <address> has a corrupt string table index'} \
            if args.target in ('aarch64', 'arm32') else set()
        assert warnings(text) <= allowed and warnings(text) <= warnings(reference_gdb)
        observations.append({'case': name, 'gdb': json.loads((case / 'multi-observations.json').read_text())})
        for part, expected in item['successfulInventory'].items():
            assert digest(case / part) == expected
    after = {str(p.relative_to(project)): digest(p) for p in project.rglob('*') if p.is_file()}
    changed = {name for name in before.keys() | after.keys() if before.get(name) != after.get(name)}
    assert changed <= {'Publication.rep/idata/~index.bak', 'Publication.rep/idata/~journal.bak'}
    assert protected == {name: digest(Path(name)) for name in protected}
    (work / 'acceptance.json').write_text(json.dumps({'status': 'PASS_MULTIFILE_PUBLICATION_RUNTIME',
        'target': args.target, 'publication': result, 'observations': observations,
        'protectedSha256': protected, 'projectBackupChanges': sorted(changed)}, indent=4) + '\n')
    print('multifile-publication-runtime=PASS', args.target, flush=True)


if __name__ == '__main__':
    main()

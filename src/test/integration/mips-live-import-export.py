#!/usr/bin/env python3
"""Verify allocation and real exports before closing a freshly analyzed program."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('layout', source / 'mips-layout-arguments.py')
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)
support = layout.support


def main(baseline, ghidra, debugger, data):
    baseline, ghidra = baseline.resolve(strict=True), ghidra.resolve(strict=True)
    assert json.loads((baseline / 'result.json').read_text())['status'] in ('PASS', 'LIVE_PENDING')
    case = Path(tempfile.mkdtemp(prefix='live.', dir=baseline))
    print(case, flush=True)
    metadata = json.loads((baseline / 'metadata.json').read_text())
    for name in ('input', 'reference', 'labels.txt', 'metadata.json'):
        shutil.copy2(baseline / name, case / name)
    if (baseline / 'driver').exists():
        shutil.copy2(baseline / 'driver', case / 'driver')
    scripts, project = case / 'scripts', case / 'project'
    scripts.mkdir()
    project.mkdir()
    for name in ('ProbeMipsLayoutArguments.java', 'RepeatLiveAbiExport.java', 'RebaseFixtureProgram.java'):
        shutil.copy2(source / 'ghidra_scripts' / name, scripts / name)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    protected = [p for p in [*case.iterdir(), *scripts.iterdir(), *module.rglob('*'),
        Path(__file__), source / 'mips-layout-arguments-gdb.py', source / 'mips-layout-arguments-gdb.sh'] if p.is_file()]
    hashes = {str(p): support.digest(p) for p in protected}
    (case / 'protected-before.json').write_text(json.dumps(hashes, indent=4) + '\n')
    output = case / 'input.dbg'
    rebase = ['-postScript', 'RebaseFixtureProgram.java', '0x2000000'] if metadata['role'].endswith('-rebased') else []
    command = [ghidra / 'support/analyzeHeadless', project, 'Live', '-import', case / 'input',
        '-analysisTimeoutPerFile', '120', '-scriptPath', scripts, *rebase,
        '-postScript', 'ProbeMipsLayoutArguments.java', case / 'labels.txt', case / 'curated.json',
        '-postScript', 'RepeatLiveAbiExport.java', output]
    support.run(command, case / 'import-export.log', timeout=240)
    log = (case / 'import-export.log').read_text()
    assert 'REPORT SCRIPT ERROR' not in log and 'live-abi-export-repeat=PASS' in log
    assert log.count('GhidraDwarfForge symbol export PASS') == 2
    assert 'allocation correction unavailable' not in log
    for name, command in (
            ('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', output]),
            ('llvm', ['llvm-dwarfdump', '--verify', output]),
            ('strict-driver', ['python3', source / 'check-dwarfdump.py', output, case / 'strict.log', '--original', case / 'input']),
            ('gdb', ['bash', source / 'mips-layout-arguments-gdb.sh', case, 'forge', debugger, data])):
        support.run(command, case / (name + '.log'), timeout=120)
        support.require_clean(case / (name + '.log'))
    assert 'MIPS_LAYOUT_FORGE_PASS' in (case / 'gdb.log').read_text()
    assert hashes == {name: support.digest(Path(name)) for name in hashes}
    (case / 'result.json').write_text(json.dumps(dict(status='PASS', role=metadata['role'],
        liveExports=2, artifactSha256=[support.digest(output), support.digest(Path(str(output) + '.c'))],
        unchangedInputs=True), indent=4) + '\n')
    print('mips-live-import-export=PASS', case, flush=True)


if __name__ == '__main__':
    main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '')

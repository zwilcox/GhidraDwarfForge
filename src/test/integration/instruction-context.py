#!/usr/bin/env python3
"""Validate bounded packaged instruction reads on private saved Ghidra fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
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
    for name in ('ghidra', 'fixture', 'results'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='context-', dir=args.results)).resolve()
    print('instruction-context-results=' + str(root), flush=True)
    scripts, project = root / 'scripts', root / 'project'
    scripts.mkdir()
    project.mkdir()
    helper = Path(__file__).with_name('ghidra_scripts') / 'VerifyInstructionContext.java'
    shutil.copy2(helper, scripts / helper.name)
    original = root / 'fixture'
    shutil.copy2(args.fixture, original)
    jar = args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p.resolve()): digest(p) for p in [Path(__file__), helper, args.fixture, original, jar]}
    commands = []

    def run(phase, command):
        command = list(map(str, command))
        commands.append({'phase': phase, 'argv': command})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (phase + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=300)
        text = (root / (phase + '.log')).read_text()
        assert result.returncode == 0 and 'instruction-context=PASS' in text, phase
        assert 'ERROR REPORT SCRIPT ERROR' not in text and 'error: cannot find symbol' not in text

    base = [args.ghidra / 'support/analyzeHeadless', project, 'Context', '-scriptPath', scripts]
    run('setup', base + ['-import', original, '-noanalysis', '-postScript', helper.name, 'setup', root / 'setup.json'])
    states = [snapshot(project)]
    for phase in ('read1', 'read2'):
        run(phase, base + ['-process', 'fixture', '-readOnly', '-noanalysis', '-postScript', helper.name, 'read', root / (phase + '.json')])
        states.append(snapshot(project))
        (root / (phase + '-project.json')).write_text(json.dumps(states[-1], indent=4) + '\n')
    assert (root / 'read1.json').read_bytes() == (root / 'read2.json').read_bytes()
    changed = [key for key in states[0].keys() | states[1].keys() if states[0].get(key) != states[1].get(key)]
    assert set(changed) <= {'Context.rep/idata/~index.bak', 'Context.rep/idata/~journal.bak'}, changed
    assert states[1] == states[2]
    observed = json.loads((root / 'read1.json').read_text())
    assert Path(unquote(urlsplit(observed['origin']).path)).resolve() == jar.resolve()
    assert all(observed[k]['cancellationPoints'] > 0 for k in ('split', 'truncated', 'override', 'unmapped', 'uninitialized', 'undecoded'))
    assert protected == {p: digest(Path(p)) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_PACKAGED_INSTRUCTION_CONTEXT',
        'observations': observed, 'protectedSha256': protected, 'firstReopenBackups': changed,
        'scope': 'Read-only packaged instruction component; no production source/DWARF context emission yet.'}, indent=4) + '\n')
    print('instruction-context-harness=PASS ' + observed['language'])


if __name__ == '__main__':
    main()

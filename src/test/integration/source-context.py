#!/usr/bin/env python3
"""Run native source-context component checks against a saved instruction-context fixture."""
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
    return {str(path.relative_to(root)): digest(path) for path in root.rglob('*')
        if path.is_file() and not path.name.endswith('.lock')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('ghidra', 'context_fixture', 'results'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='source-context-', dir=args.results)).resolve()
    print(root, flush=True)
    helper = Path(__file__).with_name('ghidra_scripts') / 'VerifySourceContext.java'
    scripts = root / 'scripts'
    scripts.mkdir()
    shutil.copy2(helper, scripts / helper.name)
    project = args.context_fixture / 'project'
    before = snapshot(project)
    jar = args.ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p.resolve()): digest(p) for p in [helper, Path(__file__), jar, args.context_fixture / 'fixture']}
    commands = []
    for phase in ('first', 'second'):
        output = root / phase
        command = list(map(str, [args.ghidra / 'support/analyzeHeadless', project, 'Context',
            '-scriptPath', scripts, '-process', 'fixture', '-readOnly', '-noanalysis',
            '-postScript', helper.name, output]))
        commands.append(command)
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (phase + '.log')).open('w') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
        text = (root / (phase + '.log')).read_text()
        assert result.returncode == 0 and 'source-context=PASS' in text, phase
        assert snapshot(project) == before, 'saved project changed'
        receipt = json.loads((output / 'result.json').read_text())
        assert Path(unquote(urlsplit(receipt['origin']).path)).resolve() == jar.resolve()
    assert snapshot(root / 'first') == snapshot(root / 'second'), 'fresh-process results differ'
    assert protected == {path: digest(Path(path)) for path in protected}, 'protected inputs changed'
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_NATIVE_SOURCE_CONTEXT_COMPONENT',
        'protectedSha256': protected, 'projectSha256': before, 'outputsSha256': snapshot(root / 'first')}, indent=4) + '\n')
    print('source-context-harness=PASS')


if __name__ == '__main__':
    main()

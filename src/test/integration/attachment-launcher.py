#!/usr/bin/env python3
"""Owned launcher routing controls; fake authorizers never acquire OS privileges."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = ROOT / 'support/ghidra-dwarf-forge-attach'


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    with tempfile.TemporaryDirectory(prefix='forge launcher λ ') as temporary:
        root = Path(temporary)
        ghidra = root / 'ghidra'
        module = root / 'module'
        for file in [module / 'lib/GhidraDwarfForge.jar',
                     ghidra / 'Ghidra/Framework/Pty/lib/jna-5.14.0.jar',
                     ghidra / 'Ghidra/Framework/Generic/lib/gson-2.9.0.jar']:
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('owned fake dependency; no native claim')
        log = root / 'calls.jsonl'
        java = root / 'java'
        java.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FORGE_TEST_CALLS'], 'a', encoding='utf-8') as out:
    out.write(json.dumps({'kind':'java','argv':sys.argv[1:]}) + '\\n')
preview = '--preview' in sys.argv
print(json.dumps({'outcome': 'PREVIEW' if preview else 'TEST_ONLY_EXECUTION'}))
sys.exit(int(os.environ.get('FORGE_TEST_PREVIEW_STATUS' if preview else 'FORGE_TEST_EXEC_STATUS', '0')))
''')
        java.chmod(0o755)
        for name in ['sudo', 'pkexec']:
            file = root / name
            file.write_text('''#!/usr/bin/env python3
import json, os, subprocess, sys
with open(os.environ['FORGE_TEST_CALLS'], 'a', encoding='utf-8') as out:
    out.write(json.dumps({'kind':os.path.basename(sys.argv[0]),'argv':sys.argv[1:]}) + '\\n')
args = sys.argv[1:]
if args[0] == '--': args = args[1:]
sys.exit(subprocess.run(args).returncode)
''')
            file.chmod(0o755)
        request = root / 'literal $(touch PWNED) ; [x] " λ.json'
        base = [str(LAUNCHER), '--ghidra-dir=' + str(ghidra), '--extension-dir=' + str(module),
                '--java=' + str(java), '--request=' + str(request), '--request-sha256=' + 'a' * 64]
        env = {**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'], 'FORGE_TEST_CALLS': str(log)}
        cases = 0

        def run(extra, status, kinds, overrides=None):
            nonlocal cases
            if log.exists():
                log.unlink()
            result = subprocess.run(base + extra, env={**env, **(overrides or {})}, cwd=root,
                                    capture_output=True, text=True, timeout=15)
            calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            require(result.returncode == status, str((extra, result.returncode, result.stderr)))
            require([call['kind'] for call in calls] == kinds, str(calls))
            for call in calls:
                if call['kind'] == 'java':
                    index = call['argv'].index('--request')
                    require(call['argv'][index + 1] == str(request), 'request argument was split or evaluated')
                    require(call['argv'][index + 3] == 'a' * 64, 'request digest changed')
            require(not (root / 'PWNED').exists(), 'request path was evaluated by a shell')
            cases += 1
            return calls

        run([], 64, ['java'])
        run(['--authorize=sudo'], 64, ['java'])
        run(['--preview', '--authorize=sudo'], 0, ['java'])
        run(['--confirm-target-change'], 17, ['java', 'java'], {'FORGE_TEST_EXEC_STATUS': '17'})
        calls = run(['--confirm-target-change', '--authorize=sudo'], 0, ['java', 'sudo', 'java'])
        require(calls[1]['argv'][0] == '--' and calls[1]['argv'][1] == str(java), 'sudo command boundary differs')
        calls = run(['--recover', '--confirm-target-change', '--authorize=pkexec'], 0, ['java', 'pkexec', 'java'])
        require(calls[1]['argv'][0] == str(java) and '--recover' in calls[-1]['argv'], 'pkexec recovery command differs')
        run(['--confirm-target-change', '--authorize=sudo'], 23, ['java'], {'FORGE_TEST_PREVIEW_STATUS': '23'})
        run(['--confirm-target-change', '--confirm-target-change'], 64, [])
        run(['--authorize=automatic'], 64, [])
        run(['--unknown'], 64, [])
        control = str(root / 'cancel λ $(literal)')
        calls = run(['--confirm-target-change', '--authorize=pkexec', '--cancel-file=' + control],
                    0, ['java', 'pkexec', 'java'])
        for call in calls:
            index = call['argv'].index('--cancel-file')
            require(call['argv'][index + 1] == control, 'cancellation selection was split or lost')
        run(['--cancel-file=relative'], 64, [])
        print(f'attachment-launcher=PASS cases={cases} actual-elevation=false native-execution=false')


if __name__ == '__main__':
    main()

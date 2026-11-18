"""Single-use adapter for the real wrapper's analyzer invocation, not a JVM launcher."""
import json
import os
from pathlib import Path
import sys


root = Path(__file__).resolve().parents[1]
try:
    with (root / 'invoked').open('x') as marker:
        marker.write('analyzeHeadless\n')
except FileExistsError:
    (root / 'duplicate').touch()
    raise SystemExit('coverage analyzer adapter invoked more than once')
command = json.loads((root / 'command.json').read_text(encoding='utf-8'))
os.execv(command[0], [*command, *sys.argv[1:]])

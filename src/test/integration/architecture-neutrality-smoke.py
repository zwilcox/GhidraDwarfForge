#!/usr/bin/env python3
"""Ensure the architecture gate rejects violations without relying on ripgrep."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

script = Path(__file__).with_name('architecture-neutrality.sh')
with tempfile.TemporaryDirectory(prefix='forge-architecture-check-') as temporary:
    root = Path(temporary)
    copied = root / 'src/test/integration/architecture-neutrality.sh'
    copied.parent.mkdir(parents=True)
    shutil.copyfile(script, copied)
    source = root / 'src/main/java'
    source.mkdir(parents=True)
    binary = root / 'bin'
    binary.mkdir()
    stub = binary / 'rg'
    stub.write_text('#!/bin/sh\necho unexpected-rg >&2\nexit 127\n')
    stub.chmod(0o755)
    env = os.environ.copy()
    env['PATH'] = str(binary) + os.pathsep + env['PATH']

    def run(success, expected):
        result = subprocess.run(['bash', str(copied)], env=env, capture_output=True, text=True, check=False)
        assert (result.returncode == 0) == success, result
        assert expected in result.stdout + result.stderr
        assert 'unexpected-rg' not in result.stderr
        assert ('architecture-neutrality=PASS' in result.stdout) == success

    run(False, 'no Java sources')
    generic = source / 'Generic.java'
    generic.write_text('class Generic { String value = "plain"; }\n')
    run(True, 'architecture-neutrality=PASS')
    generic.write_text('class Generic { String value = "R0"; }\n')
    run(False, 'src/main/java/Generic.java:1:')
    for spelling in ('EM_386', 'ESP'):
        generic.write_text('class Generic { String value = "' + spelling + '"; }\n')
        run(False, 'src/main/java/Generic.java:1:')
    generic.write_text('class Generic { String value = "plain"; }\n')
    audited = source / 'ghidradwarfforge/elf/MipsAbiFlags.java'
    audited.parent.mkdir(parents=True)
    audited.write_text('class MipsAbiFlags { String value = "r2"; }\n')
    run(True, 'architecture-neutrality=PASS')
    outside = source / 'other/MipsAbiFlags.java'
    outside.parent.mkdir()
    shutil.copyfile(audited, outside)
    run(False, 'src/main/java/other/MipsAbiFlags.java:1:')
print('architecture-neutrality-smoke=PASS checks=7')

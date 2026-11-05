#!/usr/bin/env python3
"""Runtime observations must survive PowerShell colors without weakening identity checks."""
import importlib.util
from pathlib import Path
import tempfile


spec = importlib.util.spec_from_file_location('observations',
    Path(__file__).with_name('headless-observations.py'))
observations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observations)

with tempfile.TemporaryDirectory(prefix='forge-headless-observation-') as temporary:
    root = Path(temporary)
    module = root / 'module'
    scripts = module / 'ghidra_scripts'
    scripts.mkdir(parents=True)
    script = scripts / 'GhidraDwarfForge.java'
    script.write_text('// observation fixture\n', encoding='utf-8')
    log, stderr = root / 'export.log', root / 'export.stderr'
    banner = 'openjdk version "21.0.13" 2026-10-20 LTS\n'
    selected = f'INFO  SCRIPT: {script} (HeadlessAnalyzer)\n'
    checks = 0
    for out, err in ((selected, banner), (banner + selected, ''),
            ('\x1b[31;1m' + banner.rstrip() + '\x1b[0m\n' + selected, ''),
            (selected, '\x1b[31;1m' + banner.rstrip() + '\x1b[0m\n')):
        log.write_text(out, encoding='utf-8')
        stderr.write_text(err, encoding='utf-8')
        observed = observations.verify(log, module, exported=True)
        assert observed['javaVersions'] == ['21.0.13']
        assert observed['packagedScript'] == str(script.resolve())
        checks += 1
    for out, err in ((selected, ''), ('mentioned ' + banner + selected, ''),
            (banner + selected, 'java version "25.0.1"\n'),
            ('\x1b[31;1m' + banner.replace('21.', '25.') + '\x1b[0m' + selected, ''),
            (banner, ''), (banner + selected * 2, ''),
            (banner + selected.replace(str(script), str(root / 'wrong/GhidraDwarfForge.java')), ''),
            ('\x1b[2K' + banner + selected, '')):
        log.write_text(out, encoding='utf-8')
        stderr.write_text(err, encoding='utf-8')
        try:
            observations.verify(log, module, exported=True)
        except (ValueError, FileNotFoundError):
            checks += 1
        else:
            raise AssertionError('invalid observation accepted: ' + repr((out, err)))
    print(f'headless-observations=PASS checks={checks}')

"""Verify benchmark logs describe the intended runtime and packaged script."""

from pathlib import Path
import re


def verify(log, module, java_major=21, exported=False):
    text = log.read_text() + '\n' + log.with_suffix('.stderr').read_text()
    versions = re.findall(r'(?m)^(?:openjdk|java) version "([^"\n]+)"', text)
    if not versions or any(int(version.split('.')[0]) != java_major for version in versions):
        raise ValueError(f'headless runtime is not verified Java {java_major}: {versions}')
    scripts = re.findall(r'(?m)^INFO\s+SCRIPT: (.+GhidraDwarfForge\.java) \(HeadlessAnalyzer\)\s*$', text)
    expected = (module / 'ghidra_scripts/GhidraDwarfForge.java').resolve(strict=True)
    if exported and (len(scripts) != 1 or Path(scripts[0]).resolve(strict=True) != expected):
        raise ValueError('headless export did not execute the selected packaged script: ' + repr(scripts))
    return {'javaVersions': versions, 'packagedScript': str(expected) if exported else None}

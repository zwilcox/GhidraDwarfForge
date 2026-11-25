"""Verify benchmark logs describe the intended runtime and packaged script."""

from pathlib import Path
import re


def verify(log, module, java_major=21, exported=False, saved_project=False):
    text = log.read_text(encoding='utf-8') + '\n' + log.with_suffix('.stderr').read_text(encoding='utf-8')
    # PowerShell's merged native stderr is rendered with SGR color sequences.
    # Remove presentation only; retain anchoring and reject every conflicting
    # runtime banner rather than accepting an arbitrary mention of Java 21.
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    versions = re.findall(r'(?m)^(?:openjdk|java) version "([^"\n]+)"', text)
    if not versions or any(int(version.split('.')[0]) != java_major for version in versions):
        raise ValueError(f'headless runtime is not verified Java {java_major}: {versions}')
    expected = (module / 'ghidra_scripts/GhidraDwarfForge.java').resolve(strict=True)
    if not (exported or saved_project):
        return {'javaVersions': versions, 'packagedScript': None}
    # Older packages ran the exporter directly even for a saved project.
    read_only = module / 'ghidra_scripts/GhidraDwarfForgeReadOnly.java'
    if saved_project and read_only.is_file():
        expected = read_only.resolve(strict=True)
        completed = re.findall(r'(?m)^INFO +GhidraDwarfForge\.java> GhidraDwarfForge symbol export PASS '
            r'\(GhidraScript\)[ \t]*\r?$', text)
        if len(completed) != 1:
            raise ValueError('read-only entry point did not record exactly one completed export')
    scripts = re.findall(r'(?m)^INFO +SCRIPT: (.+GhidraDwarfForge(?:ReadOnly)?\.java) '
        r'\(HeadlessAnalyzer\)[ \t]*\r?$', text)
    if len(scripts) != 1 or Path(scripts[0]).resolve(strict=True) != expected:
        raise ValueError('headless export did not execute the selected packaged script: ' + repr(scripts))
    return {'javaVersions': versions, 'packagedScript': str(expected)}

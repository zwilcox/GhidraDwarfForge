#!/usr/bin/env python3
"""Probe the installed exporter against MMIO references; reports remaining gaps."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

from layout import PROFILES, REPOSITORY, expected, observe


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*') if p.is_file()}


def run(command, log, timeout=180):
    environment = dict(os.environ, XDG_CONFIG_HOME=str(log.parent / 'settings'))
    if os.environ.get('TMPDIR'):
        environment['JAVA_TOOL_OPTIONS'] = os.environ.get('JAVA_TOOL_OPTIONS', '') + \
            ' -Djava.io.tmpdir="' + os.environ['TMPDIR'] + '"'
    with log.open('w') as stream:
        subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=timeout, env=environment)


def observe_alias(original, sidecar):
    return subprocess.run(['gdb-multiarch', '-nx', '-nh', '-batch', '-ex', 'set auto-load off',
        '-ex', 'set auto-solib-add off', '-ex', 'file ' + json.dumps(str(original)),
        '-ex', 'symbol-file ' + json.dumps(str(sidecar)), '-ex', 'info address peripheral_alias',
        '-ex', 'python a=gdb.parse_and_eval("peripheral_alias"); p=gdb.parse_and_eval("peripheral"); '
        'assert int(a.address)==int(p.address)==0x40000000; '
        'assert int(a["status"]["raw"])==0xa5a5e28d and int(a["counter"])==17; '
        'print("MMIO_ALIAS_VALUES=PASS")'], capture_output=True, text=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--targets', nargs='+', choices=tuple(PROFILES), default=list(PROFILES))
    args = parser.parse_args()
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    ghidra = args.ghidra.resolve(strict=True)
    wrapper = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/support/ghidra-dwarf-forge-headless'
    results = {}
    for name in args.targets:
        reference = args.references.resolve() / name / 'reference.elf'
        reference_hash = digest(reference)
        case = root / name
        case.mkdir()
        project = case / 'project'
        project.mkdir()
        original = case / 'input.elf'
        run([PROFILES[name][1], '--strip-all', str(reference), str(original)], case / 'strip.log')
        original_hash = digest(original)
        main_address = next(line.split()[1] for line in
            subprocess.check_output(['readelf', '-Ws', str(reference)], text=True).splitlines()
            if line.split() and line.split()[-1] == 'main')
        run([str(ghidra / 'support/analyzeHeadless'), str(project), 'Mmio', '-import', str(original),
            '-analysisTimeoutPerFile', '120', '-scriptPath', str(REPOSITORY / 'src/test/integration/ghidra_scripts'),
            '-postScript', 'ApplyMmioFixture.java', main_address], case / 'curation.log')
        curation = (case / 'curation.log').read_text()
        assert 'MMIO_CURATION=PASS' in curation and 'SCRIPT ERROR' not in curation, curation
        saved = snapshot(project)
        (case / 'saved-before.json').write_text(json.dumps(saved, indent=4) + '\n')
        sidecar = case / 'firmware.dbg'
        command = ['bash', str(wrapper), '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
            '--project-name=Mmio', '--program=input.elf', '--input=' + str(original), '--output=' + str(sidecar), '--mmio']
        run(command, case / 'export.log')
        assert 'GhidraDwarfForge symbol export PASS' in (case / 'export.log').read_text()
        after = snapshot(project)
        project_changes = sorted(k for k in saved.keys() | after.keys() if saved.get(k) != after.get(k))
        assert not project_changes, 'saved project changed: ' + repr(project_changes)
        run(['llvm-dwarfdump', '--verify', str(sidecar)], case / 'llvm.log')
        assert 'No errors.' in (case / 'llvm.log').read_text()
        run(['readelf', '-hSW', '-n', '--debug-dump=info,abbrev,aranges,decodedline', str(sidecar)], case / 'readelf.log')
        run(['python3', str(REPOSITORY / 'src/test/integration/check-dwarfdump.py'),
            str(sidecar), str(case / 'dwarfdump.log'), '--original', str(original)], case / 'validator.log')
        values = observe(case, original, 'forge', sidecar, require_qualifiers=False)
        assert values == expected(PROFILES[name][3]), (name, values)
        types = (case / 'forge.log').read_text()
        assert 'volatile word32 counter' in types, 'saved scalar-member volatility omitted'
        alias = observe_alias(original, sidecar)
        (case / 'alias.log').write_text(alias.stdout + alias.stderr)
        gaps = []
        assert alias.returncode == 0 and '0x40000000' in alias.stdout and 'MMIO_ALIAS_VALUES=PASS' in alias.stdout, \
            'secondary global address/value mismatch: ' + alias.stdout + alias.stderr
        profile_path = Path(str(sidecar) + '.mmio.json')
        profile = json.loads(profile_path.read_text())
        assert profile['sidecar_sha256'] == digest(sidecar) and profile['registers'][0]['address'] == '0x40000000'
        alias_type = profile['registers'][0]['views'][0]['type']
        qualifiers = subprocess.run(['gdb-multiarch', '-nx', '-nh', '-batch', '-ex', 'set auto-load off',
            '-ex', 'symbol-file ' + json.dumps(str(sidecar)), '-ex', 'ptype ' + alias_type], capture_output=True, text=True, timeout=30)
        (case / 'profile-type.log').write_text(qualifiers.stdout + qualifiers.stderr)
        assert qualifiers.returncode == 0 and not qualifiers.stderr
        assert 'const' in qualifiers.stdout and 'volatile' in qualifiers.stdout and 'union Register' in qualifiers.stdout, qualifiers.stdout
        outputs = [digest(sidecar), digest(Path(str(sidecar) + '.c')), digest(profile_path)]
        (case / 'first-output-hashes.json').write_text(json.dumps(outputs) + '\n')
        run(command, case / 'repeat.log')
        repeated_outputs = [digest(sidecar), digest(Path(str(sidecar) + '.c')), digest(profile_path)]
        assert outputs == repeated_outputs, (outputs, repeated_outputs)
        repeated = snapshot(project)
        extra_changes = sorted(k for k in after.keys() | repeated.keys() if after.get(k) != repeated.get(k))
        assert not extra_changes, 'repeated export changed project: ' + repr(extra_changes)
        assert digest(original) == original_hash and digest(reference) == reference_hash
        results[name] = {'status': 'INCOMPLETE_MMIO_EXPORT' if gaps else 'PASS_LAYOUT_AND_SAVED_SETTINGS',
            'values': values, 'gaps': gaps, 'inputSha256': original_hash, 'outputsSha256': outputs,
            'inputPreservation': 'PASS', 'projectPreservation': 'FAIL' if project_changes or extra_changes else 'PASS',
            'determinism': 'PASS'}
    (root / 'result.json').write_text(json.dumps({'scope': 'saved Ghidra export/static memory only; no access helper',
        'profiles': results}, indent=4) + '\n')
    for name, result in results.items():
        print(name, result['status'], result['gaps'])


if __name__ == '__main__':
    main()

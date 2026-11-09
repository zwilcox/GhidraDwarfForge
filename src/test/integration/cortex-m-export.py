#!/usr/bin/env python3
"""Export the explicitly curated Cortex-M reference through the installed package."""
import argparse
import hashlib
import json
import os
import runpy
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('reference', type=Path)
    parser.add_argument('--ghidra', required=True, type=Path)
    args = parser.parse_args()
    case = args.reference.resolve(strict=True)
    reference = json.loads((case / 'result.json').read_text())
    assert reference['status'] == 'PASS_COMPILER_CORTEX_M_REFERENCE'
    original = case / 'original.elf'
    assert digest(original) == reference['protectedSha256'][str(original)]
    ghidra = args.ghidra.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    package_before = inventory(module)
    root = Path(tempfile.mkdtemp(prefix='export.', dir=case))
    print('cortex-m-export-results=' + str(root), flush=True)
    project = root / 'project'
    project.mkdir()
    headless = ghidra / 'support/analyzeHeadless'
    commands = []

    def run(label, argv):
        argv = list(map(str, argv))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as output:
            subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT, check=True, timeout=240,
                env=dict(os.environ, XDG_CONFIG_HOME=settings))
        return (root / (label + '.log')).read_text()

    # Reproducible package timestamps can leave Ghidra's previous compiled
    # scripts looking newer than replacement sources. Use per-run settings in
    # the guarded temporary root; share them within this run and remove on exit.
    with tempfile.TemporaryDirectory(prefix='cortex-settings.') as settings:
        imported = run('import', [headless, project, 'CortexM', '-import', original,
            '-processor', 'ARM:LE:32:Cortex', '-cspec', 'default', '-analysisTimeoutPerFile', '120',
            '-scriptPath', HERE / 'ghidra_scripts', '-postScript', 'PrepareCortexM.java',
            case / 'curation.json', root / 'curation-result.json'])
        assert 'cortex-m-curation=PASS functions=8' in imported, imported[-15000:]
        assert 'REPORT SCRIPT ERROR' not in imported and 'Script error' not in imported
        saved = inventory(project)
        (root / 'project-before.json').write_text(json.dumps(saved, indent=4) + '\n')
        sidecar = root / 'firmware.dbg'
        previous = None
        reports = []
        for phase in ('first', 'repeat'):
            # Headless -readOnly still opens a writable project container and rotates
            # its idata backups. The host script opens a genuinely read-only view.
            host = root / (phase + '-host')
            host.mkdir()
            transcript = run(phase, [headless, host, 'Harness', '-noanalysis',
                '-scriptPath', HERE / 'ghidra_scripts', '-postScript', 'ExportCortexMReadOnly.java',
                project, original, sidecar, module])
            assert 'cortex-m-read-only-export=PASS' in transcript
            assert 'GhidraDwarfForge symbol export PASS' in transcript, transcript[-15000:]
            report, = [json.JSONDecoder().raw_decode(line.split('GhidraDwarfForge report: ', 1)[1])[0]
                for line in transcript.splitlines() if 'GhidraDwarfForge report: {' in line]
            assert report['failure'] is None and not report['failedFunctions']
            assert report['counts']['functionsExported'] == 8
            assert report['coverage']['profile'] == {'languageId': 'ARM:LE:32:Cortex', 'compilerSpecId': 'default'}
            (root / (phase + '-report.json')).write_text(json.dumps(report, indent=4) + '\n')
            reports.append(report)
            hashes = [digest(sidecar), digest(Path(str(sidecar) + '.c'))]
            assert previous is None or hashes == previous, 'nondeterministic Cortex-M export'
            previous = hashes
            after = inventory(project)
            changes = {name: {'before': saved.get(name), 'after': after.get(name)}
                for name in saved.keys() | after.keys() if saved.get(name) != after.get(name)}
            (root / (phase + '-project-preservation.json')).write_text(json.dumps(changes, indent=4) + '\n')
            assert not changes, 'export changed saved Ghidra program'
            assert digest(original) == reference['protectedSha256'][str(original)]
        host = root / 'controls-host'
        host.mkdir()
        controlled = run('controls', [headless, host, 'Harness', '-noanalysis',
            '-scriptPath', HERE / 'ghidra_scripts', '-postScript', 'ExportCortexMReadOnly.java',
            project, original, sidecar, module, 'controls'])
        assert 'cortex-m-failure-controls=PASS cases=8 recovery=1' in controlled, controlled[-15000:]
        assert 'cortex-m-read-only-export=PASS' in controlled
        assert inventory(project) == saved, 'failure controls changed saved project'
        assert [digest(sidecar), digest(Path(str(sidecar) + '.c'))] == previous
        artifact_checks = runpy.run_path(str(HERE / 'cortex-m-artifact.py'))
        _, _, addresses = artifact_checks['inspect'](case, sidecar, root / 'addresses')
        run('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', sidecar])
        assert 'No errors.' in run('llvm', ['llvm-dwarfdump', '--verify', sidecar])
        run('pinned', ['python3', HERE / 'check-dwarfdump.py', sidecar, root / 'pinned.txt', '--original', original])
        run('runtime', ['python3', HERE / 'cortex-m-runtime.py', case, '--symbols', sidecar,
            '--output', root / 'runtime', '--variant', 'forge'])
        observed = json.loads((root / 'runtime/forge-gdb.json').read_text())
        assert observed['status'] == 'PASS'
        assert [digest(sidecar), digest(Path(str(sidecar) + '.c'))] == previous
        assert digest(original) == reference['protectedSha256'][str(original)]
        assert inventory(module) == package_before, 'export modified installed package'
        result = {'status': 'PASS_CURATED_CORTEX_EXPORT_RUNTIME', 'reference': str(case),
            'originalSha256': digest(original), 'sidecarSha256': previous[0], 'sourceSha256': previous[1],
            'counts': reports[0]['counts'], 'packageSha256': package_before,
            'addressChecks': addresses,
            'exceptionFrameCounts': [len(row['frames']) for row in observed['exceptions']],
            'failureControls': {'contextRejections': 2, 'cancellations': 6, 'deterministicRecovery': True},
            'scope': 'Selected Cortex-M3 runtime, structure, profile selection, failure/cancellation and preservation; required hosted lane and independent runtime mutation controls remain pending.'}
        (root / 'result.json').write_text(json.dumps(result, indent=4) + '\n')
        print('cortex-m-export=PASS ' + str(root))


if __name__ == '__main__':
    main()

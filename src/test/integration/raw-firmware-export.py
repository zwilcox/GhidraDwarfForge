#!/usr/bin/env python3
"""Export a raw Cortex-M fixture through the installed production exporter."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {str(p.relative_to(root)): digest(p) for p in root.rglob('*') if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--objcopy', default='arm-none-eabi-objcopy')
    parser.add_argument('--separate-ram-input', action='store_true')
    parser.add_argument('--prepared-inputs', type=Path, help='Verified portable reference capsule; no target compiler needed')
    parser.add_argument('--producer-only', action='store_true', help='Defer structural/runtime validation to transported consumer')
    args = parser.parse_args()
    case = args.case.resolve(strict=True)
    ghidra = args.ghidra.resolve(strict=True)
    root = args.results.resolve()
    root.mkdir(parents=True, exist_ok=False)
    print('raw-firmware-results=' + str(root), flush=True)
    original = root / 'firmware.bin'
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    package = inventory(module)
    commands = []
    prepared = None
    if args.prepared_inputs:
        prepared = args.prepared_inputs.resolve(strict=True)
        portable = runpy.run_path(str(HERE / 'raw-firmware-portable.py'))
        portable['verify'](prepared)
        assert case == prepared / 'reference'
        assert args.separate_ram_input, 'portable case binds two inputs'
    with tempfile.TemporaryDirectory(prefix='raw-firmware-settings.') as settings:
        environment = dict(os.environ, XDG_CONFIG_HOME=settings)
        if os.environ.get('TMPDIR'):
            environment['JAVA_TOOL_OPTIONS'] = (os.environ.get('JAVA_TOOL_OPTIONS', '') +
                ' -Djava.io.tmpdir="' + os.environ['TMPDIR'] + '"')

        def run(label, argv):
            command = list(map(str, argv))
            commands.append({'label': label, 'argv': command})
            (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
            with (root / (label + '.log')).open('w') as output:
                subprocess.run(command, stdout=output, stderr=subprocess.STDOUT,
                    check=True, timeout=240, env=environment)
            return (root / (label + '.log')).read_text()

        if prepared:
            shutil.copyfile(prepared / 'firmware.bin', original)
        else:
            run('raw', [args.objcopy, '-O', 'binary', case / 'reference.elf', original])
        before = digest(original)
        extra_inputs = {}
        input_selection = []
        map_selection = []
        if args.separate_ram_input:
            ram = root / 'ram-init.bin'
            if prepared:
                shutil.copyfile(prepared / 'ram-init.bin', ram)
            else:
                run('ram-input', [args.objcopy, '-O', 'binary', '-j', '.data', case / 'reference.elf', ram])
            selection = root / 'inputs.json'
            selection.write_text(json.dumps({'schema': 1, 'inputs': [
                {'id': 'input', 'fileBytesIndex': 0, 'path': original.name},
                {'id': 'ram', 'fileBytesIndex': 1, 'path': ram.name}]}, indent=4) + '\n')
            input_selection = [selection]
            map_selection = [ram]
            extra_inputs = {path: digest(path) for path in (ram, selection)}
        project = root / 'project'
        project.mkdir()
        headless = ghidra / ('support/analyzeHeadless.bat' if os.name == 'nt' else 'support/analyzeHeadless')
        imported = run('import', [headless, project, 'CortexM', '-import', original,
            '-loader', 'BinaryLoader', '-loader-baseAddr', '0', '-processor', 'ARM:LE:32:Cortex',
            '-cspec', 'default', '-analysisTimeoutPerFile', '120', '-scriptPath', HERE / 'ghidra_scripts',
            '-preScript', 'MapRawCortexM.java', case / 'curation.json', case / 'labels.json', *map_selection,
            '-postScript', 'PrepareCortexM.java', case / 'curation.json', root / 'curation.json'])
        assert 'raw-cortex-map=PASS' in imported and 'cortex-m-curation=PASS functions=8' in imported
        assert 'REPORT SCRIPT ERROR' not in imported and 'Script error' not in imported
        saved = inventory(project)
        (root / 'project-before.json').write_text(json.dumps(saved, indent=4) + '\n')
        sidecar = root / 'firmware.dbg'
        source = root / 'firmware.dbg.c'
        manifest = root / 'firmware.dbg.firmware.json'
        previous = None
        for phase in ('first', 'repeat'):
            if os.name == 'nt':
                command = ['pwsh', '-NoLogo', '-NoProfile', '-File',
                    module / 'support/ghidra-dwarf-forge-headless.ps1',
                    '-GhidraDirectory', ghidra, '-ProjectDirectory', project,
                    '-ProjectName', 'CortexM', '-Program', '/' + original.name,
                    '-RawFirmware', 'cortex-m3', '-Input', original, '-Output', sidecar,
                    *(['-FirmwareInputs', selection] if input_selection else [])]
            else:
                command = [module / 'support/ghidra-dwarf-forge-headless',
                '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
                '--project-name=CortexM', '--program=/' + original.name,
                '--raw-firmware=cortex-m3', '--input=' + str(original), '--output=' + str(sidecar),
                *(['--firmware-inputs=' + str(selection)] if input_selection else [])]
            text = run(phase, command)
            assert 'GhidraDwarfForge symbol export PASS' in text
            assert 'REPORT SCRIPT ERROR' not in text and 'Script error' not in text
            assert inventory(project) == saved, 'raw export changed saved project'
            assert digest(original) == before, 'raw export changed original input'
            hashes = [digest(path) for path in (sidecar, source, manifest)]
            assert previous is None or hashes == previous, 'nondeterministic firmware generation'
            previous = hashes
            record = json.loads(manifest.read_text())
            assert record['kind'] == 'synthetic-firmware-debug-container'
            assert record['inputs'][0]['sha256'] == before
            assert record['artifacts']['sidecarSha256'] == hashes[0]
            assert record['artifacts']['sourceSha256'] == hashes[1]
            assert len(record['regions']) == 3 and record['analysis']['savedFileId']
            assert len(record['inputs']) == (2 if args.separate_ram_input else 1)
            if args.separate_ram_input:
                assert record['inputs'][1]['id'] == 'ram' and record['inputs'][1]['sha256'] == extra_inputs[ram]
                assert record['regions'][1]['fileSpans'] == [
                    {'regionOffset': 0, 'size': ram.stat().st_size, 'inputId': 'ram', 'fileOffset': 0}]
        host = root / 'controls-host'
        host.mkdir()
        text = run('controls', [headless, host, 'Harness', '-noanalysis',
            '-scriptPath', HERE / 'ghidra_scripts', '-postScript', 'ExportCortexMReadOnly.java',
            project, original, sidecar, module, 'raw-controls', *input_selection])
        failure_controls = 21 if args.separate_ram_input else 20
        assert 'raw-firmware-failure-controls=PASS cases=' + str(failure_controls) in text, text[-3000:]
        assert digest(original) == before and inventory(project) == saved and inventory(module) == package
        assert all(digest(path) == expected for path, expected in extra_inputs.items())
        if args.producer_only:
            assert prepared and args.separate_ram_input, 'transport requires the verified two-input capsule'
            transport = root / 'transport'
            shutil.copytree(prepared, transport)
            (transport / 'SHA256.json').unlink()
            for path in (sidecar, source, manifest, selection):
                shutil.copyfile(path, transport / path.name)
            producer = {'status': 'PASS_RAW_FIRMWARE_PRODUCER', 'host': 'Windows' if os.name == 'nt' else 'Linux',
                'failureControls': failure_controls, 'inputFiles': 2, 'sourceOrigin': str(source),
                'inputSha256': before, 'outputsSha256': previous, 'packagedNatives': True,
                'packageSha256': package, 'savedProjectSha256': saved}
            (transport / 'producer.json').write_text(json.dumps(producer, indent=4) + '\n')
            portable['seal'](transport)
            (root / 'result.json').write_text(json.dumps(producer, indent=4) + '\n')
            print('raw-firmware-producer=PASS ' + str(root))
            return
        for label, command in [
                ('readelf', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', sidecar]),
                ('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
                ('dwarfdump', [os.environ.get('DWARFDUMP', 'dwarfdump'), sidecar])]:
            text = run(label, command)
            assert 'warning:' not in text.lower() and 'error:' not in text.lower(), text
        runtime = runpy.run_path(str(HERE / 'cortex-m-runtime.py'))
        artifact = runpy.run_path(str(HERE / 'cortex-m-artifact.py'))
        _, _, addresses = artifact['inspect'](case, sidecar, root / 'addresses', record)
        observed = runtime['debugger'](case, sidecar, root, 'forge', source=source, raw_input=original)
        assert digest(original) == before and inventory(project) == saved and inventory(module) == package
        assert all(digest(path) == expected for path, expected in extra_inputs.items())
        (root / 'result.json').write_text(json.dumps({'status': 'PASS_RAW_FIRMWARE_EXPORT_RUNTIME',
            'inputSha256': before, 'outputsSha256': previous, 'runtime': observed, 'addresses': addresses,
            'failureControls': failure_controls, 'inputFiles': len(record['inputs']),
            'scope': 'one raw runtime layout per invocation'}, indent=4) + '\n')
    print('raw-firmware-export=PASS ' + str(root))


if __name__ == '__main__':
    main()

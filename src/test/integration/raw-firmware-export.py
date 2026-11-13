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
    parser.add_argument('--mmio', action='store_true', help='Include an explicitly selected uninitialized peripheral view')
    args = parser.parse_args()
    if args.mmio and (args.producer_only or args.separate_ram_input):
        parser.error('MMIO fixture controls currently use the single-input Linux runtime case')
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
            '-postScript', 'PrepareCortexM.java', case / 'curation.json', root / 'curation.json',
            *(['-postScript', 'PrepareRawMmio.java', root / 'analyst-mmio.json'] if args.mmio else [])])
        assert 'raw-cortex-map=PASS' in imported and 'cortex-m-curation=PASS functions=8' in imported
        if args.mmio:
            assert 'raw-mmio-selection=PASS' in imported
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
                    *(['-Mmio'] if args.mmio else []),
                    *(['-FirmwareInputs', selection] if input_selection else [])]
            else:
                command = [module / 'support/ghidra-dwarf-forge-headless',
                '--ghidra-dir=' + str(ghidra), '--project-dir=' + str(project),
                '--project-name=CortexM', '--program=/' + original.name,
                '--raw-firmware=cortex-m3', '--input=' + str(original), '--output=' + str(sidecar),
                *(['--mmio'] if args.mmio else []),
                *(['--firmware-inputs=' + str(selection)] if input_selection else [])]
            text = run(phase, command)
            assert 'GhidraDwarfForge symbol export PASS' in text
            assert 'REPORT SCRIPT ERROR' not in text and 'Script error' not in text
            assert inventory(project) == saved, 'raw export changed saved project'
            assert digest(original) == before, 'raw export changed original input'
            outputs = [sidecar, source, manifest]
            if args.mmio:
                outputs.append(Path(str(sidecar) + '.mmio.json'))
            hashes = [digest(path) for path in outputs]
            assert previous is None or hashes == previous, 'nondeterministic firmware generation'
            previous = hashes
            record = json.loads(manifest.read_text())
            assert record['kind'] == 'synthetic-firmware-debug-container'
            assert record['inputs'][0]['sha256'] == before
            assert record['artifacts']['sidecarSha256'] == hashes[0]
            assert record['artifacts']['sourceSha256'] == hashes[1]
            assert len(record['regions']) == (4 if args.mmio else 3) and record['analysis']['savedFileId']
            if args.mmio:
                peripheral, = [r for r in record['regions'] if r['address'] == '0x40001000']
                assert peripheral['size'] == 4 and not peripheral['fileSpans']
                selected = json.loads(outputs[-1].read_text())
                assert selected['sidecar_sha256'] == hashes[0]
                assert selected['registers'][0]['read_effect'] == 'unknown'
            assert len(record['inputs']) == (2 if args.separate_ram_input else 1)
            if args.separate_ram_input:
                assert record['inputs'][1]['id'] == 'ram' and record['inputs'][1]['sha256'] == extra_inputs[ram]
                assert record['regions'][1]['fileSpans'] == [
                    {'regionOffset': 0, 'size': ram.stat().st_size, 'inputId': 'ram', 'fileOffset': 0}]
        if args.mmio:
            import sys
            text = run('controls', [sys.executable, '-B', HERE.parent / 'research/mmio-access/failures.py',
                '--ghidra', ghidra, '--project', project, '--original', original, '--sidecar', sidecar,
                '--results', root / 'mmio-failures', '--raw-firmware'])
            failure_controls = 22
            assert 'mmio-failure-controls=PASS' in text
            # No target connected: the unknown policy must reject before any read.
            text = run('mmio-policy', ['gdb-multiarch', '-nx', '-nh', '-batch',
                '-ex', 'set auto-load off', '-ex', 'file ' + json.dumps(str(sidecar)),
                '-ex', 'source ' + str(module / 'support/mmio/forge_mmio.py'),
                '-ex', 'forge-mmio load ' + json.dumps(str(outputs[-1])) + ' ' + json.dumps(str(sidecar)),
                '-ex', 'ptype analyst_status', '-ex', 'ptype struct RawStatusBits',
                '-ex', 'info address analyst_status',
                '-ex', 'forge-mmio snapshot status unproved-device',
                '-ex', 'echo MMIO_POLICY_CONTROL_FINISHED\\n'])
            assert text.count('register read policy prohibits access') == 1 and '0x40001000' in text
            assert 'MMIO profile loaded; no device reads performed.' in text
            assert 'MMIO_POLICY_CONTROL_FINISHED' in text and 'raw;' in text and 'mode : 3;' in text
            assert '"address":' not in text and 'Traceback' not in text
        else:
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
            'mmio': args.mmio,
            'scope': 'one raw runtime layout per invocation'}, indent=4) + '\n')
    print('raw-firmware-export=PASS ' + str(root))


if __name__ == '__main__':
    main()

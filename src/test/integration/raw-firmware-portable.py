#!/usr/bin/env python3
"""Transport a bounded compiler fixture, then independently validate a host export."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import runpy
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
REFERENCE_FILES = ('reference.elf', 'original.elf', 'curation.json', 'labels.json',
    'disassembly.log', 'profile.json', 'result.json', 'compiler-gdb.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    assert not any(p.is_symlink() for p in root.rglob('*')), 'unexpected transport symlink'
    return {p.relative_to(root).as_posix(): digest(p) for p in root.rglob('*')
        if p.is_file() and p != root / 'SHA256.json'}


def seal(root):
    (root / 'SHA256.json').write_text(json.dumps(inventory(root), indent=4, sort_keys=True) + '\n')


def verify(root):
    expected = json.loads((root / 'SHA256.json').read_text())
    assert expected and inventory(root) == expected, 'transported files differ from producer receipt'
    return expected


def pack(case, exported, output):
    result = json.loads((exported / 'result.json').read_text())
    assert result['status'] == 'PASS_RAW_FIRMWARE_EXPORT_RUNTIME' and result['inputFiles'] == 2
    assert result['inputSha256'] == digest(exported / 'firmware.bin')
    assert json.loads((case / 'result.json').read_text())['status'] == 'PASS_COMPILER_CORTEX_M_REFERENCE'
    labels = json.loads((case / 'labels.json').read_text())
    assert labels['_sdata'] == 0x20001000
    output.mkdir(parents=True, exist_ok=False)
    reference = output / 'reference'
    reference.mkdir()
    for name in REFERENCE_FILES:
        shutil.copyfile(case / name, reference / name)
    for name in ('firmware.bin', 'ram-init.bin'):
        shutil.copyfile(exported / name, output / name)
    seal(output)


def consume(incoming, output, host, dwarfdump):
    before = verify(incoming)
    producer = json.loads((incoming / 'producer.json').read_text())
    assert producer['status'] == 'PASS_RAW_FIRMWARE_PRODUCER' and producer['host'] == host
    assert producer['packagedNatives'] and producer['failureControls'] == 21 and producer['inputFiles'] == 2
    assert producer['inputSha256'] == before['firmware.bin']
    assert producer['outputsSha256'] == [before[name] for name in
        ('firmware.dbg', 'firmware.dbg.c', 'firmware.dbg.firmware.json')]
    output.mkdir(parents=True, exist_ok=False)
    transported = output / 'transported'
    shutil.copytree(incoming, transported)
    assert verify(transported) == before
    case, sidecar = transported / 'reference', transported / 'firmware.dbg'
    source = transported / 'firmware.dbg.c'
    manifest = json.loads((transported / 'firmware.dbg.firmware.json').read_text())
    assert manifest['artifacts']['sidecarSha256'] == before['firmware.dbg']
    assert manifest['artifacts']['sourceSha256'] == before['firmware.dbg.c']
    assert [row['sha256'] for row in manifest['inputs']] == [before['firmware.bin'], before['ram-init.bin']]
    for label, argv in (
            ('readelf', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline', sidecar]),
            ('llvm', ['llvm-dwarfdump', '--verify', sidecar]),
            ('dwarfdump', [dwarfdump, sidecar])):
        completed = subprocess.run(list(map(str, argv)), capture_output=True, text=True, timeout=90)
        text = completed.stdout + completed.stderr
        (output / (label + '.log')).write_text(text)
        assert completed.returncode == 0 and 'warning:' not in text.lower() and 'error:' not in text.lower(), text
    artifact = runpy.run_path(str(HERE / 'cortex-m-artifact.py'))
    _, _, addresses = artifact['inspect'](case, sidecar, output / 'addresses', manifest)
    runtime = runpy.run_path(str(HERE / 'cortex-m-runtime.py'))
    origin = (PureWindowsPath(producer['sourceOrigin']).parent.as_posix() if host == 'Windows'
        else str(Path(producer['sourceOrigin']).parent))
    observed = runtime['debugger'](case, sidecar, output, 'forge', source=source,
        raw_input=transported / 'firmware.bin', source_origin=origin)
    assert verify(incoming) == before and verify(transported) == before
    (output / 'result.json').write_text(json.dumps({'status': 'PASS_RAW_FIRMWARE_TRANSPORT',
        'producerHost': host, 'inputSha256': before['firmware.bin'],
        'sidecarSha256': before['firmware.dbg'], 'addresses': addresses, 'runtime': observed,
        'sourceSubstitution': {'from': origin, 'to': str(source.parent)}}, indent=4) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    packer = sub.add_parser('pack')
    packer.add_argument('--case', type=Path, required=True)
    packer.add_argument('--export', dest='exported', type=Path, required=True)
    packer.add_argument('--output', type=Path, required=True)
    consumer = sub.add_parser('consume')
    consumer.add_argument('--incoming', type=Path, required=True)
    consumer.add_argument('--output', type=Path, required=True)
    consumer.add_argument('--producer-host', choices=('Windows', 'Linux'), required=True)
    consumer.add_argument('--dwarfdump', default=os.environ.get('DWARFDUMP', 'dwarfdump'))
    args = parser.parse_args()
    if args.mode == 'pack':
        pack(args.case.resolve(strict=True), args.exported.resolve(strict=True), args.output.resolve())
    else:
        consume(args.incoming.resolve(strict=True), args.output.resolve(), args.producer_host, args.dwarfdump)
    print('raw-firmware-portable-' + args.mode + '=PASS')


if __name__ == '__main__':
    main()

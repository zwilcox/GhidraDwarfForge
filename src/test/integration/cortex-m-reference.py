#!/usr/bin/env python3
"""Compile and debug the standalone Cortex-M3 ELF before testing Forge output."""
import argparse
import hashlib
import json
import runpy
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / 'fixtures'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, required=True)
    parser.add_argument('--ram-origin', choices=('0x20000000', '0x20001000'), default='0x20000000')
    args = parser.parse_args()
    args.results.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='cortex-m3.', dir=args.results.resolve()))
    print('cortex-m-reference-results=' + str(root), flush=True)
    sources = [FIXTURES / name for name in ('cortex-m-profile.c', 'cortex-m-start.S', 'cortex-m.ld')]
    protected = {str(p): digest(p) for p in sources}
    linker = sources[2]
    if args.ram_origin != '0x20000000':
        # Move only data/RAM; retain flash, reset and stack limits. This catches a
        # guessed single load-bias transformation applied to disjoint memory banks.
        text = linker.read_text()
        original_region = 'ORIGIN = 0x20000000, LENGTH = 64K'
        assert text.count(original_region) == 1
        linker = root / 'shifted-ram.ld'
        linker.write_text(text.replace(original_region, 'ORIGIN = 0x20001000, LENGTH = 60K'))
        protected[str(linker)] = digest(linker)
    commands = []

    def run(label, argv, **kwargs):
        argv = list(map(str, argv))
        commands.append({'label': label, 'argv': argv})
        (root / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (root / (label + '.log')).open('w') as output:
            subprocess.run(argv, stdout=output, stderr=subprocess.STDOUT,
                check=True, timeout=90, **kwargs)
        return (root / (label + '.log')).read_text()

    cc = shutil.which('arm-none-eabi-gcc')
    assert cc, 'arm-none-eabi-gcc is required on PATH'
    reference, original = root / 'reference.elf', root / 'original.elf'
    versions = {tool: run(tool + '-version', [tool, '--version']).splitlines()[0]
        for tool in ('arm-none-eabi-gcc', 'arm-none-eabi-objcopy', 'qemu-system-arm', 'gdb-multiarch')}
    run('compile', [cc, '-mcpu=cortex-m3', '-mthumb', '-mfloat-abi=soft',
        '-O1', '-g', '-gdwarf-5', '-ffreestanding', '-fno-builtin', '-fno-common',
        '-fno-omit-frame-pointer', '-fno-optimize-sibling-calls', '-Wall', '-Wextra', '-Werror',
        '-nostdlib', '-static', '-Wl,--build-id=sha1', '-Wl,-z,noexecstack', '-Wl,-T,' + str(linker),
        sources[1], sources[0], '-o', reference])
    run('strip', ['arm-none-eabi-objcopy', '--strip-all', reference, original])
    protected.update({str(p): digest(p) for p in (reference, original)})
    attributes = run('attributes', ['arm-none-eabi-readelf', '-hAlSW', reference])
    assert 'Tag_CPU_arch: v7' in attributes and 'Tag_CPU_arch_profile: Microcontroller' in attributes
    assert 'Tag_THUMB_ISA_use: Thumb-2' in attributes
    assert 'Tag_ARM_ISA_use: Yes' not in attributes
    assert 'Tag_FP_arch:' not in attributes and 'Tag_ABI_VFP_args: VFP registers' not in attributes
    symbols = run('symbols', ['arm-none-eabi-nm', '-n', reference])
    labels = {parts[2]: int(parts[0], 16) for line in symbols.splitlines()
        if len(parts := line.split()) == 3}
    assert labels['cortex_vectors'] == 0 and labels['_stack_top'] == 0x20010000
    assert labels['_psp_top'] == 0x2000f000
    assert labels['_sidata'] < 0x40000 and labels['_sdata'] == int(args.ram_origin, 16)
    assert labels['_sdata'] < labels['_edata'] <= labels['_sbss'] < labels['_ebss']
    run('disassembly', ['arm-none-eabi-objdump', '-d', reference])
    symbol_table = run('symbol-table', ['arm-none-eabi-readelf', '-sW', reference])
    records = []
    for line in symbol_table.splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[0].rstrip(':').isdigit():
            records.append({'address': int(fields[1], 16), 'size': int(fields[2]),
                'type': fields[3], 'section': fields[6], 'name': fields[7]})
    mappings = sorted((r for r in records if r['name'] in ('$t', '$d')),
        key=lambda r: (r['section'], r['address']))
    functions = []
    for symbol in sorted((r for r in records if r['type'] == 'FUNC'), key=lambda r: r['address']):
        assert symbol['address'] & 1, 'compiler function is not tagged Thumb'
        start = symbol['address'] & ~1
        end = start + symbol['size']
        regions = [m for m in mappings if m['section'] == symbol['section']]
        ranges = []
        for index, mapping in enumerate(regions):
            limit = regions[index + 1]['address'] if index + 1 < len(regions) else end
            low, high = max(start, mapping['address']), min(end, limit)
            if mapping['name'] == '$t' and low < high:
                ranges.append([low, high])
        assert len(ranges) == 1 and ranges[0][0] == start
        functions.append({'name': symbol['name'], 'entry': start, 'ranges': ranges})
    assert len(functions) == 8
    text_section, = [r['section'] for r in records if r['type'] == 'SECTION' and r['name'] == '.text']
    text_mappings = [m for m in mappings if m['section'] == text_section]
    text_end = max((r['address'] & ~1) + r['size'] for r in records if r['type'] == 'FUNC')
    data_ranges = [[m['address'], text_mappings[i + 1]['address'] if i + 1 < len(text_mappings) else text_end]
        for i, m in enumerate(text_mappings) if m['name'] == '$d']
    manifest = {'functions': functions, 'literalPools': data_ranges,
        'objects': [r for r in records if r['type'] == 'OBJECT'], 'labels': labels}
    (root / 'curation.json').write_text(json.dumps(manifest, indent=4) + '\n')
    run('llvm', ['llvm-dwarfdump', '--verify', reference])
    (root / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    (root / 'profile.json').write_text(json.dumps({'core': 'Cortex-M3', 'isa': 'ARMv7-M',
        'board': 'lm3s6965evb', 'abi': 'AAPCS32 base PCS', 'byteOrder': 'little',
        'ramOrigin': args.ram_origin, 'versions': versions, 'inputSha256': protected[str(original)]}, indent=4) + '\n')
    runtime = runpy.run_path(str(HERE / 'cortex-m-runtime.py'))
    observed = runtime['debugger'](root, reference, root, 'compiler')
    assert observed['status'] == 'PASS' and len(observed['exceptions']) == 2
    assert all(digest(Path(path)) == before for path, before in protected.items())
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_COMPILER_CORTEX_M_REFERENCE',
        'profile': 'Cortex-M3/lm3s6965evb/base-PCS', 'protectedSha256': protected,
        'versions': versions, 'scope': 'Compiler reference only; Forge export remains unverified.'}, indent=4) + '\n')
    print('cortex-m-reference=PASS ' + str(root))


if __name__ == '__main__':
    main()

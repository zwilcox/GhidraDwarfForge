#!/usr/bin/env python3
"""Independent frame decoding, ELF validation and runtime encoder comparisons."""

import argparse
import copy
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys
import zlib


ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "src/test/integration"
metadata = runpy.run_path(str(SCRIPTS / "matched-elf-prefix.py"))["metadata"]


def run(argv, log, env=None):
    argv = list(map(str, argv))
    Path(str(log) + ".command.json").write_text(json.dumps(argv) + "\n")
    with log.open("wb") as stream:
        result = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                                env={**os.environ, "LC_ALL": "C", **(env or {})}, timeout=120)
    assert result.returncode == 0, (result.returncode, str(log))
    return log.read_text()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode(data, width, order):
    """Consumer implementation: reconstruct rows, including CIE initial state."""
    offset = 0
    cies = {}
    frames = []

    def integer(count):
        nonlocal offset
        assert count <= len(data) - offset
        value = int.from_bytes(data[offset:offset + count], order)
        offset += count
        return value

    def leb(signed=False):
        nonlocal offset
        value = shift = 0
        for unused in range(10):
            byte = integer(1)
            value |= (byte & 127) << shift
            shift += 7
            if byte < 128:
                return value - (1 << shift) if signed and byte & 64 else value
        raise AssertionError("unbounded LEB128")

    def instructions(end, initial, address, frame_end):
        state = copy.deepcopy(initial)
        rows = []
        while offset < end:
            opcode = integer(1)
            if opcode == 0:
                continue
            if opcode in (1, 4):
                assert address is not None and state["cfa"] is not None
                rows.append({"address": address, **copy.deepcopy(state)})
                next_address = integer(width) if opcode == 1 else address + integer(4)
                assert address < next_address < frame_end
                address = next_address
            elif opcode == 0x12:
                state["cfa"] = [leb(), leb(True)]
            elif opcode in (7, 8):
                state["rules"][leb()] = ["u" if opcode == 7 else "s"]
            elif opcode in (9, 0x11, 0x15):
                register = leb()
                state["rules"][register] = [{9: "r", 0x11: "m", 0x15: "v"}[opcode], leb(opcode != 9)]
            else:
                raise AssertionError(("unexpected frame opcode", opcode))
        assert offset == end
        if address is not None:
            assert state["cfa"] is not None
            rows.append({"address": address, **state})
        return state, rows

    while offset < len(data):
        start = offset
        length = integer(4)
        end = offset + length
        assert start % width == end % width == 0 and end <= len(data) and 0 < length < 0xfffffff0
        pointer = integer(4)
        if pointer == 0xffffffff:
            assert integer(1) == 4 and integer(1) == 0
            assert integer(1) == width and integer(1) == 0
            assert leb() == leb(True) == 1
            return_register = leb()
            initial, rows = instructions(end, {"cfa": None, "rules": {}}, None, None)
            assert not rows and return_register in initial["rules"]
            cies[start] = (return_register, initial)
        else:
            assert pointer in cies
            address, size = integer(width), integer(width)
            assert size > 0 and address + size <= 1 << (8 * width)
            return_register, initial = cies[pointer]
            unused, rows = instructions(end, initial, address, address + size)
            frames.append({"address": address, "size": size, "rows": rows})
    return frames


def write_plan(path, width, order, return_register, registers, frames):
    lines = [f'{width} {order} {return_register} ' + ','.join(map(str, registers))]
    for frame in frames:
        lines.append(f'frame {frame["address"]:x} {frame["size"]:x}')
        for row in frame["rows"]:
            rules = ','.join(str(reg) + ':' + ':'.join(map(str, row['rules'][reg])) for reg in registers)
            lines.append(f'row {row["address"]:x} {row["cfa"][0]} {row["cfa"][1]} {rules}')
    path.write_text('\n'.join(lines) + '\n')


def layout_fixture(path, width, order, text_size=0x80):
    """Small source-built ELF container, not a runnable processor fixture."""
    wide = width == 8
    endian = '<' if order == 'little' else '>'
    header_size, section_size = (64, 64) if wide else (52, 40)
    names = b'\0.text\0.shstrtab\0'
    table = (header_size + len(names) + 7) & ~7
    result = bytearray(table + 3 * section_size)
    result[:16] = b'\x7fELF' + bytes([2 if wide else 1, 1 if order == 'little' else 2, 1]) + bytes(9)
    machine = {(4, 'little'): 3, (4, 'big'): 8, (8, 'little'): 62, (8, 'big'): 21}[width, order]
    struct.pack_into(endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), result, 16,
                     2, machine, 1, 0x1000, 0, table, 0, header_size, 0, 0, section_size, 3, 2)
    result[header_size:header_size + len(names)] = names
    form = endian + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII')
    struct.pack_into(form, result, table + section_size, 1, 8, 6, 0x1000, 0, text_size, 0, 0, width, 0)
    struct.pack_into(form, result, table + section_size * 2, 7, 3, 0, 0, header_size, len(names), 0, 0, 1, 0)
    path.write_bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('classes', type=Path, help='Gradle output/classes/java directory')
    parser.add_argument('output', type=Path)
    parser.add_argument('--java', default='java')
    parser.add_argument('--dwarfdump', required=True)
    parser.add_argument('--target', choices=('x86_64', 'aarch64', 'all'), default='all',
                        help='Runtime target; all width/endian structural cases always run')
    args = parser.parse_args()
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    classes = args.classes.resolve()
    classpath = os.pathsep.join(str(classes / name) for name in ('main', 'test'))
    reports = []

    def encode(case, original, width, order, return_register, registers, frames):
        plan = case / 'plan.txt'
        write_plan(plan, width, order, return_register, registers, frames)
        before = digest(original)
        plain = None
        for mode in ('none', 'zlib'):
            candidate = case / (mode + '.dbg')
            raw = case / (mode + '.frame')
            command = [args.java, '-cp', classpath, 'ghidradwarfforge.unwind.CallFrameEncoderProbe',
                       plan, original, candidate, raw, mode]
            run(command, case / (mode + '-encode.log'))
            encoded = candidate.read_bytes()
            run(command, case / (mode + '-repeat.log'))
            assert encoded == candidate.read_bytes() and digest(original) == before
            assert decode(raw.read_bytes(), width, order) == frames
            if plain is None: plain = raw.read_bytes()
            assert raw.read_bytes() == plain
            section, = [s for s in metadata(candidate)['sections'] if s['name'] == '.debug_frame']
            assert section['alignment'] == width and section['offset'] % width == 0
            payload = candidate.read_bytes()[section['offset']:section['offset'] + section['size']]
            if section['flags'] & 0x800:
                header_size = 24 if width == 8 else 12
                fields = struct.unpack(('<' if order == 'little' else '>') +
                                       ('IIQQ' if width == 8 else 'III'), payload[:header_size])
                assert fields[0] == 1 and fields[-2:] == (len(plain), width)
                assert zlib.decompress(payload[header_size:]) == plain
            else:
                assert payload == plain
            log = run(['readelf', '-h', '-S', '--debug-dump=frames', candidate], case / (mode + '-gnu.log'))
            assert 'warning' not in log.lower() and 'error' not in log.lower()
            run(['llvm-dwarfdump', '--verify', candidate], case / (mode + '-llvm.log'))
            run(['llvm-dwarfdump', '--debug-frame', candidate], case / (mode + '-llvm-frame.log'))
            run([sys.executable, SCRIPTS / 'check-dwarfdump.py', candidate, case / (mode + '-strict.log'),
                 '--tool', args.dwarfdump], case / (mode + '-strict-driver.log'))
        # Prove the external readers inspect CFI rather than only the tiny CU.
        candidate = case / 'none.dbg'
        section, = [s for s in metadata(candidate)['sections'] if s['name'] == '.debug_frame']
        corrupt = bytearray(candidate.read_bytes())
        cie_size = int.from_bytes(plain[:4], order) + 4
        field = section['offset'] + cie_size + 4
        corrupt[field:field + 4] = (0x123456).to_bytes(4, order)
        invalid = case / 'invalid-cie-pointer.dbg'
        invalid.write_bytes(corrupt)
        invalid_raw = bytearray(plain)
        invalid_raw[cie_size + 4:cie_size + 8] = (0x123456).to_bytes(4, order)
        try:
            decode(invalid_raw, width, order)
            raise RuntimeError('oracle accepted unknown CIE')
        except AssertionError:
            pass
        for label, command in [
            ('llvm', ['llvm-dwarfdump', '--debug-frame', invalid]),
            ('strict', [sys.executable, SCRIPTS / 'check-dwarfdump.py', invalid,
                        case / 'invalid-strict.log', '--tool', args.dwarfdump]),
        ]:
            with (case / ('invalid-' + label + '-driver.log')).open('wb') as stream:
                result = subprocess.run(list(map(str, command)), stdout=stream, stderr=subprocess.STDOUT, timeout=60)
            assert result.returncode == 1, (label, result.returncode)
        assert json.loads((case / 'invalid-strict.log.check.json').read_text())['exit_status'] == 0
        return {'directory': str(case), 'inputSha256': before, 'frameSha256': hashlib.sha256(plain).hexdigest()}

    for width in (4, 8):
        for order in ('little', 'big'):
            case = work / f'layout-{width}-{order}'
            case.mkdir()
            original = case / 'original'
            layout_fixture(original, width, order)
            # All five rule forms, positive/negative CFA and saved offsets,
            # and high register IDs are checked without an ABI interpretation.
            registers = [0, 7, 12, 16, 129]
            rows = [
                {'address': 0x1000, 'cfa': [7, 8], 'rules': {0: ['u'], 7: ['v', 0], 12: ['s'], 16: ['m', -8], 129: ['r', 12]}},
                {'address': 0x1010, 'cfa': [12, -129], 'rules': {0: ['s'], 7: ['v', 129], 12: ['m', -256], 16: ['r', 129], 129: ['u']}},
                {'address': 0x1030, 'cfa': [7, 8], 'rules': {0: ['u'], 7: ['v', -129], 12: ['s'], 16: ['m', 256], 129: ['r', 16]}},
            ]
            reports.append(encode(case, original, width, order, 16, registers,
                                  [{'address': 0x1000, 'size': 0x40, 'rows': rows}]))
    for order in ('little', 'big'):
        case = work / ('large-gap-' + order)
        case.mkdir()
        original = case / 'original'
        size = 0x100000080
        layout_fixture(original, 8, order, size)
        rules = {7: ['v', 0], 16: ['m', -8]}
        frames = [{'address': 0x1000, 'size': size, 'rows': [
            {'address': 0x1000, 'cfa': [7, 8], 'rules': rules},
            {'address': 0x100001000, 'cfa': [7, 24], 'rules': rules},
            {'address': 0x100001010, 'cfa': [7, 8], 'rules': rules},
        ]}]
        reports.append(encode(case, original, 8, order, 16, [7, 16], frames))

    targets = ('x86_64', 'aarch64') if args.target == 'all' else (args.target,)
    for target, role in itertools.product(targets, ('exec', 'pie')):
        case = work / (target + '-' + role)
        case.mkdir()
        prefix = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
        source = ROOT / 'src/test/fixtures' / ('cfi-encoder-' + target + '.S')
        reference, original = case / 'reference', case / 'original'
        flags = ['-static', '-no-pie'] if role == 'exec' else ['-fPIE', '-static-pie']
        run([prefix + 'gcc', '-nostdlib', *flags, '-Wl,--build-id=none', source, '-o', reference], case / 'build.log')
        run([prefix + 'objcopy', '--strip-debug', reference, original], case / 'strip.log')
        symbols = {}
        for line in run(['readelf', '-Ws', reference], case / 'symbols.log').splitlines():
            fields = line.split()
            if len(fields) == 8 and fields[7] in ('cf_checkpoint', 'cf_recurse', '_start', 'cf_saved', 'cf_restored'):
                symbols[fields[7]] = (int(fields[1], 16), int(fields[2]))
        assert len(symbols) == 5
        if target == 'x86_64':
            sp, ra, witness, count, entry_offset = 7, 16, 12, 17, 8
        else:
            sp, ra, witness, count, entry_offset = 31, 30, 19, 33, 0
        registers = list(range(count))
        entry_rules = {reg: ['u'] for reg in registers}
        entry_rules.update({sp: ['v', 0], ra: ['m', -8] if target == 'x86_64' else ['s'], witness: ['s']})
        if target == 'aarch64':
            entry_rules[32] = ['r', 30]  # Explicit caller PC recovery; not an undefined LR alias.
        saved_rules = copy.deepcopy(entry_rules)
        saved_rules.update({ra: ['m', -8], witness: ['m', -16]})
        if target == 'aarch64':
            saved_rules[32] = ['m', -8]
        frames = []
        for name in ('cf_checkpoint', 'cf_recurse', '_start'):
            address, size = symbols[name]
            rules = copy.deepcopy(entry_rules)
            offset = entry_offset
            if name == '_start':
                rules[ra] = ['u']
                if target == 'aarch64': rules[32] = ['u']
                offset = 0
            rows = [{'address': address, 'cfa': [sp, offset], 'rules': rules}]
            if name == 'cf_recurse':
                rows += [{'address': symbols['cf_saved'][0], 'cfa': [sp, 16], 'rules': saved_rules},
                         {'address': symbols['cf_restored'][0], 'cfa': [sp, entry_offset], 'rules': entry_rules}]
            frames.append({'address': address, 'size': size, 'rows': rows})
        frames.sort(key=lambda frame: frame['address'])
        reports.append(encode(case, original, 8, 'little', ra, registers, frames))
        results = {}
        warnings = {}
        for mode, artifact in [('reference', reference), ('none', case / 'none.dbg'),
                               ('zlib', case / 'zlib.dbg'), ('absent', original)]:
            run(['bash', SCRIPTS / 'cfi-encoder-gdb.sh', target, mode, artifact, original,
                 case / ('gdb-' + mode)], case / ('gdb-' + mode + '-driver.log'))
            record = json.loads((case / ('gdb-' + mode + '.json')).read_text())
            log = (case / ('gdb-' + mode + '.log')).read_text()
            selected = 'level=0,type=NORMAL_FRAME,unwinder="dwarf2",pc=' + hex(record['checkpointAddress'])
            assert (selected in log) == (mode != 'absent')
            warnings[mode] = [line for line in log.splitlines() if 'warning:' in line.lower()]
            results[mode] = record
        def normalized(record):
            trace = copy.deepcopy(record['trace'])
            for stack in trace:
                for frame in stack:
                    frame['pc'] -= record['checkpointAddress']
            return trace
        assert normalized(results['reference']) == normalized(results['none']) == normalized(results['zlib'])
        assert all(value == warnings['reference'] for value in warnings.values())
        assert all(target == 'aarch64' and re.fullmatch(
            r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index',
            line) for line in warnings['reference'])
        reports[-1].update({'runtime': results, 'warnings': warnings})
        print(target + ' ' + role + ' encoded CFI runtime PASS', flush=True)
    (work / 'result.json').write_text(json.dumps({'status': 'PASS_FRAME_ENCODER', 'cases': reports,
        'scope': 'Explicit test plans only; no Ghidra rule recovery or production synthesis'}, indent=4) + '\n')


if __name__ == '__main__':
    main()

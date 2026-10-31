#!/usr/bin/env python3
"""Independent raw inventory oracle for the source-built sectionless alias fixtures."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('elf_support', source / 'retained-function-aliases-export.py')
elf_support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(elf_support)


def verify(original, binary, sidecar, aliases, receipt):
    ident, _, old = elf_support.elf(original)
    output_ident, output_header, new = elf_support.elf(sidecar)
    data, emitted = binary.read_bytes(), sidecar.read_bytes()
    wide, order = data[4] == 2, '<' if data[5] == 1 else '>'
    header = struct.unpack_from(order + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), data, 16)
    assert ident == output_ident == data[:16]
    assert header[5] == header[11] == header[12] == 0
    assert output_header[:4] == header[:4] and output_header[6:8] == header[6:8]
    assert output_header[4] == output_header[8] == output_header[9] == 0
    assert emitted[header[7]:len(data)] == data[header[7]:], 'retained source prefix changed'
    unwind = None
    if '.eh_frame_hdr' in old:
        before, original_frames = old['.eh_frame']
        after, recovered_frames = new['.eh_frame']
        assert after[1:5] == before[1:5] and after[6:8] == (0, 0) and after[8] == 1
        assert 0 < after[5] <= before[5] and original_frames.startswith(recovered_frames)
        assert not any(original_frames[len(recovered_frames):])
        unwind = {'address': after[3], 'offset': after[4], 'size': after[5],
            'originalSize': before[5], 'sha256': hashlib.sha256(recovered_frames).hexdigest()}
    else:
        assert '.eh_frame' not in new, 'invented an unproved original frame section'
    loads = []
    has_dynamic = False
    for index in range(header[9]):
        fields = struct.unpack_from(order + ('IIQQQQQQ' if wide else 'IIIIIIII'),
            data, header[4] + index * header[8])
        if wide:
            kind, flags, offset, address, _, size, memory, _ = fields
        else:
            kind, offset, address, _, size, memory, flags, _ = fields
        has_dynamic |= kind == 2
        if kind != 1 or memory == 0:
            continue
        ordinal = len(loads) + 1
        section = new['.forge.load.' + str(index)][0]
        assert list(new).index('.forge.load.' + str(index)) == ordinal
        assert section[1:4] == (8, 2 | (1 if flags & 2 else 0) | (4 if flags & 1 else 0), address)
        assert section[4:10] == (offset, memory, 0, 0, 1, 0)
        loads.append((ordinal, address, memory, size))
    width = 24 if wide else 16
    if '.dynsym' in old:
        old_table, old_bytes = old['.dynsym']
        old_strings = list(old.values())[old_table[6]][1]
    else:
        assert not has_dynamic, 'missing section-backed dynamic inventory oracle'
        # No dynamic inventory exists: the new table begins with a null record.
        old_table, old_bytes = (0, 2, 0, 0, 0, width, 0, 1, 1, width), bytes(width)
        old_strings = b'\0'
    new_table, new_bytes = new['.symtab']
    strings = list(new.values())[new_table[6]][1]
    assert strings.startswith(old_strings)
    assert old_table[9] == new_table[9] == width and new_table[2:4] == (0, 0)
    assert new_table[7] == old_table[7] + len(aliases)
    assert len(new_bytes) == len(old_bytes) + width * len(aliases)

    def record(payload, index, names):
        fields = struct.unpack_from(order + ('IBBHQQ' if wide else 'IIIBBH'), payload, index * width)
        if wide:
            name, info, other, section, value, size = fields
        else:
            name, value, size, info, other, section = fields
        return (names[name:names.index(0, name)], info, other, section, value, size)

    # GNU readelf independently supplies defined version-qualified spellings.
    oracle = subprocess.run(['readelf', '--dyn-syms', '--wide', str(original)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert oracle.returncode == 0 and not oracle.stderr
    receipt.with_suffix('.symbols.txt').write_bytes(oracle.stdout)
    spellings = {}
    for line in oracle.stdout.decode().splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(':') and fields[0][:-1].isdigit():
            spellings[int(fields[0][:-1])] = fields[7].encode()
    preserved = []
    for index in range(len(old_bytes) // width):
        expected = record(old_bytes, index, old_strings)
        destination = index if index < old_table[7] else index + len(aliases)
        actual = record(new_bytes, destination, strings)
        name, info, other, section, value, size = expected
        # readelf synthesizes section names for unnamed STT_SECTION entries;
        # only a real version suffix changes the mirrored symbol spelling.
        if section != 0 and name and spellings.get(index, b'').startswith(name + b'@'):
            name = spellings[index]
        assert actual[0] == name and actual[1:3] == expected[1:3] and actual[4:] == expected[4:], (str(binary), index, name, expected, actual)
        if section in (0, 0xfff1, 0xfff2):
            assert actual[3] == section
        else:
            possible = [ordinal for ordinal, address, memory, _ in loads
                if address <= value < address + memory and size <= address + memory - value]
            if not possible and size == 0:
                possible = [ordinal for ordinal, address, memory, _ in loads if value == address + memory]
            assert possible == [actual[3]], (name, possible, actual)
        preserved.append({'name': name.decode(), 'value': value, 'size': size, 'section': actual[3]})
    added = {}
    for index in range(old_table[7], new_table[7]):
        name, info, other, section, value, size = record(new_bytes, index, strings)
        assert info == 2 and other == 0 and name.decode() not in added
        allocation, = [row for row in loads if row[0] == section]
        assert allocation[1] <= value and value + size <= allocation[1] + allocation[3]
        added[name.decode()] = (value, size)
    assert added == {row['alias']: (row['entry'], row['size']) for row in aliases}
    result = {'status': 'RAW_SECTIONLESS_INVENTORY_PASS', 'originalRecords': len(preserved),
        'preserved': preserved, 'added': added, 'loads': loads, 'unwind': unwind,
        'artifacts': {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (original, binary, sidecar, Path(__file__).resolve())}}
    receipt.write_text(json.dumps(result, indent=4) + '\n')
    return result


def corruption_controls(original, binary, sidecar, aliases, root):
    """Prove the oracle rejects lost records, changed semantics and invented aliases."""
    root.mkdir()
    ident, header, sections = elf_support.elf(sidecar)
    wide, order = ident[4] == 2, '<' if ident[5] == 1 else '>'
    table = sections['.symtab'][0]
    original_sections = elf_support.elf(original)[2]
    original_locals = original_sections['.dynsym'][0][7] if '.dynsym' in original_sections else 1
    width = 24 if wide else 16
    # A static fixture has no inherited nonlocal row; corrupt its null binding.
    binding_row = table[7] if table[7] * width < table[5] else 0
    table_header = header[5] + list(sections).index('.symtab') * header[10]
    modifications = {
        'missing-record': (table_header + (32 if wide else 20), 'Q' if wide else 'I', table[5] - width),
        'wrong-boundary': (table_header + (44 if wide else 28), 'I', table[7] - 1),
        'changed-binding': (table[4] + binding_row * width + (4 if wide else 12), 'B', 0 if binding_row else 16),
        'undefined-alias': (table[4] + original_locals * width + (6 if wide else 14), 'H', 0),
        'unnamed-alias': (table[4] + original_locals * width, 'I', 0),
    }
    rejected = []
    for label, (offset, fmt, value) in modifications.items():
        data = bytearray(sidecar.read_bytes())
        struct.pack_into(order + fmt, data, offset, value)
        candidate = root / (label + '.dbg')
        candidate.write_bytes(data)
        try:
            verify(original, binary, candidate, aliases, root / (label + '.json'))
        except (AssertionError, ValueError) as error:
            (root / (label + '.rejection.txt')).write_text(type(error).__name__ + ': ' + str(error) + '\n')
            rejected.append(label)
        else:
            raise AssertionError('oracle accepted corruption: ' + label)
    (root / 'result.json').write_text(json.dumps({'status': 'CORRUPTION_CONTROLS_PASS',
        'rejected': rejected}, indent=4) + '\n')

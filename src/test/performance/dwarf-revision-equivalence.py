#!/usr/bin/env python3
"""Compare the pinned pre-comp_dir performance control with current DWARF.

Only the documented CU compilation-directory addition and resulting DIE/string
encoding offsets may differ. Every DIE attribute/form/reference and every other
ELF section remains checked. This is specific to the ELF64-LE workload corpus.
"""
import hashlib
import json
import re
import struct
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def elf(data):
    require(data[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little-endian workload')
    header = list(struct.unpack_from('<16sHHIQQQIHHHHHH', data))
    offset, size, count, strings_index = header[6], header[11], header[12], header[13]
    require(header[5] == header[10] == 0 and size == 64 and 0 < strings_index < count,
        'expected non-loadable sidecar with ordinary section table')
    require(offset + size * count <= len(data), 'truncated section table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + size * i) for i in range(count)]
    names_header = headers[strings_index]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    sections, payloads = {}, {}
    for section in headers:
        name_offset, kind, flags, address, start, length, link, info, align, entsize = section
        require(name_offset < len(names) and b'\0' in names[name_offset:], 'bad section name')
        name = names[name_offset:names.index(b'\0', name_offset)].decode('utf-8')
        require(name not in sections, 'duplicate section ' + name)
        payload = None
        if kind != 8:  # SHT_NOBITS has no file bytes.
            require(start + length <= len(data), 'truncated section ' + name)
            payload = data[start:start + length]
        payloads[name] = payload
        sections[name] = {'metadata': [kind, flags, address, link, info, align, entsize],
            'size': length, 'sha256': digest(payload) if payload is not None else None}
    header[0] = header[0].hex()
    header[6] = '<section-table-offset>'
    return header, sections, payloads


def dies(text, directory, *, baseline):
    units = re.findall(r'^0x[0-9a-f]+: Compile Unit:.*$', text, re.M)
    require(len(units) == 1 and all(value in units[0] for value in (
        'format = DWARF32', 'version = 0x0005', 'unit_type = DW_UT_compile',
        'abbr_offset = 0x0000', 'addr_size = 0x08')), 'expected one ELF64 workload DWARF 5 CU')
    headers = list(re.finditer(r'^0x([0-9a-f]+):( +)(DW_TAG_\w+|NULL)\s*$', text, re.M))
    require(headers and headers[0][3] == 'DW_TAG_compile_unit', 'missing CU DIE')
    offsets = {int(header[1], 16): i for i, header in enumerate(headers)}
    require(len(offsets) == len(headers), 'duplicate DIE offsets')
    result = []
    for i, header in enumerate(headers):
        body = text[header.end():headers[i + 1].start() if i + 1 < len(headers) else len(text)]
        attrs = list(re.finditer(r'^\s+(DW_AT_\w+) \[(DW_FORM_\w+)\]\s+', body, re.M))
        require(not attrs or not body[:attrs[0].start()].strip(), 'unparsed attribute prefix')
        values = {}
        for j, attr in enumerate(attrs):
            value = body[attr.end():attrs[j + 1].start() if j + 1 < len(attrs) else len(body)].strip()
            name, form = attr[1], attr[2]
            require(name not in values, 'duplicate attribute ' + name)
            if form.startswith('DW_FORM_ref'):
                match = re.match(r'\((0x[0-9a-f]+)(.*)', value)
                require(match is not None and int(match[1], 16) in offsets, 'unresolved DIE reference')
                value = '(DIE#%d%s' % (offsets[int(match[1], 16)], match[2])
            values[name] = [form, value]
        require(attrs or not body.strip(), 'unparsed DIE body')
        if i == 0:
            if baseline:
                require('DW_AT_comp_dir' not in values, 'pinned baseline unexpectedly has comp_dir')
            else:
                expected = ['DW_FORM_strp', '(' + json.dumps(directory, ensure_ascii=False) + ')']
                require(values.pop('DW_AT_comp_dir', None) == expected, 'wrong/missing compilation directory')
        result.append({'depth': len(header[2]), 'tag': header[3], 'attributes': values})
    return result


def compare_decoded(old, new, directory):
    left, right = dies(old, directory, baseline=True), dies(new, directory, baseline=False)
    require(left == right, 'DWARF differs beyond the accepted compilation-directory addition')
    return len(left)


def first_abbreviation(data):
    cursor = 0

    def uleb():
        nonlocal cursor
        value, shift = 0, 0
        while True:
            require(cursor < len(data) and shift < 64, 'truncated/oversized abbreviation value')
            byte = data[cursor]
            cursor += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7

    code, tag = uleb(), uleb()
    require(code == 1 and tag == 0x11 and cursor < len(data), 'expected first CU abbreviation')
    children = data[cursor]
    cursor += 1
    require(children == 1, 'expected CU children')
    attrs = []
    while True:
        attr, form = uleb(), uleb()
        if attr == form == 0:
            break
        require(attr != 0 and form != 0 and form != 0x21, 'unexpected CU abbreviation encoding')
        attrs.append((attr, form))
    return attrs, data[cursor:]


def compare_sections(old, new, directory=None):
    old_header, old_sections, old_payloads = elf(old)
    new_header, new_sections, new_payloads = elf(new)
    require(old_header == new_header, 'ELF identity/header changed')
    require(old_sections.keys() == new_sections.keys(), 'ELF section inventory changed')
    encoding = {'.debug_info', '.debug_abbrev', '.debug_str'}
    require(encoding <= old_sections.keys(), 'missing producer sections')
    for name in old_sections:
        require(old_sections[name]['metadata'] == new_sections[name]['metadata'], 'section metadata changed: ' + name)
        if name not in encoding:
            require(old_sections[name] == new_sections[name], 'section bytes/size changed: ' + name)
    if directory is not None:
        old_attrs, old_tail = first_abbreviation(old_payloads['.debug_abbrev'])
        new_attrs, new_tail = first_abbreviation(new_payloads['.debug_abbrev'])
        addition = (0x1b, 0x0e)  # DW_AT_comp_dir, DW_FORM_strp
        require(addition not in old_attrs and new_attrs.count(addition) == 1, 'unexpected comp_dir abbreviation')
        new_attrs.remove(addition)
        require(old_attrs == new_attrs and old_tail == new_tail, 'other abbreviation bytes changed')
        added = directory.encode('utf-8') + b'\0'
        strings = new_payloads['.debug_str']
        require(strings.count(added) == 1 and strings.replace(added, b'', 1) == old_payloads['.debug_str'],
            'string table differs beyond exactly one compilation-directory string')
    return {name: row for name, row in new_sections.items() if name not in encoding}


def compare(baseline, candidate, source, evidence):
    evidence.mkdir(parents=True, exist_ok=False)
    decoded = []
    for label, path in (('baseline', baseline), ('candidate', candidate)):
        for kind, options in (('verify', ['--verify']), ('info', ['--debug-info', '--show-form'])):
            command = ['llvm-dwarfdump', *options, str(path)]
            run = subprocess.run(command, capture_output=True, text=True, encoding='utf-8', timeout=300)
            (evidence / (label + '-' + kind + '.txt')).write_text(run.stdout, encoding='utf-8')
            (evidence / (label + '-' + kind + '.stderr')).write_text(run.stderr, encoding='utf-8')
            require(run.returncode == 0 and not run.stderr, 'LLVM failed: ' + repr(command))
            require(not re.search(r'\b(?:warning|error):', run.stdout, re.I), 'LLVM diagnostic')
            if kind == 'verify':
                require('No errors.' in run.stdout, 'LLVM verification did not pass')
            else:
                decoded.append(run.stdout)
    old, new = baseline.read_bytes(), candidate.read_bytes()
    directory = str(source.parent).replace('\\', '/') if source.drive else str(source.parent)
    count = compare_decoded(*decoded, directory)
    stable = compare_sections(old, new, directory)
    result = {'status': 'PASS', 'acceptedDifference': 'CU DW_AT_comp_dir added by 75860c6',
        'diesIncludingNull': count, 'directory': directory, 'stableSections': stable,
        'baselineSha256': digest(old), 'candidateSha256': digest(new)}
    (evidence / 'result.json').write_text(json.dumps(result, indent=4) + '\n', encoding='utf-8')
    return result

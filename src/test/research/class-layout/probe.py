#!/usr/bin/env python3
"""Research GDB class DIE layouts under C11; never change production CU language."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_linkage_attribute(data, named_definition=None):
    """Keep forms/bytes intact, change linkage_name to description in abbrevs."""
    result = bytearray(data)
    cursor = 0
    changes = []

    def leb():
        nonlocal cursor
        value, shift = 0, 0
        while True:
            byte = result[cursor]
            cursor += 1
            value |= (byte & 127) << shift
            if byte < 128:
                return value
            shift += 7
            assert shift < 64

    while cursor < len(result):
        code = leb()
        if code == 0:
            continue
        leb()  # tag
        assert result[cursor] in (0, 1)
        cursor += 1
        while True:
            offset = cursor
            attribute, form = leb(), leb()
            if attribute == form == 0:
                if code == named_definition:
                    result[offset:offset] = b'\x03\x0e'  # name/strp before terminator
                    cursor += 2
                break
            if attribute == 0x6e:  # audited DW_AT_linkage_name
                assert result[offset] == 0x6e and form == 0x0e
                result[offset] = 0x5a  # audited DW_AT_description, same DW_FORM_strp
                changes.append(offset)
            if form == 0x21:  # DW_FORM_implicit_const has one SLEB operand
                leb()
    assert changes
    return bytes(result), changes


def definition_name(data, description, string_offset):
    """Add an explicit root display name; relocate every compiler ref4 in this CU."""
    entries = re.split(r'(?m)(?=^ <\d+><[0-9a-f]+>:)', description)
    declaration, = [int(re.match(r' <\d+><([0-9a-f]+)>', entry)[1], 16) for entry in entries
        if 'DW_TAG_subprogram' in entry and re.search(r'DW_AT_name\s+: .*: inspect_scope$', entry, re.M)]
    index, = [i for i, entry in enumerate(entries) if 'DW_TAG_subprogram' in entry and
        re.search(r'DW_AT_specification:\s+<0x' + format(declaration, 'x') + '>', entry)]
    assert 'DW_AT_name' not in entries[index]
    code = int(re.search(r'Abbrev Number: (\d+)', entries[index])[1])
    insertion = int(re.match(r' <\d+><([0-9a-f]+)>', entries[index + 1])[1], 16)
    # The input probe uses ref4 for every DIE reference; independently require the
    # raw value before adjusting both source offsets and referenced DIE offsets.
    references = re.findall(r'<([0-9a-f]+)>\s+DW_AT_\w+\s*:\s*<0x([0-9a-f]+)>', description)
    adjusted = bytearray(data)
    adjusted[insertion:insertion] = struct.pack('<I', string_offset)
    struct.pack_into('<I', adjusted, 0, struct.unpack_from('<I', data)[0] + 4)
    for offset, target in references:
        offset, target = int(offset, 16), int(target, 16)
        assert struct.unpack_from('<I', data, offset)[0] == target
        struct.pack_into('<I', adjusted, offset + (4 if offset >= insertion else 0),
            target + (4 if target >= insertion else 0))
    return adjusted, code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    directory = Path(__file__).resolve().parent
    repository = directory.parents[3]
    fixture = directory.parent / 'scopes/scope-evidence.cpp'
    protected = {str(p): digest(p) for p in [fixture, *directory.iterdir()] if p.is_file()}
    commands = []

    def run(name, command):
        command = list(map(str, command))
        commands.append({'name': name, 'argv': command})
        (output / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (output / (name + '.log')).open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
        return (output / (name + '.log')).read_text()

    cases = []
    for target in ['x86_64', 'aarch64']:
        prefix = '' if target == 'x86_64' else 'aarch64-linux-gnu-'
        case = output / target
        case.mkdir()
        reference, stripped = case / 'reference', case / 'stripped'
        # These are research source views, not generated Forge source or a claim
        # that C++ input can compile as C. The filename controls GDB auto language.
        (case / 'scope-evidence.cpp').write_bytes(fixture.read_bytes())
        (case / 'scope-evidence.c').write_bytes(fixture.read_bytes())
        run(target + '-compile', [prefix + 'g++', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie',
            '-fno-stack-protector', '-fno-omit-frame-pointer', fixture, '-o', reference])
        run(target + '-strip', [prefix + 'objcopy', '--strip-all', reference, stripped])
        protected.update({str(p): digest(p) for p in [reference, stripped]})
        info = run(target + '-info', ['readelf', '--debug-dump=info', reference])
        abbrev = run(target + '-abbrev', ['readelf', '--debug-dump=abbrev', reference])
        assert 'DW_AT_language     DW_FORM_data1' in abbrev
        language, value = re.findall(r'<([0-9a-f]+)>\s+DW_AT_language\s+: (\d+)', info)[0]
        method, = re.findall(r'<([0-9a-f]+)>\s+DW_AT_name\s+: \(indirect string, offset: 0x[0-9a-f]+\): inspect_scope$', info, re.M)
        class_name, = re.findall(r'<([0-9a-f]+)>\s+DW_AT_name\s+: \(indirect string, offset: 0x[0-9a-f]+\): Counter$', info, re.M)
        symbols = run(target + '-symbols', [prefix + 'nm', reference])
        stop, = re.findall(r'^([0-9a-f]+) T scope_outer$', symbols, re.M)
        sections = {}
        for section in ['.debug_info', '.debug_abbrev', '.debug_str', '.debug_line_str']:
            path = case / (section + '.original')
            run(target + '-dump-' + section, [prefix + 'objcopy', '--dump-section', section + '=' + str(path), reference, case / 'dump-copy.elf'])
            sections[section] = path.read_bytes()
        assert sections['.debug_info'][int(language, 16)] == int(value)
        for variant in ['compiler', 'c11', 'c11-no-linkage', 'c11-qualified-method', 'c11-qualified-both',
                'c11-root-display', 'c11-root-and-class-display']:
            data = bytearray(sections['.debug_info'])
            strings = bytearray(sections['.debug_str'])
            abbreviation = sections['.debug_abbrev']
            line_strings = sections['.debug_line_str']
            changes = []
            if variant != 'compiler':
                data[int(language, 16)] = 0x1d  # audited DW_LANG_C11
                assert b'.cpp\x00' in line_strings
                line_strings = line_strings.replace(b'.cpp\x00', b'.c\x00\x00\x00')
            named_definition = None
            if variant in ['c11-root-display', 'c11-root-and-class-display']:
                data, named_definition = definition_name(data, info, len(strings))
                strings.extend(b'recovered::Counter::inspect_scope\x00')
            if variant not in ['compiler', 'c11']:
                abbreviation, changes = replace_linkage_attribute(abbreviation, named_definition)
            if variant in ['c11-qualified-method', 'c11-qualified-both']:
                struct.pack_into('<I', data, int(method, 16), len(strings))
                strings.extend(b'recovered::Counter::inspect_scope\x00')
            if variant in ['c11-qualified-both', 'c11-root-and-class-display']:
                struct.pack_into('<I', data, int(class_name, 16), len(strings))
                strings.extend(b'recovered::Counter\x00')
            artifact = case / (variant + '.dbg')
            run(target + '-' + variant + '-copy', [prefix + 'objcopy', '--only-keep-debug', reference, artifact])
            replacements = []
            for section, content in [('.debug_info', data), ('.debug_abbrev', abbreviation),
                    ('.debug_str', strings), ('.debug_line_str', line_strings)]:
                path = case / (variant + section)
                path.write_bytes(content)
                replacements.extend(['--update-section', section + '=' + str(path)])
            run(target + '-' + variant + '-edit', [prefix + 'objcopy', *replacements, artifact])
            # only-keep-debug leaves NOBITS frame headers with no data. Remove
            # those empty headers from this research copy: the runtime original
            # still owns its unchanged unwind bytes.
            run(target + '-' + variant + '-symbols-strip', [prefix + 'objcopy', '--strip-all', '--keep-section=.debug*',
                '--remove-section=.eh_frame', '--remove-section=.eh_frame_hdr', artifact])
            layout = run(target + '-' + variant + '-sections', ['readelf', '-SW', artifact])
            assert not re.search(r'\s\.(?:symtab|strtab)\s', layout), 'ELF symbols could mask failed DWARF lookup'
            assert re.search(r'\s\.dynsym\s+NOBITS\s', layout), 'dynamic symbol payload unexpectedly retained'
            run(target + '-' + variant + '-verify', ['llvm-dwarfdump', '--verify', artifact])
            run(target + '-' + variant + '-strict', ['python3', repository / 'src/test/integration/check-dwarfdump.py',
                artifact, case / (variant + '.dwarfdump.log'), '--original', reference])
            emitted_info = run(target + '-' + variant + '-info', ['readelf', '--debug-dump=info', artifact])
            assert 'Warning:' not in emitted_info
            if variant in ['c11-root-display', 'c11-root-and-class-display']:
                run(target + '-' + variant + '-tree', ['python3', directory / 'check-layout.py',
                    output / (target + '-' + variant + '-info.log'),
                    *(['--qualified-class'] if variant == 'c11-root-and-class-display' else [])])
            run(target + '-' + variant + '-gdb', ['bash', directory / 'gdb-probe.sh', case, target, variant, '0x' + stop])
            observation = json.loads((case / (variant + '.gdb.json')).read_text())
            cases.append({'target': target, 'variant': variant, 'artifactSha256': digest(artifact),
                'observation': observation, 'replacedLinkageAbbreviations': changes})
    assert protected == {p: digest(Path(p)) for p in protected}
    (output / 'observations.json').write_text(json.dumps({'status': 'LAYOUT_RESEARCH_PASS',
        'exporterAcceptance': False, 'originalsUnchanged': True, 'protected': protected, 'cases': cases}, indent=4) + '\n')
    print('class-layout-research=PASS; no producer or exporter acceptance')


if __name__ == '__main__':
    main()

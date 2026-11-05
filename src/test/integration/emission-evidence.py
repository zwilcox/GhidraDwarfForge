#!/usr/bin/env python3
"""Compare actual producer evidence with independent ELF/DIE/location reads and GDB."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sections(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01', 'fixture is specifically x86-64 little endian'
    start, = struct.unpack_from('<Q', data, 40)
    size, count, names = struct.unpack_from('<HHH', data, 58)
    assert size == 64 and 0 < count < 0xff00 and names < count
    assert start + size * count <= len(data)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, start + i * size) for i in range(count)]
    table = data[headers[names][4]:headers[names][4] + headers[names][5]]
    result = {}
    for header in headers:
        assert header[0] < len(table)
        name = table[header[0]:table.index(0, header[0])].decode()
        if header[1] == 8:  # SHT_NOBITS has no file payload.
            continue
        assert header[4] + header[5] <= len(data)
        result[name] = data[header[4]:header[4] + header[5]]
    return result


def line_sequences(data):
    # Independent decoder for this fixture's emitted DWARF5 standard opcodes.
    length, version, width, segment, header_size = struct.unpack_from('<IHBBI', data)
    assert length == len(data) - 4 and (version, width, segment) == (5, 8, 0)
    cursor = 12 + header_size
    address, line, rows, sequences = 0, 1, [], []

    def leb(signed=False):
        nonlocal cursor
        result, shift = 0, 0
        while True:
            assert cursor < len(data) and shift < 70
            byte = data[cursor]
            cursor += 1
            result |= (byte & 127) << shift
            shift += 7
            if byte & 128 == 0:
                return result - (1 << shift) if signed and byte & 64 else result

    while cursor < len(data):
        opcode = data[cursor]
        cursor += 1
        if opcode == 0:
            size = leb()
            end = cursor + size
            assert end <= len(data)
            extended = data[cursor]
            cursor += 1
            if extended == 2:
                address, = struct.unpack_from('<Q', data, cursor)
                cursor += 8
            elif extended == 1:
                assert rows and address > rows[-1][0]
                sequences.append((rows, address))
                address, line, rows = 0, 1, []
            else:
                raise AssertionError(('unexpected extended line opcode', extended))
            assert cursor == end
        elif opcode == 1:
            assert not rows or address > rows[-1][0]
            rows.append((address, line))
        elif opcode == 2:
            address += leb()
        elif opcode == 3:
            line += leb(True)
        elif opcode == 4:
            assert leb() == 0, "single synthetic file index"
        else:
            raise AssertionError(('unexpected standard line opcode', opcode))
    assert not rows
    return sequences


def dies(text):
    result, stack = {}, {}
    for entry in re.split(r'(?m)(?=^ <\d+><[0-9a-f]+>:)', text):
        header = re.match(r' <(\d+)><([0-9a-f]+)>: Abbrev Number: (\d+)(?: \((DW_TAG_\w+)\))?', entry)
        if not header:
            continue
        depth, offset, abbreviation, tag = header.groups()
        depth, offset = int(depth), int(offset, 16)
        stack = {d: node for d, node in stack.items() if d < depth}
        if abbreviation == '0':
            continue
        attributes = dict(re.findall(r'DW_AT_(\w+)\s*:\s*([^\n]*)', entry))
        name = attributes.get('name', '').split('): ')[-1].strip()
        target = re.fullmatch(r'<0x([0-9a-f]+)>', attributes.get('type', ''))
        node = {'tag': tag, 'name': name, 'type': int(target[1], 16) if target else None,
                'attributes': attributes, 'parent': stack.get(depth - 1), 'children': [], 'offset': offset}
        if node['parent'] is not None:
            node['parent']['children'].append(node)
        assert offset not in result
        result[offset] = node
        stack[depth] = node
    return result


def inspect(case):
    evidence = json.loads((case / 'forge.dbg.evidence.json').read_text())
    emitted = evidence['emission']
    raw = sections(case / 'forge.dbg')
    assert raw['.debug_line'] == bytes(v & 255 for v in emitted['lines']['section'])
    entries = dies((case / 'info.log').read_text())

    def named(name, tag):
        matches = [d for d in entries.values() if d['name'] == name and d['tag'] == tag]
        assert len(matches) == 1, (name, tag)
        return matches[0]

    types = {'u64': named('uint64_t', 'DW_TAG_base_type'),
             'node': named('Node', 'DW_TAG_structure_type'),
             'opaque': named('OpaquePayload', 'DW_TAG_unspecified_type')}
    for key, target in [('node-pointer', 'node'), ('opaque-pointer', 'opaque')]:
        matches = [d for d in entries.values() if d['tag'] == 'DW_TAG_pointer_type' and d['type'] == types[target]['offset']]
        assert len(matches) == 1
        types[key] = matches[0]
    assert sum(d['tag'].endswith('_type') for d in entries.values()) == 5
    assert not any(d['name'] == 'void' for d in entries.values())
    for key, node in types.items():
        edges = ([node['type']] if node['type'] is not None else []) + [c['type'] for c in node['children'] if c['type'] is not None]
        assert Counter(edges) == Counter(types[r['key']]['offset'] for r in emitted['typeReferences'][key])
    assert emitted['typeReferences']['void'] == []
    functions = {f['function']['name']: f for f in emitted['functions']}
    assert functions.keys() == {'observed', 'failed', 'empty'}
    consumed_lists = []
    for name, function in functions.items():
        raw_function = named(name, 'DW_TAG_subprogram')
        assert int(raw_function['attributes']['low_pc'], 16) == function['function']['address']
        variables = {v['displayName']: v for v in function['variables']}
        assert len(variables) == len(function['variables'])
        assert {d['name'] for d in raw_function['children']} == variables.keys()
        for child in raw_function['children']:
            variable = variables[child['name']]
            assert child['type'] == types[variable['type']['key']]['offset']
            location = variable['location']
            if 'reason' in location:
                assert 'location' not in child['attributes']
            elif 'offset' in location:
                assert child['attributes']['location'] == hex(location['offset']) + ' (location list)'
                content = raw['.debug_loclists']
                assert struct.unpack_from('<I', content)[0] == len(content) - 4
                assert content[4:12] == bytes([5, 0, 8, 0, 0, 0, 0, 0])
                cursor = location['offset']
                assert len(location['ranges']) == (1 if child['name'] == 'late' else 2)
                start_offset = cursor
                for item in location['ranges']:
                    assert content[cursor] == 7
                    start, end = struct.unpack_from('<QQ', content, cursor + 1)
                    assert (start, end) == (item['range']['start'], item['range']['end'])
                    assert content[cursor + 17:cursor + 19] == b'\x02\x90'
                    assert item['expression']['operations'] == [{'opcode': 0x90, 'operand1': content[cursor + 19], 'operand2': 0}]
                    cursor += 20
                assert content[cursor] == 0
                consumed_lists.append((start_offset, cursor + 1))
            else:
                block = re.match(r'(\d+) byte block: ([0-9a-f ]+)\s+\(', child['attributes']['location'])
                assert block
                payload = bytes.fromhex(' '.join(n.zfill(2) for n in block[2].split()))
                assert len(payload) == int(block[1])
                operations = location['expression']['operations']
                if child['name'] == 'x':
                    assert payload == b'\x90\x05' and operations == [{'opcode': 0x90, 'operand1': 5, 'operand2': 0}]
                else:
                    assert child['name'] == 'counter' and payload[0] == 3 and len(payload) == 9
                    assert operations == [{'address': int.from_bytes(payload[1:], 'little')}]
    assert named('failed', 'DW_TAG_subprogram')['type'] is None and functions['failed']['signature'] is None
    assert named('empty', 'DW_TAG_subprogram')['type'] is None and functions['empty']['signature']['returnType']['key'] == 'void'
    assert named('observed', 'DW_TAG_subprogram')['type'] == types['u64']['offset']
    cursor = 12
    for start, end in sorted(consumed_lists):
        assert start == cursor, 'no orphan/overlapping location lists'
        cursor = end
    assert cursor == len(raw['.debug_loclists'])
    # Independent fixture populations and recursive edge traversal, not just JSON presence.
    seen, pending = set(), [types[k]['offset'] for k in ['u64', 'node', 'opaque-pointer']]
    while pending:
        offset = pending.pop()
        if offset in seen:
            continue
        seen.add(offset)
        node = entries[offset]
        pending.extend([node['type']] if node['type'] is not None else [])
        pending.extend(c['type'] for c in node['children'] if c['type'] is not None)
    assert len(seen) == 5 and sum(entries[i]['tag'] == 'DW_TAG_unspecified_type' for i in seen) == 1
    assert evidence['types']['observed']['recoveredNodes'] == len(seen)
    assert evidence['types']['observed']['resolvedEmittedNodes'] == 4
    assert evidence['types']['observed']['opaqueEmittedNodes'] == 1
    assert evidence['types']['observed']['opaqueFreeEmittedRoots'] == 2
    assert evidence['types']['failed']['notEmittedNodes'] == 1
    assert evidence['types']['empty']['emittedImplicitVoidNodes'] == 1
    metrics = evidence['locations']
    body_start = functions['observed']['function']['address']
    body_size = int(named('observed', 'DW_TAG_subprogram')['attributes']['high_pc'])
    for name in ['x', 'moving', 'late']:
        metric = metrics[name]
        assert metric['scopeComplete'] and metric['knownScopeBytes'] == body_size
        assert metric['knownScopeRanges'] == [{'address': body_start, 'size': body_size}]
    assert metrics['moving']['coveredScopeBytes'] == metrics['x']['coveredScopeBytes'] == body_size
    late, = [v for v in functions['observed']['variables'] if v['internalName'] == 'late']
    available, = late['location']['ranges']
    assert metrics['late']['coveredScopeBytes'] == available['range']['end'] - available['range']['start'] < body_size
    assert metrics['late']['locatedRanges'] == [{'address': available['range']['start'], 'size': metrics['late']['coveredScopeBytes']}]
    assert not metrics['counter']['scopeComplete'] and metrics['counter']['knownScopeBytes'] == 0
    assert metrics['counter']['locatedBytes'] == body_size and metrics['counter']['coveredScopeBytes'] == 0
    assert not metrics['failed::hidden']['declarationEmitted'] and metrics['failed::hidden']['knownScopeBytes'] > 0
    assert metrics['failed::hidden']['coveredScopeBytes'] == 0
    assert evidence['variableTotals'] == {'recoveredVariables': 10, 'emittedVariables': 9,
        'variablesWithLocation': 4, 'knownScopeVariables': 4, 'unknownScopeVariables': 6,
        'knownScopeBytes': 3 * body_size + int(named('failed', 'DW_TAG_subprogram')['attributes']['high_pc']),
        'coveredScopeBytes': 2 * body_size + metrics['late']['coveredScopeBytes'], 'extentUnavailableReason': ''}
    inventory = evidence['variableInventory']
    assert inventory['totals'] == evidence['variableTotals']
    rows = {f['function']['name']: f for f in inventory['functions']}
    assert set(rows) == {'observed', 'failed', 'empty'}
    assert all(f['recoveredSignatureKnown'] for f in rows.values())
    assert len(rows['observed']['variables']) == 9 and len(rows['failed']['variables']) == 1
    assert rows['empty']['variables'] == []
    for function_name, function in rows.items():
        for variable in function['variables']:
            name = variable['identity']['internalName']
            metric = metrics[('failed::' if function_name == 'failed' else '') + name]
            for field in ['declarationEmitted', 'scopeComplete', 'knownScopeRanges', 'locatedRanges',
                          'knownScopeBytes', 'coveredScopeBytes', 'locatedBytes']:
                assert variable['location'][field] == metric[field], (function_name, name, field)
            if function_name == 'failed':
                assert variable['emittedType'] is None and variable['omissionReason'] == 'SIGNATURE_NOT_EMITTED'
            else:
                assert variable['emittedType'] == variable['recoveredType']
            if name == 'late':
                assert variable['storageEvidence'][0]['omissionReason'] == 'UNKNOWN_LIFETIME'
                assert variable['storageEvidence'][0]['start'] == body_start
                assert variable['storageEvidence'][0]['end'] == available['range']['start']
            if name == 'counter':
                assert variable['identity']['staticAddress'] == int(named('counter', 'DW_TAG_variable')['attributes']['location'].split('DW_OP_addr: ')[1].split(')')[0], 16)
    assert {k: v['recoveredVariables'] for k, v in inventory['byKind'].items()} == {
        'PARAMETER': 2, 'LOCAL': 7, 'FUNCTION_STATIC': 1}
    sequences = line_sequences(raw['.debug_line'])
    instructions = {int(m[1], 16) for m in re.finditer(
        r'(?m)^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+', (case / 'disassembly.log').read_text())}
    source_text = (case / 'forge.dbg.c').read_text().splitlines()
    symbols = {parts[-1]: int(parts[0], 16) for row in (case / 'symbols.log').read_text().splitlines()
        if len(parts := row.split()) >= 3 and re.fullmatch('[0-9a-fA-F]+', parts[0])}
    expected_tokens = {
        'observed': {symbols['observed']: source_text.index('{') + 1,
                     symbols['observed_moved']: source_text.index('    x = x;') + 1,
                     symbols['observed_return']: source_text.index('    return x;') + 1},
        'failed': {}, 'empty': {symbols['empty']: source_text.index('    return;') + 1}}
    all_decoded, all_anchored, all_visible = set(), set(), set()
    for function in evidence['sourceInventory']['functions']:
        name = function['function']['name']
        ranges = function['function']['ranges']
        decoded = {pc for pc in instructions if any(r['address'] <= pc < r['address'] + r['size'] for r in ranges)}
        visible = {pc for pc in decoded if any(rows[0][0] <= pc < end for rows, end in sequences)}
        anchored = {pc for pc in decoded if any((pc, expected_tokens[name].get(pc)) in rows for rows, _ in sequences)}
        assert function['observedPoints'] == {'decoded': sorted(decoded), 'anchored': sorted(anchored), 'lineVisible': sorted(visible)}
        assert (function['decodedInstructions'], function['anchoredInstructions'], function['lineVisibleInstructions']) == (
            len(decoded), len(anchored), len(visible))
        all_decoded |= decoded
        all_anchored |= anchored
        all_visible |= visible
    assert evidence['sourceInventory']['observedUnion'] == {'functions': 3, 'unavailableInstructionFunctions': 0,
        'unavailableTokenFunctions': 0, 'decodedInstructions': len(all_decoded), 'anchoredInstructions': len(all_anchored),
        'lineVisibleInstructions': len(all_visible)}
    assert (len(all_decoded), len(all_anchored), len(all_visible)) == (6, 2, 4)
    scorecards = evidence['coverage']
    assert scorecards['variables'] == inventory['totals']
    assert scorecards['sourceUnion'] == evidence['sourceInventory']['observedUnion']
    assert scorecards['unknownSignatureFunctions'] == 0 and scorecards['recoveredGlobalsKnown']
    assert scorecards['recoveredGlobals'] == []
    assert scorecards['functionTypeUnion'] == {'recoveredRoots': 4, 'emittedRoots': 4, 'opaqueFreeEmittedRoots': 3,
        'recoveredNodes': len(seen), 'resolvedEmittedNodes': 4, 'opaqueEmittedNodes': 1,
        'notEmittedNodes': 0, 'implicitVoidNodes': 1, 'emittedImplicitVoidNodes': 1}
    for score in scorecards['functions']:
        name = score['function']['name']
        assert score['types'] == evidence['types'][name]
        assert score['variables'] == rows[name]
        assert score['signature']['recovered'] and score['signature']['emitted'] == (name != 'failed')
        assert score['typeProvenance'] == 'UNKNOWN_PER_TYPE'
    return {'rawTypeNodes': 5, 'opaqueNodes': 1, 'variables': 9, 'locations': 4, 'omittedLocations': 5,
            'knownScopeVariables': 3, 'lateCoveredScopeBytes': metrics['late']['coveredScopeBytes'],
            'lateKnownScopeBytes': metrics['late']['knownScopeBytes']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('consumer', type=Path)
    parser.add_argument('producer', type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[3]
    base = repository / 'build/test-results/emission-evidence'
    base.mkdir(parents=True, exist_ok=True)
    case = Path(tempfile.mkdtemp(prefix='run.', dir=base))
    print('emission-evidence-results=' + str(case), flush=True)
    env = dict(os.environ, GHIDRA_INSTALL_DIR=str(args.ghidra.resolve(strict=True)), FORGE_EMISSION_CASE=str(case))
    commands = []

    def run(label, command):
        argv = list(map(str, command))
        commands.append({'label': label, 'argv': argv})
        (case / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (case / (label + '.log')).open('w') as log:
            subprocess.run(argv, cwd=repository, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)

    sources = [repository / 'src/test/fixtures' / name for name in ['emission-evidence.c', 'emission-evidence-x86_64.S']]
    run('compile', ['gcc', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie', *sources, '-o', case / 'reference'])
    run('strip', ['objcopy', '--strip-all', case / 'reference', case / 'input'])
    run('symbols', ['nm', '-n', case / 'reference'])
    run('disassembly', ['objdump', '-d', case / 'reference'])
    protected = {str(p): digest(p) for p in [*sources, case / 'reference', case / 'input', args.consumer, args.producer]}
    run('native', [repository / 'src/test/integration/run-isolated-native-smoke.sh', case / 'native-process',
        repository / 'gradlew', 'emissionEvidenceSmoke', '-PlibdwarfPath=' + str(args.consumer.resolve()),
        '-PlibdwarfpPath=' + str(args.producer.resolve()), '-PsidecarInput=' + str(case / 'input'),
        '-PsidecarOutput=' + str(case / 'forge.dbg'), '-PfixtureSymbols=' + str(case / 'symbols.log')])
    assert 'emission-evidence-native=PASS' in (case / 'native.log').read_text()
    for view in ['info', 'abbrev', 'aranges', 'decodedline', 'loc']:
        run(view, ['readelf', '--debug-dump=' + view, case / 'forge.dbg'])
        assert 'Warning:' not in (case / (view + '.log')).read_text()
    for name in ['input', 'forge.dbg']:
        run(name + '-elf', ['readelf', '-hSWn', case / name])
    run('llvm', ['llvm-dwarfdump', '--verify', case / 'forge.dbg'])
    assert 'No errors.' in (case / 'llvm.log').read_text()
    run('strict', ['python3', repository / 'src/test/integration/check-dwarfdump.py', case / 'forge.dbg',
        case / 'dwarfdump.log', '--original', case / 'input'])
    checked = inspect(case)
    run('gdb', ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set pagination off', '-ex', 'set confirm off',
        '-ex', 'set debuginfod enabled off', '-ex', 'set auto-solib-add off', '-ex', 'set disable-randomization off',
        '-ex', 'file ' + str(case / 'input'), '-ex', 'symbol-file ' + str(case / 'forge.dbg'),
        '-x', repository / 'src/test/integration/emission-evidence-gdb.py'])
    assert 'emission-evidence-gdb=PASS' in (case / 'gdb.log').read_text()
    assert not re.search(r'(?im)^\s*(warning:|error:)', (case / 'gdb.log').read_text())
    assert protected == {p: digest(Path(p)) for p in protected}
    result = {'status': 'PASS', 'scope': 'isolated producer emission facts, raw DWARF and native x86-64 GDB; public reports pending',
        'checks': checked, 'protected': protected, 'sidecarSha256': digest(case / 'forge.dbg'),
        'sourceSha256': digest(case / 'forge.dbg.c')}
    (case / 'acceptance.json').write_text(json.dumps(result, indent=4) + '\n')
    print(json.dumps({'status': 'PASS', 'checks': checked}))


if __name__ == '__main__':
    main()

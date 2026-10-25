"""Exact compiler/storage/topology, raw location-list and GDB prefix evidence."""
from collections import Counter
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, unquote

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('facts', source / 'dynamic-composite-storage-check.py')
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)
stage, directory, repository_arg, module_arg, target = sys.argv[1:]
case, repository, module = Path(directory), Path(repository_arg), Path(module_arg)
assert stage in ("labels", "observations", "finish") and target in ("x86_64", "aarch64")
def read(name):
    return json.loads((case / name).read_text())


def check_location_list(raw, offset, start, boundary, target):
    assert len(raw) >= 12 and int.from_bytes(raw[:4], 'little') == len(raw) - 4
    assert raw[4:12] == bytes((5, 0, 8, 0, 0, 0, 0, 0))
    assert 12 <= offset and offset + 29 <= len(raw)
    assert raw[offset] == 0x07  # DW_LLE_start_end
    assert int.from_bytes(raw[offset + 1:offset + 9], 'little') == start
    assert int.from_bytes(raw[offset + 9:offset + 17], 'little') == boundary
    # Complete object-order pieces; immediate end-of-list leaves the tail absent.
    first, second = (5, 4) if target == 'x86_64' else (0, 1)
    expression = bytes((0x90, first, 0x9d, 64, 0, 0x90, second, 0x9d, 64, 0))
    assert raw[offset + 17:offset + 29] == bytes((len(expression),)) + expression + b'\x00'


reference, original = (facts.facts.elf(case / name) for name in ('prefix.reference', 'prefix.stripped'))
assert original['class'] == 2 and original['data'] == 1
assert original['header'][0] == reference['header'][0] == 2  # ET_EXEC only
assert original['header'][1] == (62 if target == 'x86_64' else 183)
assert original['sections']['.text'][1] == reference['sections']['.text'][1]
assert original['header'][:5] == reference['header'][:5] and original['header'][6] == reference['header'][6]
assert not original['symbols'] and not any(n.startswith('.debug_') or n == '.note.gnu.build-id' for n in original['sections'])
if stage == 'labels':
    labels = {}
    for name in ('capture_pair', 'observed_first', 'observed_second', 'prefix_before', 'prefix_write', 'prefix_after'):
        row, = [row for row in reference['symbols'] if row['name'] == name]
        labels[name] = row
    assert labels['capture_pair']['size'] > 0
    (case / 'labels.json').write_text(json.dumps(labels, indent=4) + '\n')
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(row['address']) + '\n' for name, row in labels.items()))
    paths = [case / name for name in ('prefix.reference', 'prefix.stripped')]
    paths += [repository / 'src/test/fixtures/composite-register-prefix.c']
    paths += [source / name for name in (
        'ghidra_scripts/PrepareCompositeRegisterPrefix.java', 'composite-register-prefix-export.sh',
        'composite-register-prefix-check.py', 'composite-register-prefix-gdb.py',
        'dynamic-composite-storage-check.py', 'dynamic-parameter-storage-check.py',
        'qemu-socket.sh', 'check-dwarfdump.py')]
    paths += [module / 'lib/GhidraDwarfForge.jar', module / 'ghidra_scripts/GhidraDwarfForge.java']
    assert len(paths) == 13
    (case / 'protected-before.json').write_text(json.dumps({str(p): facts.facts.snapshot(p) for p in paths}, indent=4) + '\n')
    sys.exit(0)
labels = read('labels.json')
observations = [read(phase + '.json') for phase in ('natural', 'curate', 'inspect', 'custom', 'reopen-custom')]
def semantic(row):
    row = json.loads(json.dumps(row))
    row.pop('phase')
    for function in row['functions']:
        function.pop('customStorage')
        for parameter in function['parameters']:
            for key in ('hasAssignedStorage', 'storageClass'):
                parameter.pop(key)
    return row
assert all(semantic(row) == semantic(observations[1]) for row in observations[2:])
prep = observations[1]
function, = prep['functions']
parameter, = function['parameters']
assert prep['aggregateBytes'] == parameter['byteSize'] == 16
assert parameter['storageValid'] and not parameter['storageForcedIndirect'] and not parameter['storageBad']
assert parameter['ownerIsFunction'] and parameter['isAttachedParameter'] and parameter['ordinal'] == 0
assert function['callingConvention'] == prep['defaultCallingConvention'] and function['signatureSource'] == 'USER_DEFINED'
assert function['name'] == 'curated_capture_pair' and function['returnType'] == 'void'
assert parameter['name'] == 'value' and parameter['source'] == 'USER_DEFINED'
assert parameter['storageClass'] == 'ghidra.program.model.lang.DynamicVariableStorage'
assert not parameter['storageUnassigned'] and not parameter['storageStack']
assert [p['size'] for p in parameter['varnodes']] == [8, 8]
assert all(p['space'] == 'register' for p in parameter['varnodes'])
expected_join = ['rsi', 'rdi'] if target == 'x86_64' else ['x1', 'x0']
assert [p['register'].lower() for p in parameter['varnodes']] == expected_join
assert [p['baseRegister']['name'].lower() for p in parameter['varnodes']] == expected_join
assert function['highParameterStorageSerialization'] == parameter['storageSerialization']
assert [(p['name'], p['offset'], p['bytes']) for p in parameter['fields']] == [('first', 0, 8), ('second', 8, 8)]
assert not function['customStorage'] and not parameter['hasAssignedStorage']
for observation in observations[3:]:
    converted = observation['functions'][0]
    assert converted['customStorage'] and converted['parameters'][0]['hasAssignedStorage']
    assert converted['parameters'][0]['storageClass'] == 'ghidra.program.model.listing.VariableStorage'
text = function['decompiledC']
for field in ('first', 'second'):
    assert len(re.findall(r'\bvalue\.' + field + r'\b', text)) == 1, text
    assignment = re.findall(r'(?m)^\s*observed_' + field + r'\s*=\s*([^;]+);', text)
    assert len(assignment) == 1, text
    rhs = assignment[0].strip()
    if rhs != 'value.' + field:
        assert re.fullmatch(r'[A-Za-z_]\w*', rhs), text
        assert len(re.findall(r'\b' + re.escape(rhs) + r'\s*(?:=(?!=)|[+*/%&|^-]=|\+\+|--)', text)) == 1, text
        assert re.search(r'(?m)^\s*' + re.escape(rhs) + r'\s*=\s*value\.' + field + r'\s*;', text), text
start, end = map(lambda x: int(x, 16), function['ranges'][0])
assert len(function['ranges']) == 1 and start == int(function['entry'], 16) == labels['capture_pair']['address']
assert end == start + labels['capture_pair']['size']
assert all(p['register'] and p['baseRegister']['space'] == 'register' and p['baseRegister']['bytes'] == 8 for p in parameter['varnodes'])
pieces = [(p['baseRegister']['offset'], p['baseRegister']['bytes']) for p in parameter['varnodes']]
instructions = function['instructions']
by_address = {int(i['address'], 16): i for i in instructions}
cursor = start
writes = []
for index, instruction in enumerate(instructions):
    address = int(instruction['address'], 16)
    raw_instruction = bytes.fromhex(instruction['bytes'])
    assert address == cursor and 0 < instruction['length'] == instruction['parsedLength'] == len(raw_instruction)
    text_header, text_bytes = original['sections']['.text']
    text_offset = address - text_header[3]
    assert 0 <= text_offset <= len(text_bytes) - len(raw_instruction)
    assert text_bytes[text_offset:text_offset + len(raw_instruction)] == raw_instruction
    assert not instruction['lengthOverride'] and not instruction['fallthroughOverride'] and instruction['flowOverride'] == 'NONE'
    assert not instruction['inDelaySlot'] and instruction['delayDepth'] == 0
    cursor += instruction['length']
    opcodes = [p['opcode'] for p in instruction['pcode']]
    assert not set(opcodes) & {'CALL', 'CALLIND', 'BRANCH', 'CBRANCH', 'BRANCHIND', 'CALLOTHER', 'UNIMPLEMENTED'}
    assert not instruction['flowCall'] and not instruction['flowJump']
    if index == len(instructions) - 1:
        assert 'RETURN' in opcodes and instruction['flowTerminal'] and instruction['fallthrough'] is None and cursor == end
    else:
        assert 'RETURN' not in opcodes and instruction['flowFallthrough'] and int(instruction['fallthrough'], 16) == cursor
    for store in instruction['stores']:
        assert store['inputCount'] == 3 and not store['hasOutput'] and store['constantSelector'] and store['memorySpace'] and store['addressBytes'] == store['pointerBytes']
    outputs = [p['output'] for p in instruction['pcode'] if p['output'] is not None and p['output']['register']]
    outputs += instruction['resultRegisters']
    touched = [pi for pi, (at, size) in enumerate(pieces) if any(o['space'] == 'register' and o['offset'] < at + size and at < o['offset'] + o['bytes'] for o in outputs)]
    if touched:
        writes.append({'address': address, 'fallthrough': cursor, 'pieces': touched, 'instruction': instruction['text'], 'outputs': outputs})
for ref in function['flowReferences']:
    destination = int(ref['to'], 16)
    if destination == start:
        continue
    predecessor = by_address.get(int(ref['from'], 16))
    assert ref['type'] == 'FALL_THROUGH' and predecessor is not None and destination in by_address
    assert int(predecessor['fallthrough'], 16) == destination == int(predecessor['address'], 16) + predecessor['length']
assert writes and writes[0]['address'] == labels['prefix_write']['address'] and writes[0]['fallthrough'] == labels['prefix_after']['address']
assert start < labels['prefix_before']['address'] < writes[0]['address']
reports = [facts.facts.transcript(case / ('export-' + phase + '.log'), 'GhidraDwarfForge report: ') for phase in ('curate', 'inspect', 'custom', 'reopen-custom')]
assert reports[0] == reports[1] and reports[2] == reports[3]
for phase, observation in zip(('natural', 'curate', 'inspect', 'custom', 'reopen-custom'), observations):
    assert observation['javaVersion'] == observations[0]['javaVersion']
    assert int(observation['javaVersion'].split('.')[0]) >= 21
    assert observation['language'] == ('x86:LE:64:default' if target == 'x86_64' else 'AARCH64:LE:64:v8A')
    assert observation['pointerBytes'] == 8 and observation['executablePath'] == str(case / 'prefix.stripped')
    origin = urlsplit(observation['exporterOrigin'])
    assert origin.scheme == 'file' and not origin.netloc and not origin.query and not origin.fragment
    assert Path(unquote(origin.path)) == module / 'lib/GhidraDwarfForge.jar'
    log = (case / ('export-' + phase + '.log')).read_text()
    scripts = re.findall(r'^INFO\s+SCRIPT: (.+) \(HeadlessAnalyzer\)\s*$', log, re.MULTILINE)
    expected_scripts = [str(source / 'ghidra_scripts/PrepareCompositeRegisterPrefix.java')]
    if phase != 'natural':
        expected_scripts.append(str(module / 'ghidra_scripts/GhidraDwarfForge.java'))
    assert scripts == expected_scripts, scripts
    versions = re.findall(r'^(?:openjdk|java) version "([0-9]+)[^"]*"[^\n]*$', log, re.MULTILINE)
    assert versions == [observation['javaVersion'].split('.', 1)[0]], versions
for report in reports:
    assert report['status'] == 'PARTIAL' and report['validation'] == {'status': 'NOT_RUN'}
    omission, = [o for o in report['omittedLocations'] if o['function'] == function['name'] and o['variable'] == 'value']
    assert omission['reason'] == 'REGISTER_MODIFIED' and omission['kind'] == 'PARAMETER'
    assert [int(omission[k], 16) for k in ('startAddress', 'endAddress')] == [writes[0]['fallthrough'], end]
proof = {'function': function, 'writes': writes, 'incomingPrefix': [start, writes[0]['fallthrough']], 'reports': reports, 'observations': observations}
if stage == 'observations':
    (case / 'proof.json').write_text(json.dumps(proof, indent=4) + '\n')
    sys.exit(0)
assert proof == read('proof.json')
for prefix, leaf, report in [('', 'prefix.dbg', reports[0]), ('custom-', 'custom.prefix.dbg', reports[2])]:
    output = facts.facts.elf(case / leaf)
    assert output['sections']['.text'][1] == original['sections']['.text'][1]
    assert output['header'][:4] == original['header'][:4] and output['header'][6] == original['header'][6]
    assert output['header'][4] == output['header'][9] == 0
    for role, path in [('input', case / 'prefix.stripped'), ('output', case / leaf), ('source', case / (leaf + '.c'))]:
        assert report['artifacts'][role + 'Path'] == str(path)
        assert report['artifacts'][role + 'Sha256'] == facts.facts.snapshot(path)['sha256']
    dies = facts.die_records((case / (prefix + 'forge-info.stdout')).read_text())
    index, = [i for i, row in enumerate(dies) if row['tag'] == 'DW_TAG_subprogram' and facts.facts.die_name(row) == function['name']]
    parameter_die, = [row for row in facts.children(dies, index) if row['tag'] == 'DW_TAG_formal_parameter']
    assert facts.facts.die_name(parameter_die) == 'value' and 'DW_AT_const_value' not in parameter_die['attrs']
    location = re.fullmatch(r'0x([0-9a-f]+) \(location list\)', parameter_die['attrs']['DW_AT_location'])
    assert location, parameter_die
    raw = output['sections']['.debug_loclists'][1]
    check_location_list(raw, int(location[1], 16), start, writes[0]['fallthrough'], target)
    dtype = {r['offset']: r for r in dies}[int(re.fullmatch(r'<0x([0-9a-f]+)>', parameter_die['attrs']['DW_AT_type'])[1], 16)]
    assert dtype['tag'] == 'DW_TAG_structure_type' and dtype['attrs']['DW_AT_byte_size'] == '16'
    members = [row for row in facts.children(dies, dies.index(dtype)) if row['tag'] == 'DW_TAG_member']
    assert [(facts.facts.die_name(m), m['attrs']['DW_AT_data_member_location']) for m in members] == [('first', '0'), ('second', '8')]
    strict = read(prefix + 'strict.log.check.json')
    assert strict['status'] == 'PASS' and strict['exit_status'] == 0 and strict['uncorroborated_errors'] == 0
    assert strict['reported_errors'] == (4 if target == 'x86_64' else 6)
    for suffix in ('', '.c'):
        assert (case / (leaf + suffix)).read_bytes() == (case / ('first.' + leaf + suffix)).read_bytes()
gdb = [read(v + '-gdb.json') for v in ('compiler', 'forge', 'custom')]
assert all(x['status'] == 'PASS' and x['exitCodes'] == [0] for x in gdb)
assert gdb[1]['states'] == gdb[2]['states']
for run in gdb:
    assert [state['pc'] for state in run['states']] == list(by_address)
    assert run['entry'] == start and run['firstWrite'] == writes[0]['address'] and run['boundary'] == writes[0]['fallthrough']
for run in gdb[1:]:
    assert any(state['available'] for state in run['states']) and any(not state['available'] for state in run['states'])
    assert all(state['available'] == (state['pc'] < writes[0]['fallthrough']) for state in run['states'])
vdso = re.compile(r'warning: BFD: warning: system-supplied DSO at 0x[0-9a-f]+ has a corrupt string table index')
warnings = []
for variant in ('compiler', 'forge', 'custom'):
    lines = (case / (variant + '-gdb.stderr')).read_text().splitlines()
    assert all(target == 'aarch64' and vdso.fullmatch(line) for line in lines), lines
    warnings.append(Counter(vdso.sub('<oracle-vdso>', line) for line in lines))
assert warnings[0] == warnings[1] == warnings[2]
if target == 'aarch64':
    for variant in ('compiler', 'forge', 'custom'):
        endpoint = dict(line.split('=', 1) for line in (case / (variant + '.qemu.endpoint')).read_text().splitlines())
        assert (case / (variant + '.qemu.status')).read_text() == 'exit=0\n'
        assert not (case / (variant + '.qemu.stderr')).read_bytes()
        assert not Path(endpoint['socket']).exists() and not Path(endpoint['socket']).parent.exists()


before = read('protected-before.json')
after = {path: facts.facts.snapshot(Path(path)) for path in before}
(case / 'protected-after.json').write_text(json.dumps(after, indent=4) + '\n')
assert before == after
(case / 'result.json').write_text(json.dumps({'status': 'COMPOSITE_REGISTER_PREFIX_EXPORT_PASS', 'target': target, 'proof': proof, 'gdb': gdb, 'gdbWarnings': [dict(x) for x in warnings], 'protectedFiles': len(before)}, indent=4) + '\n')
print('composite-register-prefix-export PASS: ' + str(case))

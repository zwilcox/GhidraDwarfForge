"""Independent compiler/export DIE checks and a real caller's aggregate return."""
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

source = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('facts', source / 'dynamic-composite-storage-check.py')
facts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(facts)
stage, directory, repository_arg, module_arg = sys.argv[1:]
assert stage in ('labels', 'observations', 'finish')
case, repository, module = Path(directory), Path(repository_arg), Path(module_arg)


def read(name):
    return json.loads((case / name).read_text())


def write(name, value):
    (case / name).write_text(json.dumps(value, indent=4) + '\n')


def return_shape(text, name):
    dies = facts.die_records(text)
    by_offset = {row['offset']: row for row in dies}
    function, = [row for row in dies if row['tag'] == 'DW_TAG_subprogram' and facts.facts.die_name(row) == name]
    def referenced(row):
        return by_offset[int(re.fullmatch(r'<0x([0-9a-f]+)>', row['attrs']['DW_AT_type'])[1], 16)]
    returned = referenced(function)
    assert returned['tag'] == 'DW_TAG_structure_type' and returned['attrs']['DW_AT_byte_size'] == '24', returned
    members = [row for row in facts.children(dies, dies.index(returned)) if row['tag'] == 'DW_TAG_member']
    assert [(facts.facts.die_name(row), row['attrs']['DW_AT_data_member_location']) for row in members] == [
        ('first', '0'), ('second', '8'), ('third', '16')]
    for row in members:
        dtype = referenced(row)
        while dtype['tag'] == 'DW_TAG_typedef':
            dtype = referenced(dtype)
        assert dtype['tag'] == 'DW_TAG_base_type' and dtype['attrs']['DW_AT_byte_size'] == '8'
        assert 'unsigned' in dtype['attrs']['DW_AT_encoding']
    return dies, function, returned, referenced


reference, original = (facts.facts.elf(case / name) for name in ('return.reference', 'return.stripped'))
assert original['class'] == 2 and original['data'] == 1
assert reference['header'][0] == original['header'][0] == 2 and original['header'][1] == 62
assert original['sections']['.text'][1] == reference['sections']['.text'][1]
assert not original['symbols'] and not any(name.startswith('.debug_') for name in original['sections'])
if stage == 'labels':
    labels = {}
    for name in ('make_result', 'main', 'observed_first', 'observed_second', 'observed_third'):
        labels[name], = [row for row in reference['symbols'] if row['name'] == name]
    write('labels.json', labels)
    (case / 'labels.txt').write_text(''.join(name + ' ' + hex(row['address']) + '\n' for name, row in labels.items()))
    paths = [case / name for name in ('return.reference', 'return.stripped')]
    paths += [repository / 'src/test/fixtures/formal-function-return.c', module / 'lib/GhidraDwarfForge.jar',
        module / 'ghidra_scripts/GhidraDwarfForge.java']
    paths += [source / name for name in ('formal-function-return-check.py', 'formal-function-return-export.sh',
        'formal-function-return-gdb.py', 'ghidra_scripts/PrepareReturnTriple.java',
        'dynamic-composite-storage-check.py', 'dynamic-parameter-storage-check.py', 'check-dwarfdump.py')]
    write('protected-before.json', {str(path): facts.facts.snapshot(path) for path in paths})
    sys.exit(0)
labels = read('labels.json')
start = labels['make_result']['address']
end = start + labels['make_result']['size']
current, reopened = (read(phase + '.json') for phase in ('curate', 'reopen'))
assert {k: v for k, v in current.items() if k != 'phase'} == {k: v for k, v in reopened.items() if k != 'phase'}
for phase in ('natural', 'curate', 'reopen'):
    row = read(phase + '.json')
    assert Path(unquote(urlsplit(row['exporterOrigin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    log = (case / ('export-' + phase + '.log')).read_text()
    scripts = [str(source / 'ghidra_scripts/PrepareReturnTriple.java')]
    if phase != 'natural':
        scripts.append(str(module / 'ghidra_scripts/GhidraDwarfForge.java'))
        assert log.count('GhidraDwarfForge symbol export PASS') == 1
    assert re.findall(r'^INFO\s+SCRIPT: (.+) \(HeadlessAnalyzer\)\s*$', log, re.M) == scripts
assert current['language'] == 'x86:LE:64:default' and current['pointerBytes'] == 8
assert not current['customStorage'] and current['signatureSource'] == 'USER_DEFINED'
assert current['return']['forcedIndirect'] and current['return']['effective']['bytes'] == 8
formal = current['return']['formal']
assert formal['bytes'] == 24 and [(x['name'], x['offset'], x['bytes']) for x in formal['fields']] == [
    ('first', 0, 8), ('second', 8, 8), ('third', 16, 8)]
auto, seed, delta = current['parameters']
assert auto['auto'] and auto['autoKind'] == 'RETURN_STORAGE_PTR' and auto['pointsToFormalReturn'] and not auto['forcedIndirect']
assert [p['name'] for p in (seed, delta)] == ['seed', 'delta'] and not seed['auto'] and not delta['auto']
assert [p['varnodes'][0]['register'].lower() for p in current['parameters']] == ['rdi', 'rsi', 'edx']
text_header, text_bytes = original['sections']['.text']
cursor = start
for ins in current['instructions']:
    address = int(ins['address'], 16)
    raw = bytes.fromhex(ins['bytes'])
    assert address == cursor and not ins['lengthOverride'] and ins['flowOverride'] == 'NONE'
    assert text_bytes[address - text_header[3]:address - text_header[3] + len(raw)] == raw and ins['length'] == len(raw)
    cursor += len(raw)
assert cursor == end and current['ranges'] == [[current['entry'], format(end, '08x')]]
assert current['decompileCompleted'] and current['decompiledC']
reports = [facts.facts.transcript(case / ('export-' + phase + '.log'), 'GhidraDwarfForge report: ') for phase in ('curate', 'reopen')]
assert reports[0] == reports[1]
for name in ('return.dbg', 'return.dbg.c'):
    assert (case / name).read_bytes() == (case / ('first.' + name)).read_bytes()
strict = read('strict.log.check.json')
assert strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0
return_shape((case / 'compiler-info.stdout').read_text(), 'make_result')
dies, function, returned, referenced = return_shape((case / 'forge-info.stdout').read_text(), 'curated_make_result')
parameters = [row for row in facts.children(dies, dies.index(function)) if row['tag'] == 'DW_TAG_formal_parameter']
assert [facts.facts.die_name(row) for row in parameters] == [p['name'] for p in current['parameters'][1:]]
assert [row['attrs'].get('DW_AT_artificial', '0') for row in parameters] == ['0', '0']
hidden_variable, = [row for row in facts.children(dies, dies.index(function))
    if row['tag'] == 'DW_TAG_variable' and facts.facts.die_name(row) == auto['name']]
assert hidden_variable['attrs']['DW_AT_artificial'] == '1'
hidden = referenced(hidden_variable)
assert hidden['tag'] == 'DW_TAG_pointer_type' and hidden['attrs']['DW_AT_byte_size'] == '8' and referenced(hidden) == returned
output = facts.facts.elf(case / 'return.dbg')
assert output['header'][:4] == original['header'][:4] and output['header'][6] == original['header'][6]
assert output['header'][4] == output['header'][9] == 0
assert output['sections']['.text'][1] == text_bytes
# Check actual encoded locations, independently of omission reports.
locations = []
for parameter, register in zip([hidden_variable, *parameters], (5, 4, 1), strict=True):
    attr = parameter['attrs']['DW_AT_location']
    expected = bytes((0x90, register))
    if 'byte block:' in attr:
        match = re.fullmatch(r'(\d+) byte block: (.*?)\s*\(DW_OP_regx:.*', attr)
        assert match
        raw = bytes(int(value, 16) for value in match[2].split())
        assert raw == expected and len(raw) == int(match[1])
        ranges = [[start, end, raw.hex()]]
    else:
        match = re.fullmatch(r'0x([0-9a-f]+) \(location list\)', attr)
        assert match, attr
        offset = int(match[1], 16)
        raw = output['sections']['.debug_loclists'][1]
        assert raw[4:12] == bytes((5, 0, 8, 0, 0, 0, 0, 0)) and offset >= 12
        assert raw[offset] == 7
        low = int.from_bytes(raw[offset + 1:offset + 9], 'little')
        high = int.from_bytes(raw[offset + 9:offset + 17], 'little')
        assert low == start and start < high < end
        assert raw[offset + 17:offset + 21] == bytes((2,)) + expected + b'\0'
        ranges = [[low, high, expected.hex()]]
    locations.append({'name': facts.facts.die_name(parameter), 'locations': ranges, 'attrs': parameter['attrs']})
main = labels['main']
returns = []
for line in (case / 'compiler-disassembly.stdout').read_text().splitlines():
    match = re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)ret(?:q)?\s*', line)
    if match and main['address'] <= int(match[1], 16) < main['address'] + main['size']:
        returns.append((int(match[1], 16), bytes.fromhex(match[2])))
(main_return, instruction), = returns
assert instruction == b'\xc3' and text_bytes[main_return - text_header[3]] == 0xc3
model = {'start': start, 'end': end, 'mainReturn': main_return, 'parameters': locations, 'report': reports[0],
    'wanted': [0x1122334455667788, 0x1122334455667775, 0x1122334455667788 ^ 0xffffffed]}
if stage == 'observations':
    write('model.json', model)
    sys.exit(0)
assert read('model.json') == model
compiler, forge = (read(variant + '-gdb.json') for variant in ('compiler', 'forge'))
pcs = [int(ins['address'], 16) for ins in current['instructions']]
for row in (compiler, forge):
    assert row['status'] == 'PASS' and [state['pc'] for state in row['states']] == pcs and row['exitCodes'] == [0]
    assert row['returnType']['bytes'] == 24 and row['returnType']['code'] == 3
    assert list(row['callerGlobals'].values()) == model['wanted']
    assert row['injectedCalls'] == [
        {'seed': 0x1122334455667788, 'delta': -19, 'returned': model['wanted']},
        {'seed': 23, 'delta': 7, 'returned': [23, 30, 16]}]
assert all(compiler['explicitPositivePCs'][name] == len(pcs) for name in ('seed', 'delta'))
assert forge['explicitPositivePCs']['seed'] == len(pcs) and 0 < forge['explicitPositivePCs']['delta'] < len(pcs)
protected = read('protected-before.json')
after = {path: facts.facts.snapshot(Path(path)) for path in protected}
write('protected-after.json', after)
assert protected == after
for role, name in [('input', 'return.stripped'), ('output', 'return.dbg'), ('source', 'return.dbg.c')]:
    assert reports[0]['artifacts'][role + 'Sha256'] == facts.facts.snapshot(case / name)['sha256']
write('result.json', {'status': 'PASS', 'target': 'x86_64', 'javaVersion': current['javaVersion'],
    'protectedUnchanged': True, 'instructionPCs': pcs, 'strict': strict, 'gdb': [compiler, forge],
    'scope': 'One native SysV ET_EXEC aggregate return with two injected calls per compiler/Forge run; no broad ABI claim.'})
print('formal-function-return=PASS ' + str(case))

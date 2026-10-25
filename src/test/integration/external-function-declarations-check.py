"""Compiler, raw declaration DIE, immutable model and actual caller oracle."""
from collections import Counter
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


reference, original = (facts.facts.elf(case / name) for name in ('decl.reference', 'decl.stripped'))
assert original['class'] == 2 and original['data'] == 1 and original['header'][0:2] == (2, 62)
assert original['sections']['.text'][1] == reference['sections']['.text'][1] and not original['symbols']
if stage == 'labels':
    labels = {}
    for name in ('main', 'observed_result'):
        labels[name], = [row for row in reference['symbols'] if row['name'] == name]
    write('labels.json', labels)
    (case / 'labels.txt').write_text(hex(labels['main']['address']) + ' ' + hex(labels['observed_result']['address']) + '\n')
    paths = [case / name for name in ('decl.reference', 'decl.stripped', 'libexternal.so')]
    paths += [repository / 'src/test/fixtures/external-function-declarations.c', module / 'lib/GhidraDwarfForge.jar',
        module / 'ghidra_scripts/GhidraDwarfForge.java']
    paths += [source / name for name in ('external-function-declarations-check.py', 'external-function-declarations-export.sh',
        'external-function-declarations-gdb.py', 'ghidra_scripts/PrepareExternalDeclarations.java',
        'dynamic-composite-storage-check.py', 'dynamic-parameter-storage-check.py', 'check-dwarfdump.py')]
    write('protected-before.json', {str(path): facts.facts.snapshot(path) for path in paths})
    sys.exit(0)
labels = read('labels.json')
current, reopened = (read(phase + '.json') for phase in ('curate', 'reopen'))
assert {k: v for k, v in current.items() if k != 'phase'} == {k: v for k, v in reopened.items() if k != 'phase'}
for phase in ('curate', 'reopen'):
    row = read(phase + '.json')
    assert Path(unquote(urlsplit(row['exporterOrigin']).path)).resolve() == (module / 'lib/GhidraDwarfForge.jar').resolve()
    log = (case / ('export-' + phase + '.log')).read_text()
    assert log.count('GhidraDwarfForge symbol export PASS') == 1
    assert re.findall(r'^INFO\s+SCRIPT: (.+) \(HeadlessAnalyzer\)\s*$', log, re.M) == [
        str(source / 'ghidra_scripts/PrepareExternalDeclarations.java'), str(module / 'ghidra_scripts/GhidraDwarfForge.java')]
for name in ('decl.dbg', 'decl.dbg.c'):
    assert (case / name).read_bytes() == (case / ('first.' + name)).read_bytes()
reports = [facts.facts.transcript(case / ('export-' + phase + '.log'), 'GhidraDwarfForge report: ') for phase in ('curate', 'reopen')]
assert reports[0] == reports[1]
strict = read('strict.log.check.json')
assert strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0
model_declarations = current['model']['functionDeclarations']
assert len(model_declarations) >= 2
assert all('address' not in row and 'locals' not in row for row in model_declarations)
assert all(row['externalAddress'] for row in current['externals'])
assert any(row['name'].endswith('::unknown_signature') and row['source'] == 'DEFAULT' for row in current['externals'])
assert not any(row['name'].endswith('::unknown_signature') for row in model_declarations)
output = facts.facts.elf(case / 'decl.dbg')
assert output['header'][:4] == original['header'][:4] and output['header'][6] == original['header'][6]
assert output['header'][4] == output['header'][9] == 0
assert output['sections']['.text'][1] == original['sections']['.text'][1]
dies = facts.die_records((case / 'forge-info.stdout').read_text())
by_offset = {row['offset']: row for row in dies}
declarations = [row for row in dies if row['tag'] == 'DW_TAG_subprogram' and row['attrs'].get('DW_AT_declaration') == '1']
assert Counter(facts.facts.die_name(row) for row in declarations) == Counter(row['name'] for row in model_declarations)
for row in declarations:
    assert row['attrs']['DW_AT_external'] == row['attrs']['DW_AT_prototyped'] == '1'
    assert not (set(row['attrs']) & {'DW_AT_low_pc', 'DW_AT_high_pc', 'DW_AT_ranges', 'DW_AT_entry_pc',
        'DW_AT_location', 'DW_AT_frame_base', 'DW_AT_decl_file', 'DW_AT_decl_line', 'DW_AT_linkage_name'})
    for child in facts.children(dies, dies.index(row)):
        if child['tag'] is not None:
            assert child['tag'] in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters')
            assert 'DW_AT_location' not in child['attrs'] and 'DW_AT_const_value' not in child['attrs']
imported, = [row for row in declarations if facts.facts.die_name(row).endswith('::imported_adjust')]
compiler = facts.die_records((case / 'compiler-info.stdout').read_text())
compiler_import, = [row for row in compiler if row['tag'] == 'DW_TAG_subprogram' and facts.facts.die_name(row) == 'imported_adjust']
assert compiler_import['attrs']['DW_AT_declaration'] == '1'
for records, function in ((dies, imported), (compiler, compiler_import)):
    index = {row['offset']: row for row in records}
    def dtype(row):
        return index[int(re.fullmatch(r'<0x([0-9a-f]+)>', row['attrs']['DW_AT_type'])[1], 16)]
    returned = dtype(function)
    parameter, = [row for row in facts.children(records, records.index(function)) if row['tag'] == 'DW_TAG_formal_parameter']
    argument = dtype(parameter)
    assert returned['tag'] == argument['tag'] == 'DW_TAG_base_type'
    assert returned['attrs']['DW_AT_byte_size'] == '8' and argument['attrs']['DW_AT_byte_size'] == '4'
    assert all('signed' in row['attrs']['DW_AT_encoding'] and 'unsigned' not in row['attrs']['DW_AT_encoding'] for row in (returned, argument))
unused, = [row for row in declarations if facts.facts.die_name(row) == 'analyst_library::never_called']
assert unused['attrs']['DW_AT_noreturn'] == '1'
assert any(row['tag'] == 'DW_TAG_unspecified_parameters' for row in facts.children(dies, dies.index(unused)))
main = labels['main']
start, end = main['address'], main['address'] + main['size']
returns = []
for line in (case / 'compiler-disassembly.stdout').read_text().splitlines():
    match = re.fullmatch(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)ret(?:q)?\s*', line)
    if match and start <= int(match[1], 16) < end:
        returns.append((int(match[1], 16), bytes.fromhex(match[2])))
(main_return, instruction), = returns
assert instruction == b'\xc3'
model = {'start': start, 'end': end, 'mainReturn': main_return,
    'declarationNames': [row['name'] for row in model_declarations]}
if stage == 'observations':
    write('model.json', model)
    sys.exit(0)
assert read('model.json') == model
runs = [read(variant + '-gdb.json') for variant in ('compiler', 'forge')]
assert all(row['status'] == 'PASS' and row['observed'] == 12 and row['exitCodes'] == [0] for row in runs)
protected = read('protected-before.json')
after = {path: facts.facts.snapshot(Path(path)) for path in protected}
write('protected-after.json', after)
assert protected == after
for role, name in [('input', 'decl.stripped'), ('output', 'decl.dbg'), ('source', 'decl.dbg.c')]:
    assert reports[0]['artifacts'][role + 'Sha256'] == facts.facts.snapshot(case / name)['sha256']
write('result.json', {'status': 'PASS', 'declarations': model_declarations, 'gdb': runs, 'strict': strict,
    'javaVersion': current['javaVersion'], 'protectedUnchanged': True,
    'scope': 'Declaration metadata only. GDB ignores unlocated declarations in compiler and Forge artifacts; real definition and runtime remain usable.'})
print('external-function-declarations=PASS ' + str(case))

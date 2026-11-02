"""Review complete split-pair locations and the first unproven store boundary."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit
from mixed_incoming_contract import location_rows, validate_code

spec = importlib.util.spec_from_file_location('mixed_dies', Path(__file__).with_name('dynamic-parameter-storage-check.py'))
dies = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dies)


def pair_locations(text):
    records = dies.die_records(text)
    index, = [i for i, die in enumerate(records) if die['tag'] == 'DW_TAG_subprogram' and dies.die_name(die) == 'mixed']
    parameters = []
    for die in records[index + 1:]:
        if die['depth'] <= records[index]['depth']:
            break
        if die['tag'] == 'DW_TAG_formal_parameter' and dies.die_name(die) == 'pair':
            parameters.append(die)
    parameter, = parameters
    location = parameter['attrs']['DW_AT_location']
    assert '(location list)' in location
    offset = int(re.search(r'0x[0-9a-f]+', location)[0], 16)
    rows, active = [], False
    for line in text.splitlines():
        row = re.fullmatch(r'\s*([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) (\([^\n]+\))', line)
        if row:
            active = active or int(row[1], 16) == offset
            if active:
                rows.append((int(row[2], 16), int(row[3], 16), row[4]))
        elif active:
            assert re.fullmatch(r'\s*[0-9a-f]+ <End of list>', line), line
            return rows
    raise AssertionError('unterminated or missing pair location list')

root, ghidra = map(Path, sys.argv[1:])
jar = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
expected = {'low': 0x12345678, 'high': -1234567}
cases = []
for role in ('exec', 'pie'):
    case = root / role
    labels = dict((name, int(address, 16)) for name, address in
        (line.split() for line in (case / 'labels.txt').read_text().splitlines()))
    compiler = json.loads((case / 'compiler-gdb.txt.json').read_text())
    assert compiler['status'] == 'PASS' and compiler['compiler']
    assert all(not point['compilerLocationValidated'] and point['machine'] == expected
        for point in compiler['points'][:2])
    assert all(point['fields'] == expected for point in compiler['points'][2:])
    initial = json.loads((case / 'computed/baseline/model.json').read_text())
    for form in ('computed', 'custom'):
        for sample in ('baseline', 'rebased', 'repeat'):
            directory = case / form / sample
            model = json.loads((directory / 'model.json').read_text())
            assert Path(unquote(urlsplit(model['origin']).path)).resolve() == jar.resolve()
            parameter, = [p for p in model['parameters'] if p['name'] == 'pair']
            assert parameter['dynamic'] == (form == 'computed')
            assert parameter['storage'] == 'Stack[0x0]:4,r3:4'
            assert [(p['space'], p['size']) for p in parameter['pieces']] == [('stack', 4), ('register', 4)]
            delta = initial['rebaseDelta'] + (0x2000000 if sample == 'rebased' else 0)
            assert model['rebaseDelta'] == model['imageBase'] - model['originalImageBase'] == delta
            store = next(i for i in model['instructions'] if any('STORE' in op for op in i['pcode']))
            store_pc = int(store['address'], 16) - delta
            boundary = store_pc + store['length']
            assert store_pc == labels['mixed'] + 4 and boundary == labels['mixed_before']
            report, = [json.loads(line[line.index('{'):line.rindex('}') + 1])
                for line in (directory / 'headless.txt').read_text().splitlines()
                if 'GhidraDwarfForge report:' in line]
            omission, = [row for row in report['omittedLocations'] if row['function'] == 'mixed'
                and row['variable'] == 'pair']
            assert omission['reason'] == 'UNKNOWN_LIFETIME' and int(omission['startAddress'], 16) == labels['mixed'] + 24
            rows = pair_locations((directory / 'readelf.txt').read_text())
            assert rows == location_rows(labels['mixed']), rows
            runtime = json.loads((directory / 'gdb.txt.json').read_text())
            assert runtime['status'] == 'PASS' and not runtime['compiler']
            assert (runtime['bias'] == 0) == (role == 'exec')
            validate_code(bytes.fromhex(runtime['codeHex']), role == 'pie', labels['mixed'], labels['mixed_low'])
            assert [p['offset'] for p in runtime['points']] == list(range(0, 40, 4))
            assert all(p['machine'] == expected for p in runtime['points'])
            assert all(p['fields'] == expected for p in runtime['points'][:6])
            assert all(not p['available'] for p in runtime['points'][6:])
            strict = json.loads((directory / 'strict.txt.check.json').read_text())
            assert strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0
            assert 'No errors.' in (directory / 'llvm.txt').read_text()
            cases.append({'role': role, 'form': form, 'sample': sample, 'java': model['java'],
                'runtimeBias': runtime['bias'], 'artifact': hashlib.sha256((directory / 'mixed.dbg').read_bytes()).hexdigest()})
(root / 'acceptance.json').write_text(json.dumps({'status': 'PASS', 'cases': cases,
    'jarSha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
    'compilerBeforePrologueValidated': False}, indent=4) + '\n')

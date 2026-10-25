"""Review exact mixed piece order, SP offsets, write cutoff, and runtime values."""
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

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
            assert omission['reason'] == 'UNKNOWN_LIFETIME' and int(omission['startAddress'], 16) == boundary
            rows = re.findall(r'^\s*[0-9a-f]+ ([0-9a-f]+) ([0-9a-f]+) '
                r'\(DW_OP_regx: 3 \(r3\); DW_OP_bit_piece: size: 32 offset: 0 ; '
                r'DW_OP_bregx: 13 \(r13\) ([0-9]+); DW_OP_bit_piece: size: 32 offset: 0 \)',
                (directory / 'readelf.txt').read_text(), re.MULTILINE)
            assert [(int(start, 16), int(end, 16), int(offset)) for start, end, offset in rows] == [
                (labels['mixed'], store_pc, 0), (store_pc, boundary, 8)], rows
            runtime = json.loads((directory / 'gdb.txt.json').read_text())
            assert runtime['status'] == 'PASS' and not runtime['compiler']
            assert (runtime['bias'] == 0) == (role == 'exec')
            assert all(p['fields'] == p['machine'] == expected for p in runtime['points'][:2])
            assert all(not p['available'] for p in runtime['points'][2:])
            strict = json.loads((directory / 'strict.txt.check.json').read_text())
            assert strict['status'] == 'PASS' and strict['uncorroborated_errors'] == 0
            assert 'No errors.' in (directory / 'llvm.txt').read_text()
            cases.append({'role': role, 'form': form, 'sample': sample, 'java': model['java'],
                'runtimeBias': runtime['bias'], 'artifact': hashlib.sha256((directory / 'mixed.dbg').read_bytes()).hexdigest()})
(root / 'acceptance.json').write_text(json.dumps({'status': 'PASS', 'cases': cases,
    'jarSha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
    'compilerBeforePrologueValidated': False}, indent=4) + '\n')

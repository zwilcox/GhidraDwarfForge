"""Cross-check actual joins, normalized DWARF ranges, and runtime observations."""
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

root, ghidra = map(Path, sys.argv[1:])
jar = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
cases = []
for role in ('exec', 'pie'):
    case = root / role
    labels = dict((name, int(address, 16)) for name, address in
        (line.split() for line in (case / 'labels.txt').read_text().splitlines()))
    compiler = json.loads((case / 'compiler-gdb.txt.json').read_text())
    assert compiler['status'] == 'PASS' and compiler['compiler']
    assert not compiler['points'][0]['compilerLocationValidated']
    for row in compiler['points'][1:3]:
        assert row['fields'] == {'low': -19, 'high': 37}
    initial = json.loads((case / 'baseline/model.json').read_text())
    for sample in ('baseline', 'rebased', 'repeat'):
        directory = case / sample
        model = json.loads((directory / 'model.json').read_text())
        assert Path(unquote(urlsplit(model['origin']).path)).resolve() == jar.resolve()
        parameter, = model['parameters']
        assert parameter['dynamic'] and parameter['storage'] == 'r1:4,r0:4'
        assert [(p['space'], p['size']) for p in parameter['pieces']] == [('register', 4)] * 2
        terminal = model['instructions'][-1]
        assert terminal['instruction'] == 'bx lr'
        assert any('CALLOTHER' in operation for operation in terminal['pcode'])
        assert 'RETURN' in terminal['pcode'][-1]
        delta = initial['rebaseDelta'] + (0x2000000 if sample == 'rebased' else 0)
        assert model['rebaseDelta'] == model['imageBase'] - model['originalImageBase'] == delta
        assert int(model['instructions'][0]['address'], 16) == labels['terminal_pair'] + delta
        reports = [json.loads(line[line.index('{'):line.rindex('}') + 1])
            for line in (directory / 'headless.txt').read_text().splitlines()
            if 'GhidraDwarfForge report:' in line]
        report, = reports
        omission, = [row for row in report['omittedLocations'] if row['function'] == 'terminal_pair'
            and row['variable'] == 'pair']
        assert omission['reason'] == 'REGISTER_MODIFIED'
        assert int(omission['startAddress'], 16) == labels['terminal_pair_after']
        rows = re.findall(r'^\s*[0-9a-f]+ ([0-9a-f]+) ([0-9a-f]+) '
            r'\(DW_OP_regx: 0 \(r0\); DW_OP_bit_piece: size: 32 offset: 0 ; '
            r'DW_OP_regx: 1 \(r1\); DW_OP_bit_piece: size: 32 offset: 0 \)',
            (directory / 'readelf.txt').read_text(), re.MULTILINE)
        assert len(rows) == 1 and tuple(int(n, 16) for n in rows[0]) == (
            labels['terminal_pair'], labels['terminal_pair_after']), rows
        runtime = json.loads((directory / 'gdb.txt.json').read_text())
        assert runtime['status'] == 'PASS' and not runtime['compiler']
        assert (runtime['bias'] == 0) == (role == 'exec')
        assert all(row['fields'] == {'low': -19, 'high': 37} for row in runtime['points'][:3])
        assert runtime['points'][-1]['r0'] == 0 and not runtime['points'][-1]['available']
        strict = json.loads((directory / 'strict.txt.check.json').read_text())
        assert strict['status'] == 'PASS' and strict['reported_errors'] == strict['uncorroborated_errors'] == 0
        assert 'No errors.' in (directory / 'llvm.txt').read_text()
        cases.append({'role': role, 'sample': sample, 'java': model['java'],
            'runtimeBias': runtime['bias'], 'artifact': hashlib.sha256((directory / 'terminal.dbg').read_bytes()).hexdigest()})
(root / 'acceptance.json').write_text(json.dumps({'status': 'PASS', 'cases': cases,
    'jarSha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
    'compilerEntryLocationValidated': False}, indent=4) + '\n')

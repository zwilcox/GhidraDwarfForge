#!/usr/bin/env python3
"""Require live GDB to reject wrong XMM carriers and overlong incoming-value ranges."""
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('abi', HERE / 'i386-abi-matrix-export.py')
abi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(abi)


def main(base):
    base = base.resolve(strict=True)
    assert json.loads((base / 'result.json').read_text())['status'] in ('PASS', 'CONTROLS_PENDING')
    protected = {str(p): abi.support.digest(p) for p in base.iterdir() if p.is_file()}
    root = Path(tempfile.mkdtemp(prefix='negative.', dir=base))
    image = (base / 'profile.dbg').read_bytes()
    assert image[:6] == b'\x7fELF\x01\x01' and struct.unpack_from('<H', image, 18)[0] == 3
    shoff = struct.unpack_from('<I', image, 32)[0]
    shsize, count, names_index = struct.unpack_from('<HHH', image, 46)
    assert shsize == 40 and 0 < names_index < count
    sections = [struct.unpack_from('<10I', image, shoff + i * shsize) for i in range(count)]
    names_row = sections[names_index]
    names = image[names_row[4]:names_row[4] + names_row[5]]
    row, = [row for row in sections if names[row[0]:].split(b'\0', 1)[0] == b'.debug_loclists']
    section = {'row': row, 'data': image[row[4]:row[4] + row[5]]}
    dies = re.split(r'(?=^\s*<\d+><[0-9a-f]+>:)', (base / 'forge-info.log').read_text(), flags=re.M)
    offsets = {}
    for function in ('vector_add', 'sse_parameters'):
        owner, = [i for i, die in enumerate(dies) if 'DW_TAG_subprogram' in die and
            re.search(r'DW_AT_name\s*:.*\b' + function + r'\s*$', die, re.M)]
        formal = dies[owner + 1]
        assert 'DW_TAG_formal_parameter' in formal and re.search(r'DW_AT_name\s*:\s*a\s*$', formal, re.M)
        at = int(re.search(r'DW_AT_location\s*:\s*(0x[0-9a-f]+) \(location list\)', formal)[1], 16)
        data = section['data']
        assert data[at] == 7 and data[at + 10:at + 12] == b'\x90\x15'
        start, end = struct.unpack_from('<II', data, at + 1)
        assert end - start == (3 if function == 'vector_add' else 4)
        offsets[function] = at
    rows = []
    for function, kind in [(None, 'positive')] + [(fn, kind) for fn in offsets for kind in ('wrong-xmm', 'late-gap')]:
        label = (function + '-' if function else '') + kind
        case = root / label
        case.mkdir()
        for name in ('profile.input', 'profile.reference', 'profile.dbg.c'):
            shutil.copy2(base / name, case / name)
        data = bytearray(image)
        if function:
            offset = section['row'][4] + offsets[function]
            if kind == 'wrong-xmm':
                data[offset + 11] = 22
            else:
                end = struct.unpack_from('<I', data, offset + 5)[0]
                struct.pack_into('<I', data, offset + 5, end + 1)
        (case / 'profile.dbg').write_bytes(data)
        llvm = subprocess.run(['llvm-dwarfdump', '--verify', case / 'profile.dbg'], capture_output=True, timeout=30)
        (case / 'llvm.log').write_bytes(llvm.stdout + llvm.stderr)
        assert llvm.returncode == 0 and not llvm.stderr and b'No errors.' in llvm.stdout
        for name, command in [
                ('gnu', ['readelf', '-hSWn', '--debug-dump=info,abbrev,aranges,decodedline,loc', case / 'profile.dbg']),
                ('strict', [sys.executable, HERE / 'check-dwarfdump.py', case / 'profile.dbg', case / 'strict.txt',
                    '--original', case / 'profile.input', *(['--frame-reference', base / 'profile.sectioned']
                        if (base / 'profile.sectioned').exists() else [])])]:
            abi.support.run(command, case / (name + '.log'), timeout=60)
            abi.support.require_clean(case / (name + '.log'))
        env = dict(os.environ, I386_CASE=str(case), I386_VARIANT='forge')
        env.pop('I386_ABI_FAILED_FUNCTION', None)
        run = subprocess.run(['gdb', '-q', '-nx', '-batch', '-x', HERE / 'i386-abi-matrix-gdb.py'],
            env=env, capture_output=True, timeout=120)
        (case / 'gdb.log').write_bytes(run.stdout)
        (case / 'gdb.stderr').write_bytes(run.stderr)
        result = json.loads((case / 'forge-gdb.json').read_text())
        if function:
            assert run.returncode != 0 and result['status'] == 'FAIL'
            assert result['error'].startswith('AssertionError('), result
            row = result['rows'][-1]
            assert row['function'] == function, row
            if kind == 'wrong-xmm':
                assert row['arguments']['a'] != row['rawArguments']['a'] and 'steps' not in row
            else:
                assert row['arguments'] == row['rawArguments'] and len(row['steps']) == 1
                assert row['steps'][0]['values']['a'] is not None
        else:
            assert run.returncode == 0 and result['status'] == 'PASS' and len(result['rows']) == 11
            pattern = r"(?m)^warning: Function '([a-z_]+)' does not follow the target calling convention, cannot determine its returned value\.\n"
            output, errors = run.stdout.decode(), run.stderr.decode()
            found = re.findall(pattern, output + errors)
            assert len(found) == 6 and set(found) == {'vector_add', 'sse_parameters', 'register_parameters',
                'stdcall_parameters', 'fastcall_parameters', 'thiscall_parameters'}, found
            assert not re.sub(pattern, '', errors).strip()
            assert not re.search(r'(?im)\b(?:warning|error):', re.sub(pattern, '', output))
        rows.append({'case': label, 'status': result['status'], 'artifactSha256': abi.support.digest(case / 'profile.dbg')})
    assert protected == {p: abi.support.digest(Path(p)) for p in protected}
    (root / 'result.json').write_text(json.dumps({'status': 'PASS', 'cases': rows, 'originalsUnchanged': True}, indent=4) + '\n')
    print('i386-abi-matrix-negative=PASS ' + str(root))


if __name__ == '__main__':
    main(Path(sys.argv[1]))

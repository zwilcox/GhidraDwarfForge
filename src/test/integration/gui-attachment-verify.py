#!/usr/bin/env python3
"""Independent receipts/ELF/CRC and fresh GDB checks of the native GUI journey."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zlib


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    work, original = (Path(value).resolve(strict=True) for value in sys.argv[1:3])
    address = int(sys.argv[3], 16)
    require('gui-saved-recovery=PASS' in (work / 'result.txt').read_text(), 'GUI journey did not finish')
    spec = importlib.util.spec_from_file_location('elf_oracle', Path(__file__).with_name('attachment-elf-controller.py'))
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    records = [next((work / (name + '.dbg-records')).glob('forge-attachment-*')) for name in ('initial', 'refreshed')]
    receipts = [json.loads((directory / 'receipt.json').read_text()) for directory in records]
    commands = []

    def run(label, command, env=None):
        result = subprocess.run(list(map(str, command)), cwd=work, env=env, capture_output=True, timeout=90)
        (work / (label + '.stdout')).write_bytes(result.stdout)
        (work / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'label': label, 'argv': list(map(str, command)), 'exit': result.returncode})
        (work / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        require(result.returncode == 0, label + ' failed; inspect retained logs')
        return result.stdout, result.stderr

    empty = work / 'empty-debug-directory'
    empty.mkdir()
    script = work / 'automatic-gdb.py'
    script.write_text('''import gdb, os
name = os.environ['GUI_FUNCTION']
symbol = gdb.lookup_global_symbol(name) or gdb.lookup_static_symbol(name)
if os.environ['GUI_CORRUPT'] == '1':
    assert symbol is None or symbol.symtab is None
    print('GUI_CRC_REJECTED')
else:
    assert symbol is not None and symbol.symtab is not None
    assert int(symbol.value().address) == int(os.environ['GUI_ADDRESS'])
    assert os.path.realpath(symbol.symtab.objfile.filename) == os.path.realpath(os.environ['GUI_SIDECAR'])
    assert os.path.realpath(symbol.symtab.fullname()) == os.path.realpath(os.environ['GUI_SOURCE'])
    print(gdb.execute('ptype ' + name, to_string=True))
    assert name in gdb.execute('list ' + name, to_string=True)
    gdb.Breakpoint(name)
    exits = []
    gdb.events.exited.connect(lambda event: exits.append(event.exit_code))
    gdb.execute('run')
    assert gdb.selected_frame().name() == name
    before = int(gdb.parse_and_eval('$pc'))
    gdb.execute('next')
    assert int(gdb.parse_and_eval('$pc')) != before
    before = int(gdb.parse_and_eval('$pc'))
    gdb.execute('step')
    assert int(gdb.parse_and_eval('$pc')) != before
    gdb.execute('disable breakpoints')
    gdb.execute('continue')
    assert exits == [0], exits
    print('GUI_AUTOMATIC_RUNTIME_PASS')
''')
    for index, (generation, record) in enumerate(zip(('initial', 'refreshed'), receipts)):
        require(record['phase'] == 'COMMITTED' and record['hostContract'] == 'linux-x64-ext4-protected-metadata-v1',
                'GUI did not use the production host/commit')
        target = work / (generation + '-target')
        sidecar = work / (generation + '.dbg')
        source = work / (generation + '.dbg.c')
        for role, path in [('targetAfter', target), ('sidecar', sidecar), ('source', source)]:
            require(record['files'][role]['sha256'] == digest(path), 'receipt byte mismatch: ' + role)
        require(record['files']['originalBackup']['sha256'] == digest(original), 'original receipt binding differs')
        payload, order = oracle.debuglink_payload(target)
        name = sidecar.name.encode()
        offset = (len(name) + 1 + 3) & ~3
        require(payload[:len(name) + 1] == name + b'\0' and not any(payload[len(name) + 1:offset]), 'bad debuglink name/padding')
        require(len(payload) == offset + 4 and struct.unpack_from(order + 'I', payload, offset)[0] ==
                record['debuglinkCrc32'] == zlib.crc32(sidecar.read_bytes()), 'bad target-endian CRC')
        run(generation + '-readelf', ['readelf', '-h', '-S', '-n', '--debug-dump=info', sidecar])
        output, errors = run(generation + '-llvm', ['llvm-dwarfdump', '--verify', sidecar])
        require(b'No errors.' in output and not errors, 'DWARF verification failed')
        run(generation + '-strict', [sys.executable, Path(__file__).with_name('check-dwarfdump.py'),
            sidecar, work / (generation + '-strict.txt'), '--original', original])
        for corrupt in (False, True):
            label = generation + ('-bad-crc' if corrupt else '-gdb')
            directory = work / label
            directory.mkdir()
            selected_target = directory / 'fixture'
            selected_sidecar = directory / sidecar.name
            shutil.copy2(target, selected_target)
            shutil.copy2(sidecar, selected_sidecar)
            if corrupt:
                with selected_sidecar.open('ab') as stream:
                    stream.write(b'GUI negative CRC control')
            env = {**os.environ, 'DEBUGINFOD_URLS': '', 'GUI_FUNCTION': 'gui_recovered_add' if index == 0 else 'gui_refreshed_add',
                'GUI_ADDRESS': str(address), 'GUI_CORRUPT': str(int(corrupt)), 'GUI_SIDECAR': str(selected_sidecar),
                'GUI_SOURCE': str(source)}
            output, errors = run(label, ['gdb', '-nx', '-nh', '-batch', '-iex', 'set debuginfod enabled off',
                '-iex', 'set auto-load off', '-iex', 'set debug-file-directory ' + str(empty),
                '-ex', 'file "' + str(selected_target) + '"', '-ex', 'source ' + str(script)], env)
            if corrupt:
                require(b'GUI_CRC_REJECTED' in output and b'CRC mismatch' in errors, 'CRC refusal missing')
            else:
                require(not errors and b'GUI_AUTOMATIC_RUNTIME_PASS' in output, 'automatic GUI runtime failed')
    require(receipts[0]['debuglinkCrc32'] != receipts[1]['debuglinkCrc32'], 'curation did not change CRC')
    require(receipts[1]['files']['previousReceipt']['sha256'] == digest(records[0] / 'receipt.json'), 'broken receipt chain')
    recovery = json.loads((records[1] / 'recovery-receipt.json').read_text())
    require(recovery['phase'] == 'ROLLED_BACK' and digest(work / 'fixture') == digest(work / 'initial-target'),
            'saved GUI recovery did not restore initial association')
    (work / 'verification.json').write_text(json.dumps({'status': 'PASS', 'checks':
        ['native GUI initial/refresh/recovery', 'retained receipt chain', 'changed target-endian CRC',
         'both pairs GNU/LLVM/pinned libdwarf', 'fresh automatic GDB source/type/break/next/step/exit',
         'both CRC negative controls']}, indent=4) + '\n')
    print('native-gui-attachment-verification=PASS')


if __name__ == '__main__':
    main()

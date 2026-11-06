#!/usr/bin/env python3
"""Check compiler and real Forge semantic fixtures with pinned LLDB 18.1.3."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import shlex
import signal
import socket
import subprocess
import time


SCRIPTS = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_union_diagnostic(reference, original, output):
    """Bind the pinned consumer's union-array limitation to actual compiler DIEs."""
    spec = importlib.util.spec_from_file_location('semantic_dwarf_facts',
        SCRIPTS / 'dynamic-composite-storage-check.py')
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    result = subprocess.run(['readelf', '--debug-dump=info', str(reference)],
        capture_output=True, text=True, check=True)
    assert not result.stderr
    (output / 'compiler-info.txt').write_text(result.stdout)
    with (output / 'compiler-llvm.txt').open('w') as log:
        subprocess.run(['llvm-dwarfdump', '--verify', str(reference)], stdout=log,
            stderr=subprocess.STDOUT, check=True)
    rows = facts.die_records(result.stdout)
    by_offset = {row['offset']: row for row in rows}
    union, = [row for row in rows if row['tag'] == 'DW_TAG_union_type' and facts.facts.die_name(row) == 'word_view']
    member, = [row for row in facts.children(rows, rows.index(union))
        if row['tag'] == 'DW_TAG_member' and facts.facts.die_name(row) == 'bytes']
    assert union['attrs']['DW_AT_byte_size'] == '4'
    assert 'DW_AT_data_member_location' not in member['attrs']

    def referenced_type(row):
        offset = int(re.fullmatch(r'<0x([0-9a-f]+)>', row['attrs']['DW_AT_type'])[1], 16)
        return by_offset[offset]

    array = referenced_type(member)
    assert array['tag'] == 'DW_TAG_array_type'
    bound, = [row for row in facts.children(rows, rows.index(array)) if row['tag'] == 'DW_TAG_subrange_type']
    assert bound['attrs']['DW_AT_upper_bound'] == '3'
    assert bound['attrs'].get('DW_AT_lower_bound', '0') == '0'
    element = referenced_type(array)
    for unused in range(8):
        if element['tag'] != 'DW_TAG_typedef':
            break
        element = referenced_type(element)
    assert element['tag'] == 'DW_TAG_base_type' and element['attrs']['DW_AT_byte_size'] == '1'
    assert 'unsigned char' in element['attrs']['DW_AT_encoding']
    diagnostic = (f"error: {original.name} 0x{member['offset']:08x}: DW_TAG_member 'bytes' "
        f"refers to type 0x{array['offset']:016x} which extends beyond the bounds of 0x{union['offset']:08x}")
    (output / 'compiler-limitation.json').write_text(json.dumps({
        'status': 'CONFIRMED_COMPILER_CONSUMER_LIMITATION', 'expectedDiagnostic': diagnostic,
        'union': union, 'member': member, 'array': array, 'bound': bound, 'element': element,
        'meaning': 'Compiler DWARF describes four bytes. LLDB 18.1.3 drops the extent of this union array.'}, indent=4) + '\n')
    return diagnostic


def check_unavailable_tail(sidecar, entry, boundary, output):
    """The AArch64 fixture's global store ends the proven parameter lifetimes."""
    spec = importlib.util.spec_from_file_location('semantic_location_facts',
        SCRIPTS / 'dynamic-composite-storage-check.py')
    facts = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(facts)
    captures = {}
    for kind in ('info', 'loc'):
        result = subprocess.run(['readelf', '--debug-dump=' + kind, str(sidecar)],
            capture_output=True, text=True, check=True)
        assert not result.stderr
        captures[kind] = result.stdout
        (output / ('forge-' + kind + '.txt')).write_text(result.stdout)
    dies = facts.die_records(captures['info'])
    function, = [row for row in dies if row['tag'] == 'DW_TAG_subprogram' and
        facts.facts.die_name(row) == 'recovered_add']
    lists = {}
    for parameter in facts.children(dies, dies.index(function)):
        name = facts.facts.die_name(parameter)
        if parameter['tag'] != 'DW_TAG_formal_parameter' or name not in ('left', 'right'):
            continue
        offset = int(re.fullmatch(r'0x([0-9a-f]+) \(location list\)',
            parameter['attrs']['DW_AT_location'])[1], 16)
        ranges = []
        for line in captures['loc'].splitlines():
            row = re.fullmatch(r'\s*([0-9a-f]+) ([0-9a-f]+) ([0-9a-f]+) (\(.*\))', line)
            if row and (ranges or int(row[1], 16) == offset):
                ranges.append({'start': int(row[2], 16), 'end': int(row[3], 16), 'expression': row[4]})
            elif ranges and '<End of list>' in line:
                break
        assert ranges and ranges[0]['start'] == entry and ranges[-1]['end'] == boundary
        assert all(entry <= row['start'] < row['end'] <= boundary for row in ranges)
        lists[name] = ranges
    assert set(lists) == {'left', 'right'}
    (output / 'unavailable-tail.json').write_text(json.dumps(lists, indent=4) + '\n')


def run_case(fixtures, target, mode, suffix, output, debugger):
    output.mkdir()
    original = fixtures / 'semantic.exec.stripped'
    reference = fixtures / 'semantic.exec.reference'
    sidecar = fixtures / ('semantic.exec.' + suffix)
    source = Path(str(sidecar) + '.c')
    protected = {str(path): digest(path) for path in (original, reference, sidecar, source)}
    expected_diagnostic = compiler_union_diagnostic(reference, original, output) if mode == 'compiler' else None
    symbols = {}
    for line in subprocess.check_output(['readelf', '-Ws', str(reference)], text=True).splitlines():
        fields = line.split()
        if len(fields) == 8 and fields[7] in (
                'recovered_add', 'forge_stack_normal', 'forge_stack_changed', 'recovered_composite'):
            symbols[fields[7]] = int(fields[1], 16)
    assert len(symbols) == 4
    if mode == 'forge' and target == 'aarch64':
        check_unavailable_tail(sidecar, symbols['recovered_add'], symbols['forge_stack_normal'], output)
    reference_sources = SCRIPTS.parent / 'fixtures'
    config = {'mode': mode, 'target': target, 'symbols': symbols, 'source': str(source),
        'referenceSources': str(reference_sources),
        'observations': str(output / 'observations.json')}
    config_path = output / 'config.json'
    config_path.write_text(json.dumps(config, indent=4) + '\n')
    commands = ['target create ' + shlex.quote(str(original)),
        "script assert lldb.target.FindFunctions('recovered_add').GetSize() == 0",
        'target symbols add --shlib ' + shlex.quote(str(original)) + ' ' +
            shlex.quote(str(sidecar if mode == 'forge' else reference)),
        "script assert lldb.target.FindFunctions('recovered_add').GetSize() == 1"]
    if mode == 'compiler':
        commands.append('settings set target.source-map /ghidra-dwarf-forge-fixture ' +
            shlex.quote(str(reference_sources)))
    commands.extend(['image lookup --name recovered_add', 'source list --name recovered_add',
        'type lookup fixture_state', 'type lookup list_node',
        'script exec(open(' + repr(str(SCRIPTS / 'semantic-lldb-observe.py')) + ').read())',
        'breakpoint set --name recovered_add --skip-prologue ' + ('false' if mode == 'forge' else 'true'),
        'breakpoint set --name recovered_composite --skip-prologue ' + ('false' if mode == 'forge' else 'true')])
    qemu = None
    qlog = None
    try:
        if target == 'aarch64':
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            qcommand = ['qemu-aarch64-static', '-L', '/usr/aarch64-linux-gnu', '-g', str(port), str(original)]
            (output / 'qemu-command.json').write_text(json.dumps(qcommand, indent=4) + '\n')
            qlog = (output / 'qemu.log').open('w')
            qemu = subprocess.Popen(qcommand, stdout=qlog, stderr=subprocess.STDOUT)
            time.sleep(0.2)
            assert qemu.poll() is None, 'QEMU exited before LLDB connected'
            commands.extend(['gdb-remote 127.0.0.1:' + str(port), 'continue'])
        else:
            commands.extend(['settings set target.disable-aslr false', 'run'])
        # Separate command invocations refresh LLDB's selected execution context
        # after each resume. Nested CLI calls inside one Python command can use
        # the entry frame even after SBProcess.Continue() has reached a new stop.
        commands.extend(["script semantic_check('entry')", 'frame variable left right',
            'breakpoint set --address ' + hex(symbols['forge_stack_normal']),
            'breakpoint set --address ' + hex(symbols['forge_stack_changed']),
            'source list', 'thread step-in', "script semantic_check('step')",
            "script semantic_resume_to('forge_stack_normal')", "script semantic_check('normal')",
            'continue', "script semantic_check('changed')", 'continue',
            "script semantic_check('composite')",
            'frame variable ' + ('analyst_composite' if mode == 'forge' else 'first second'),
            'continue', "script semantic_check('exit')"])
        command = [debugger, '--no-lldbinit', '--batch']
        for item in commands:
            command.extend(['-o', item])
        (output / 'command.json').write_text(json.dumps(command, indent=4) + '\n')
        with (output / 'lldb.log').open('w') as log:
            process = subprocess.Popen(command, cwd=output, stdout=log, stderr=subprocess.STDOUT,
                env=dict(os.environ, FORGE_LLDB_SEMANTIC_CONFIG=str(config_path)), start_new_session=True)
            try:
                status = process.wait(timeout=90)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        transcript = (output / 'lldb.log').read_text()
        result_path = output / 'observations.json'
        assert status == 0 and result_path.exists(), transcript[-4000:]
        assert 'Traceback' not in transcript and 'FORGE_LLDB_SEMANTIC_CHECK_PASS exit' in transcript, transcript[-4000:]
        diagnostics = [line for line in transcript.splitlines() if line.startswith(('error:', 'warning:'))]
        assert diagnostics == ([expected_diagnostic] if expected_diagnostic else []), diagnostics
        observations = json.loads(result_path.read_text())
        assert [row['phase'] for row in observations] == ['entry', 'step', 'normal', 'changed', 'composite', 'exit']
        if qemu is not None:
            assert qemu.wait(timeout=5) == 0
        assert protected == {path: digest(Path(path)) for path in protected}
        return {'target': target, 'mode': mode, 'observations': observations, 'protectedSha256': protected,
            'corroboratedCompilerDiagnostic': expected_diagnostic}
    finally:
        if qemu is not None and qemu.poll() is None:
            qemu.terminate()
            try:
                qemu.wait(timeout=5)
            except subprocess.TimeoutExpired:
                qemu.kill()
                qemu.wait()
        if qlog is not None:
            qlog.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixtures', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--lldb', default='lldb-18')
    parser.add_argument('--target', choices=('all', 'x86_64', 'aarch64'), default='all')
    parser.add_argument('--suffix', default='ghidra-forge.dbg')
    parser.add_argument('--mode', choices=('all', 'compiler', 'forge'), default='all')
    args = parser.parse_args()
    assert Path(args.suffix).name == args.suffix and args.suffix.endswith('.dbg')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    version = subprocess.check_output([args.lldb, '--version'], text=True).strip()
    assert version == 'lldb version 18.1.3', version
    targets = ('x86_64', 'aarch64') if args.target == 'all' else (args.target,)
    transport = subprocess.check_output(['qemu-aarch64-static', '--version'], text=True).splitlines()[0] \
        if 'aarch64' in targets else None
    results = []
    for target in targets:
        for mode in (('compiler', 'forge') if args.mode == 'all' else (args.mode,)):
            results.append(run_case(args.fixtures.resolve() / target, target, mode, args.suffix,
                output / (target + '-' + mode), args.lldb))
    (output / 'result.json').write_text(json.dumps({'status': 'PASS_LLDB_SEMANTIC_EXEC',
        'lldb': version, 'transport': transport, 'cases': results,
        'scope': 'Non-PIE source, types, globals, locationless local, changing stack and split GPR values; '
            'does not complete the full LLDB matrix.'}, indent=4) + '\n')
    print('lldb-semantic-exec=PASS')


if __name__ == '__main__':
    main()

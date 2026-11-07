#!/usr/bin/env python3
"""Independent compiler-reference checks for formatter APIs; not Ghidra acceptance."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shlex
import subprocess


def run(command, log, **kwargs):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=90, **kwargs)
    log.write_text(result.stdout)
    assert result.returncode == 0, result.stdout[-6000:]
    assert 'Traceback' not in result.stdout, result.stdout[-6000:]
    assert 'Python Exception' not in result.stdout and 'Error occurred in Python' not in result.stdout, result.stdout[-6000:]
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--lldb', required=True)
    args = parser.parse_args()
    root = args.work.resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[3]
    original = root / 'compiler-reference'
    run(['gcc', '-gdwarf-5', '-O0', '-fno-pie', '-no-pie',
        str(repo / 'src/test/fixtures/formatter-values.c'), '-o', str(original)], root / 'compiler.log')
    digest = hashlib.sha256(original.read_bytes()).hexdigest()
    artifact = {'path': str(original), 'sha256': digest}
    rules = [
        {'key': 'compiler:flags', 'alias': 'forge_flags_witness', 'name': 'ForgeFlags', 'mode': 'flags',
         'size': 4, 'signed': False, 'peers': [], 'flags': [
             {'name': name, 'bits': bits} for name, bits in [
                 ('FORGE_NONE', '0'), ('FORGE_READ', '1'), ('FORGE_READ_ALIAS', '1'),
                 ('FORGE_WRITE', '2'), ('FORGE_BOTH', '3'), ('FORGE_HIGH', '80000000')]]},
        {'key': 'compiler:node', 'alias': 'forge_node_witness', 'name': 'ForgeNode', 'mode': 'structure',
         'size': 24, 'signed': False, 'flags': [], 'peers': []}]
    manifest = {'schema': 1, 'original': artifact, 'sidecar': artifact, 'rules': rules}
    runtime = (repo / 'src/main/resources/ghidradwarfforge/formatters/runtime.py').read_text()
    data = base64.b64encode(json.dumps(manifest).encode()).decode()
    module = root / 'reference_formatters.py'
    module.write_text(runtime + '\nimport base64\nMANIFEST = json.loads(base64.b64decode(' + repr(data) + '))\n' +
        'def __lldb_init_module(debugger, internal_dict):\n    register_lldb(debugger)\n')
    setup = 'import sys; sys.path.insert(0, ' + repr(str(root)) + '); import reference_formatters as fmt; fmt.register_gdb()'
    commands = ['set pagination off', 'break forge_formatter_marker', 'run', 'python ' + setup,
        'print forge_flags', 'print forge_zero', 'print forge_combined', 'print forge_high', 'print forge_node',
        'python assert len(list(gdb.default_visualizer(gdb.parse_and_eval("forge_node")).children())) == 5',
        'python assert "<unavailable>" in fmt._summary(fmt._GdbView(gdb.parse_and_eval("*(struct ForgeNode *)1")))',
        'forge-formatters unload',
        'python assert gdb.default_visualizer(gdb.parse_and_eval("forge_flags")) is None', 'continue']
    argv = ['gdb', '-nx', '-batch', str(original)]
    for command in commands:
        argv.extend(['-ex', command])
    transcript = run(argv, root / 'gdb.log')
    for expected in ['FORGE_READ=FORGE_READ_ALIAS | unknown=0x4', 'FORGE_NONE (raw: 0 / 0x00000000)',
            'FORGE_HIGH', 'a=5', 'b=17', 'value=42', 'unreadable=0x1']:
        assert expected in transcript, (expected, transcript)
    mi = '\n'.join([
        '-enable-pretty-printing', '-break-insert forge_formatter_marker', '-exec-run',
        '-interpreter-exec console ' + json.dumps('python ' + setup),
        '-var-create flags * forge_flags', '-var-create node * forge_node',
        '-var-list-children --all-values node', '-gdb-exit', ''])
    transcript = run(['gdb', '-nx', '--interpreter=mi2', str(original)], root / 'gdb-mi.log', input=mi)
    assert '^error' not in transcript and 'unknown=0x4' in transcript, transcript
    for field in ['a', 'b', 'value', 'next', 'unreadable']:
        assert 'exp="' + field + '"' in transcript, transcript
    commands = ['target create ' + shlex.quote(str(original)), 'settings set target.disable-aslr false',
        'breakpoint set --name forge_formatter_marker', 'run', 'command script import ' + shlex.quote(str(module)),
        'frame variable --show-types forge_flags forge_zero forge_combined forge_high forge_node',
        'script v=lldb.target.FindFirstGlobalVariable("forge_node"); assert v.IsValid() and v.GetNumChildren() == 5',
        'forge-formatters unload',
        'script v=lldb.target.FindFirstGlobalVariable("forge_flags"); assert v.IsValid() and v.GetSummary() is None',
        'continue']
    argv = [args.lldb, '--no-lldbinit', '--batch']
    for command in commands:
        argv.extend(['-o', command])
    transcript = run(argv, root / 'lldb.log')
    for expected in ['unknown=0x4', 'FORGE_NONE (raw: 0 / 0x00000000)', 'a=5', 'b=17', 'value=42']:
        assert expected in transcript, (expected, transcript)
    assert hashlib.sha256(original.read_bytes()).hexdigest() == digest
    (root / 'result.json').write_text(json.dumps({'status': 'PASS_COMPILER_REFERENCE_FORMATTER_APIS',
        'originalSha256': digest, 'gdb': subprocess.check_output(['gdb', '--version'], text=True).splitlines()[0],
        'lldb': subprocess.check_output([args.lldb, '--version'], text=True).strip()}, indent=4) + '\n')
    print('formatter-runtime=PASS compiler reference; GDB CLI/MI and LLDB summaries/native children')


if __name__ == '__main__':
    main()

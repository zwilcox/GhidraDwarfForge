#!/usr/bin/env python3
"""Require cold GDB lookup; never pre-expand CU symbols with info functions."""
import argparse
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('original', type=Path)
parser.add_argument('sidecar', type=Path)
parser.add_argument('--isolated', action='store_true')
parser.add_argument('--unbound', action='store_true')
parser.add_argument('--variant', choices=['normal', 'collision', 'ambiguous', 'unbound-collision'], default='normal')
args = parser.parse_args()
canonical = 'StoredCounter' if args.isolated else 'Counter'
namespace = 'outer' if args.isolated else 'recovered'
method = 'method' if args.isolated else 'inspect_object'
queries = [('ptype struct ' + canonical, ['int value;', 'int ' + method + '(int);']),
    ("ptype '" + namespace + "::Counter'", ['int value;', 'int ' + method + '(int);']),
    ("ptype '" + namespace + '::Counter::' + method + "'", ['type = int (', canonical + ' *, int)'])]
if args.unbound:
    assert not args.isolated
    queries[0] = ('ptype struct Counter', ['int value;'])
    queries[1] = ("ptype 'recovered::Counter'", ['Counter'])
if args.isolated:
    queries.append(("ptype 'outer::Counter::Nested::static_method'", ['type = int (int)']))
    queries.append(("ptype 'outer::Counter::Nested'", ['static int static_method(int);']))
    if args.variant == 'unbound-collision':
        queries[-1] = ("ptype struct 'outer::Counter::Nested'", ['int first;', 'int second;'])
        queries.append(('ptype __ghidra_class_scope_3', ['static int static_method(int);']))
    if args.variant in ['normal', 'unbound-collision']:
        queries.append(('ptype Counter', ['int value;', 'int method(int);']))
    elif args.variant == 'collision':
        queries.append(('ptype struct Counter', ['int first;', 'int second;']))
    else:
        queries.append(("ptype 'other::Counter'", ['int first;', 'int second;']))
else:
    assert args.variant == 'normal'
results = []
for query, fragments in queries:
    command = ['gdb-multiarch', '-nx', '-batch', '-ex', 'set debuginfod enabled off',
        '-ex', 'set auto-solib-add off', '-ex', 'file ' + json.dumps(str(args.original.resolve())),
        '-ex', 'symbol-file ' + json.dumps(str(args.sidecar.resolve())), '-ex', 'set language c', '-ex', query]
    result = subprocess.run(command, text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, (query, result.returncode, result.stdout, result.stderr)
    assert not result.stderr, result.stderr
    assert all(fragment in result.stdout for fragment in fragments), (query, result.stdout)
    if args.unbound and query == "ptype 'recovered::Counter'":
        assert 'int value;' not in result.stdout and 'int first;' not in result.stdout
    if args.variant == 'unbound-collision' and query == 'ptype __ghidra_class_scope_3':
        assert 'int first;' not in result.stdout and 'int second;' not in result.stdout
    results.append({'query': query, 'output': result.stdout})
if args.variant == 'ambiguous':
    command[-1] = 'ptype Counter'
    result = subprocess.run(command, text=True, capture_output=True, timeout=30)
    assert result.returncode != 0 and not result.stdout
    assert result.stderr.strip() == 'No symbol "Counter" in current context.', result.stderr
    results.append({'query': 'ptype Counter', 'expectedUnavailable': result.stderr.strip()})
print(json.dumps({'status': 'CLASS_FIRST_LOOKUP_PASS', 'freshDebuggerProcesses': len(results), 'results': results}, indent=4))

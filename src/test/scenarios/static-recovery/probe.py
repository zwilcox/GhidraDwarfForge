#!/usr/bin/env python3
"""Probe static identity/type APIs; this does not validate exporter behavior.

Supply one x86-64 and one AArch64 case created by lexical-statics-export.py.
The existing compiler oracle and prepared program are checked before use.
Every mutation is confined to a headless read-only session.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def snapshot(project):
    return {str(p): digest(p) for p in sorted(project.rglob('*'))
        if p.is_file() and not p.name.endswith('.lock')}


def inspect(record, mode):
    require(record['mode'] == mode and record['javaVersion'].startswith('21.'), 'mode/Java baseline')
    require(record['bindingBefore'] == 'VALID', 'prepared explicit static identity')
    require(record['bindingAfter'] == ('VALID' if mode == 'typed' else
        'REJECTED' if mode == 'stale' else 'ABSENT'), 'absent and stale evidence must differ')
    require(record['dataDefined'] == (mode == 'typed'), 'listing type precondition')
    globals_ = [s for s in record['symbols'] if s['map'] == 'global']
    require(len(globals_) == 1, 'unique referenced object')
    symbol = globals_[0]
    require(symbol['global'] and symbol['highKind'] == 'HighGlobal', 'map does not establish ownership')
    require(symbol['highType'] == '/int' and symbol['highSize'] == 4, 'inferred integer access')
    require(symbol['memoryStorage'] and symbol['wholeMapping'], 'memory map')
    expected = '(ram, 0x' + format(int(record['objectAddress'], 16), 'x') + ', 4)'
    require(symbol['representative'] == expected and symbol['instances'] and
        all(value == expected for value in symbol['instances']), 'whole accessed memory identity')
    owned = mode in ('typed', 'undefined', 'stale', 'local')
    require((symbol['namespaceId'] == record['functionId']) == owned, 'actual function identity')
    require(symbol['namespaceKind'] == ('FUNCTION' if owned else 'NAMESPACE'), 'namespace kind')
    require(symbol['symbolType'] == ('/int' if mode in ('typed', 'local') else '/undefined'),
        'saved map type differs from inferred type')
    require(symbol['offset'] == (-1 if mode in ('typed', 'local') else 0), 'whole versus undefined map offset')
    locals_ = [s for s in record['symbols'] if s['map'] == 'local']
    require(len(locals_) == int(owned), 'local map mirrors actual owner only')
    if mode == 'local':
        require(symbol['savedSymbol'] == 'Local Var' and symbol['savedName'] == 'inferred_static'
            and symbol['savedSource'] == 'ANALYSIS', 'saved memory local identity')
        require(locals_[0]['id'] == symbol['id'] and locals_[0]['name'] == 'inferred_static', 'map identity')
    elif mode != 'unowned':
        require(symbol['id'] == record['originalSymbolId'] and symbol['savedName'] == 'saved_other',
            'retained saved label identity')
    else:
        require(symbol['namespaceId'] == 0 and symbol['savedSource'] == 'DEFAULT', 'dynamic unowned object')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('cases', type=Path, nargs=2)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar'
    protected = {str(p): digest(p) for p in [module, *sorted(source.glob('*.java')), Path(__file__).resolve()]}
    inputs = []
    for directory in args.cases:
        case = directory.resolve(strict=True)
        accepted = json.loads((case / 'acceptance.json').read_text())
        require(accepted['status'] == 'LEXICAL_STATICS_PASS', 'accepted fixture required')
        for path, value in accepted['protected'].items():
            require(digest(Path(path)) == value, 'fixture protected input changed: ' + path)
        objects = json.loads((case / 'compiler-objects.json').read_text())
        require(objects, 'compiler memory-object oracle required')
        protected.update({str(p): digest(p) for p in [case / 'reference', case / 'stripped',
            case / 'acceptance.json', case / 'prepared.json', case / 'compiler-objects.json']})
        inputs.append((accepted['target'], case))
    require({target for target, _ in inputs} == {'x86_64', 'aarch64'}, 'both runtime targets required')

    def probe(item):
        target, case = item
        project = case / 'project'
        before = snapshot(project)
        rows = []
        for mode in ['typed', 'undefined', 'stale', 'namespace', 'unowned', 'local']:
            name = target + '-' + mode
            observation = output / (name + '.json')
            command = [str(ghidra / 'support/analyzeHeadless'), str(project), 'Statics',
                '-process', 'stripped', '-readOnly', '-noanalysis', '-scriptPath', str(source),
                '-postScript', 'InspectStaticRecovery.java', mode, str(observation)]
            (output / (name + '-command.json')).write_text(json.dumps(command, indent=4) + '\n')
            with (output / (name + '.log')).open('w') as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=180)
            require('static-recovery-probe=PASS' in (output / (name + '.log')).read_text(), 'script must complete')
            record = json.loads(observation.read_text())
            inspect(record, mode)
            rows.append({'target': target, 'mode': mode, 'sha256': digest(observation)})
            print(name + ' PASS', flush=True)
        after = snapshot(project)
        changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
        allowed = {str(project / 'Statics.rep/idata' / name) for name in ['~index.bak', '~journal.bak']}
        require(changed <= allowed, 'read-only program changed: ' + str(changed))
        (output / (target + '-project.json')).write_text(json.dumps({
            'before': before, 'after': after, 'backupChanges': sorted(changed)}, indent=4) + '\n')
        return rows

    with ThreadPoolExecutor(max_workers=2) as pool:
        observations = [row for rows in pool.map(probe, inputs) for row in rows]
    archive = ghidra / 'Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip'
    with zipfile.ZipFile(archive) as zipped:
        apis = {name: hashlib.sha256(zipped.read('ghidra/program/model/pcode/' + name + '.java')).hexdigest()
            for name in ['HighSymbol', 'HighVariable', 'HighCodeSymbol', 'HighGlobal', 'GlobalSymbolMap', 'LocalSymbolMap']}
    require(protected == {p: digest(Path(p)) for p in protected}, 'protected inputs changed')
    receipt = {'status': 'STATIC_RECOVERY_RESEARCH_PASS', 'exporterAcceptance': False,
        'observations': observations, 'protected': protected, 'apiArchiveSha256': digest(archive), 'apiSources': apis,
        'remaining': 'Implement recovered type/identity policy and prove emitted artifacts in GDB.'}
    (output / 'acceptance.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print('static recovery research PASS; exporter acceptance remains required')


if __name__ == '__main__':
    main()

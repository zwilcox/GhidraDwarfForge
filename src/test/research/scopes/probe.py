#!/usr/bin/env python3
"""Inspect Ghidra 12.0.3 evidence; this is not an exporter acceptance test."""
import argparse
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    ghidra = args.ghidra.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).resolve().parent
    repository = source.parents[3]
    protected = {str(path): digest(path) for path in sorted(source.iterdir()) if path.is_file()}
    commands = []

    def run(name, command, timeout=240):
        commands.append({'name': name, 'argv': list(map(str, command))})
        (output / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        with (output / (name + '.log')).open('w') as log:
            subprocess.run(list(map(str, command)), stdout=log, stderr=subprocess.STDOUT,
                check=True, timeout=timeout)

    evidence = []
    for target, compiler, stripper in [('x86_64', 'g++', 'strip'),
            ('aarch64', 'aarch64-linux-gnu-g++', 'aarch64-linux-gnu-strip')]:
        case = output / target
        case.mkdir()
        reference, stripped = case / 'reference', case / 'stripped'
        run(target + '-compile', [compiler, '-g', '-gdwarf-5', '-O0', '-fno-omit-frame-pointer',
            '-fno-pie', '-no-pie', source / 'scope-evidence.cpp', '-o', reference])
        run(target + '-strip', [stripper, '--strip-all', '-o', stripped, reference])
        before = {str(path): digest(path) for path in [reference, stripped]}
        run(target + '-llvm', ['llvm-dwarfdump', '--verify', reference])
        run(target + '-dwarf', ['readelf', '--debug-dump=info', reference])
        run(target + '-gdb', ['bash', source / 'compiler-gdb.sh', repository, case, target])
        oracle = json.loads((case / 'compiler-gdb.json').read_text())
        require([row['shadow'] for row in oracle] == [11, 23, 11], 'shadow values')
        require(all(row['value'] == 7 and row['visits'] == 1 for row in oracle), 'this and static')
        inner = oracle[1]['blocks'][0]
        require('shadow' in inner['locals'], 'inner lexical declaration')
        require(inner['start'] > oracle[0]['blocks'][0]['start'], 'nested lexical start')
        require(inner['end'] < oracle[0]['blocks'][0]['end'], 'nested lexical end')
        for variant in ('reference', 'stripped'):
            binary = case / variant
            project = case / (variant + '-project')
            project.mkdir()
            observation = case / (variant + '.json')
            name = target + '-' + variant
            run(name, [ghidra / 'support/analyzeHeadless', project, 'Scope', '-import', binary,
                '-loader', 'ElfLoader', '-analysisTimeoutPerFile', '120', '-scriptPath', source,
                '-postScript', 'InspectScopeEvidence.java', observation])
            require('SCOPE_EVIDENCE_PROBE_PASS' in (output / (name + '.log')).read_text(), 'headless script did not finish')
            record = json.loads(observation.read_text())
            require(record['javaVersion'].startswith('21.'), 'actual Java 21 required for this probe')
            methods = [f for f in record['functions'] if 'inspect_scope' in f['name']]
            if variant == 'reference':
                require(len(methods) == 1, 'imported method identity')
                method = methods[0]
                require([p['kind'] for p in method['owners']] == ['CLASS', 'NAMESPACE'], 'class parent')
                require(method['convention'] == '__thiscall', 'selected convention')
                parameters = [v for v in method['savedVariables'] if v.get('autoKind') == 'THIS']
                require(len(parameters) == 1 and parameters[0].get('symbolId') is None, 'automatic THIS has no database symbol')
                require(parameters[0]['type'].endswith('/recovered/Counter *'), 'typed object pointer')
                shadows = [v for v in method['savedVariables'] if v['name'] in ['shadow', 'shadow_1']]
                require(len(shadows) == 2 and all(v['firstUse'] == 0 for v in shadows), 'flattened saved local starts')
                require(all(v['owners'][0]['kind'] == 'FUNCTION' for v in shadows), 'flattened saved ownership')
                high = [v for v in method['highSymbols'] if v['name'] in ['shadow', 'shadow_1']]
                require(len(high) == 2 and all(v['firstMappingAddress'] == 'null' for v in high), 'high mappings lack lexical endpoints')
                same = [t for t in record['types'] if t['path'].endswith('/Same')]
                require(len(same) == 2 and {t['size'] for t in same} == {4, 8}, 'distinct same-name types')
                statics = [v for v in record['objects'] if v['name'] == 'visits']
                require(len(statics) == 1 and statics[0]['owners'][0]['kind'] == 'NAMESPACE', 'imported static has only plain namespace ownership')
                require(statics[0]['owners'][0]['id'] != method['symbolId'], 'same-name namespace is not function identity')
                require(statics[0]['type'].endswith('/int'), 'typed static object')
            else:
                require(not methods and not record['types'], 'stripped input must not invent source scopes/types')
            evidence.append({'target': target, 'variant': variant, 'observationSha256': digest(observation),
                'binarySha256': digest(binary), 'javaVersion': record['javaVersion']})
        require(before == {path: digest(Path(path)) for path in before}, 'original binary changed')

    apis = {}
    for relative, names in {
            'Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip': [
                'ghidra/program/model/pcode/LocalSymbolMap.java',
                'ghidra/program/model/pcode/HighFunction.java',
                'ghidra/program/model/pcode/HighSymbol.java',
                'ghidra/program/model/listing/GhidraClass.java'],
            'Ghidra/Features/Base/lib/Base-src.zip': [
                'ghidra/app/util/bin/format/dwarf/DWARFFunctionImporter.java']}.items():
        archive = ghidra / relative
        with zipfile.ZipFile(archive) as zipped:
            apis[relative] = {'sha256': digest(archive), 'sources': {
                name: hashlib.sha256(zipped.read(name)).hexdigest() for name in names}}
    require(protected == {path: digest(Path(path)) for path in protected}, 'probe source changed')
    receipt = {'status': 'RESEARCH_OBSERVATION_PASS', 'exporterAcceptance': False,
        'originalsUnchanged': True, 'cases': evidence, 'probeSources': protected, 'apis': apis,
        'remaining': 'Implement evidence-backed lexical/class model and validate real exporter behavior.'}
    (output / 'acceptance.json').write_text(json.dumps(receipt, indent=4) + '\n')
    print('scope evidence research PASS: four imports, two compiler GDB oracles; no exporter acceptance')


if __name__ == '__main__':
    main()

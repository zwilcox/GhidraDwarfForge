#!/usr/bin/env python3
"""Compare isolated global DIE layouts; this is not production acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ghidra', type=Path)
    parser.add_argument('jdk', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    root = directory.parents[3]
    ghidra, jdk = args.ghidra.resolve(strict=True), args.jdk.resolve(strict=True)
    module = ghidra / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    native = module / 'os/linux_x86_64'
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    production = root / 'src/main/java/ghidradwarfforge/nativeapi/MinimalDwarfSidecarExporter.java'
    # Preserve the pre-fix exporter as the experiment baseline even after the
    # production implementation changes. Its source is in repository history.
    baseline_commit = 'ad8f5fb3c854ffe99e393f33a6d66173fe20413c'
    text = subprocess.check_output(['git', 'show', baseline_commit + ':' + production.relative_to(root).as_posix()], cwd=root, text=True)
    (out / 'baseline-exporter.java').write_text(text)
    start = text.index('                for (ProgramTypeModel.GlobalVariable global : typeModel.globals()) {')
    stop = text.index('\n            }\n            for (var alias : aliases)', start)
    original = text[start:stop]
    required = 'namespaceParent(global.namespace(), namespaceDies, unit), errorOut);'
    assert required in original
    variants = {'baseline': original}
    variants['imported-qualified'] = original.replace('                    if (global.declaration()) {', '''                    if (!global.namespace().isEmpty()) {
                        Die alias = newDie(producer, consumer, debug, DW_TAG_IMPORTED_DECLARATION, unit, errorOut);
                        addName(producer, consumer, alias, String.join("::", global.namespace()) + "::" + global.name(), errorOut);
                        addReference(producer, consumer, debug, alias, DW_AT_IMPORT, die, errorOut);
                    }
                    if (global.declaration()) {''')
    variants['qualified-name'] = original.replace('addName(producer, consumer, die, global.name(), errorOut);',
        'addName(producer, consumer, die, global.namespace().isEmpty() ? global.name() : String.join("::", global.namespace()) + "::" + global.name(), errorOut);')
    root_spec = original.replace('                    if (global.declaration()) {', '''                    if (!global.namespace().isEmpty() && !global.declaration()) {
                        addFlag(producer, consumer, debug, die, DW_AT_DECLARATION, true, errorOut);
                        Die declaration = die;
                        die = newDie(producer, consumer, debug, DW_TAG_VARIABLE, unit, errorOut);
                        addName(producer, consumer, die, String.join("::", global.namespace()) + "::" + global.name(), errorOut);
                        addReference(producer, consumer, debug, die, DW_AT_SPECIFICATION, declaration, errorOut);
                    }
                    if (global.declaration()) {''')
    variants['root-spec'] = root_spec
    variants['root-spec-import'] = root_spec.replace('                        addReference(producer, consumer, debug, die, DW_AT_SPECIFICATION, declaration, errorOut);', '''                        addReference(producer, consumer, debug, die, DW_AT_SPECIFICATION, declaration, errorOut);
                        if (global.name().equals("unique_value")) {
                            Die alias = newDie(producer, consumer, debug, DW_TAG_IMPORTED_DECLARATION, unit, errorOut);
                            addName(producer, consumer, alias, global.name(), errorOut);
                            addReference(producer, consumer, debug, alias, DW_AT_IMPORT, die, errorOut);
                        }''')
    variants['root-qualified'] = variants['qualified-name'].replace(required, 'unit, errorOut);')
    variants['root-spec-type'] = root_spec.replace('                        addReference(producer, consumer, debug, die, DW_AT_SPECIFICATION, declaration, errorOut);', '''                        addReference(producer, consumer, debug, die, DW_AT_SPECIFICATION, declaration, errorOut);
                        addTypeReference(producer, consumer, debug, die, global.type(), typeModel.types(), allocatedTypes, errorOut);''')
    variants['root-spec-external'] = root_spec.replace('                        addReference(producer, consumer, debug, die, DW_AT_SPECIFICATION, declaration, errorOut);', '''                        addReference(producer, consumer, debug, die, DW_AT_SPECIFICATION, declaration, errorOut);
                        addFlag(producer, consumer, debug, die, DW_AT_EXTERNAL, true, errorOut);''')
    variants['root-qualified-import'] = variants['root-qualified'].replace('                    if (global.declaration()) {', '''                    if (!global.namespace().isEmpty()) {
                        Die alias = newDie(producer, consumer, debug, DW_TAG_IMPORTED_DECLARATION,
                            namespaceParent(global.namespace(), namespaceDies, unit), errorOut);
                        if (typeModel.globals().stream().filter(g -> g.name().equals(global.name())).count() == 1) {
                            addName(producer, consumer, alias, global.name(), errorOut);
                        }
                        addReference(producer, consumer, debug, alias, DW_AT_IMPORT, die, errorOut);
                    }
                    if (global.declaration()) {''')
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    protected = {str(p): sha(p) for p in [production, jar, *directory.iterdir()] if p.is_file()}
    commands = []
    def run(label, command, required=True):
        command = list(map(str, command))
        commands.append({'label': label, 'argv': command})
        (out / 'commands.json').write_text(json.dumps(commands, indent=4) + '\n')
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        (out / (label + '.log')).write_text(result.stdout)
        (out / (label + '.stderr')).write_text(result.stderr)
        if required:
            assert result.returncode == 0, (label, result.stderr)
        return result
    common = [jar, *sorted(p for p in ghidra.rglob('*.jar') if 'Extensions' not in p.parts)]
    classes = {}
    for variant, replacement in variants.items():
        folder = out / variant
        folder.mkdir()
        copy = folder / production.name
        copy.write_text(text[:start] + replacement + text[stop:])
        cp = ':'.join(map(str, [folder, *common]))
        run(variant + '-compile-java', [jdk / 'bin/javac', '--release', '21', '-proc:none', '-cp', cp,
            '-d', folder, copy, directory / 'NamespaceGlobalProducer.java'])
        classes[variant] = cp
    results = []
    for target, prefix in [('x86_64', ''), ('aarch64', 'aarch64-linux-gnu-')]:
        case = out / target
        case.mkdir()
        run(target + '-compile', [prefix + 'g++', '-O0', '-g', '-gdwarf-5', '-fno-pie', '-no-pie', directory / 'fixture.cpp', '-o', case / 'reference'])
        run(target + '-strip', [prefix + 'objcopy', '--strip-all', case / 'reference', case / 'input'])
        nm = run(target + '-symbols', [prefix + 'nm', '-S', '-C', case / 'reference']).stdout
        symbols = {}
        for line in nm.splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[3] in ['left::item', 'right::item', 'left::unique_value', 'item', 'marker']:
                symbols[fields[3]] = int(fields[0], 16)
                if fields[3] == 'marker':
                    symbols['marker.size'] = int(fields[1], 16)
        assert len(symbols) == 6
        (case / 'symbols.json').write_text(json.dumps(symbols, indent=4) + '\n')
        protected.update({str(p): sha(p) for p in [case / 'reference', case / 'input']})
        for variant, cp in classes.items():
            label = target + '-' + variant
            artifact = case / (variant + '.dbg')
            produced = run(label + '-producer', [jdk / 'bin/java', '--enable-native-access=ALL-UNNAMED', '-cp', cp,
                'ghidradwarfforge.nativeapi.NamespaceGlobalProducer', native / 'libdwarf.so.2.3.2',
                native / 'libdwarfp.so.2.3.2', case / 'input', artifact, case / 'symbols.json'])
            assert 'PASS java=21.' in produced.stdout and str(out / variant) in produced.stdout
            run(label + '-info', ['readelf', '--debug-dump=info', artifact])
            verified = run(label + '-verify', ['llvm-dwarfdump', '--verify', artifact], required=False)
            queries = []
            for name in ['left::item', 'right::item', 'left::unique_value', 'unique_value', 'item', 'left::missing']:
                cmd = ['gdb-multiarch', '-q', '-nx', '-batch', '-ex', 'set debuginfod enabled off', '-ex',
                    'set auto-solib-add off', '-ex', 'file ' + str(case / 'input'), '-ex', 'symbol-file ' + str(artifact),
                    '-ex', 'set language c', '-ex', "ptype '" + name + "'", '-ex', "print &'" + name + "'"]
                observed = run(label + '-query-' + name, cmd, required=False)
                queries.append({'name': name, 'exit': observed.returncode, 'stdout': observed.stdout, 'stderr': observed.stderr})
            results.append({'target': target, 'variant': variant, 'llvmExit': verified.returncode, 'queries': queries})
            print(label + ' OBSERVED', flush=True)
    acceptance = []
    for target in ['x86_64', 'aarch64']:
        selected_observation, = [row for row in results if row['target'] == target and row['variant'] == 'root-qualified-import']
        assert selected_observation['llvmExit'] == 0
        for query in selected_observation['queries']:
            if query['name'] == 'left::missing':
                assert 'type = int' in query['stdout'] and query['exit'] != 0
            elif query['name'] == 'unique_value':
                # C11 namespace imports expose the short name after CU expansion;
                # only the fully qualified spelling is guaranteed on cold lookup.
                assert query['exit'] != 0 and 'No symbol "unique_value"' in query['stderr']
            else:
                assert query['exit'] == 0 and 'type = int' in query['stdout'], query
        case = out / target
        artifact = case / 'root-qualified-import.dbg'
        strict = run(target + '-selected-strict', ['python3', root / 'src/test/integration/check-dwarfdump.py',
            artifact, case / 'selected-strict.log', '--original', case / 'input'])
        for mode in ['compiler', 'selected']:
            observed = run(target + '-' + mode + '-runtime', ['bash', directory / 'runtime.sh', case, target, mode])
            assert 'namespace-global-runtime=' + mode + ' PASS' in observed.stdout
        compiler = json.loads((case / 'compiler-runtime.json').read_text())
        selected = json.loads((case / 'selected-runtime.json').read_text())
        assert compiler['values'] == selected['values'] and compiler['addresses'] == selected['addresses']
        assert selected['shortUnique'] == 41 and selected['return'] == compiler['return'] == 140
        acceptance.append({'target': target, 'compiler': compiler, 'selected': selected})
    assert protected == {p: sha(Path(p)) for p in protected}
    (out / 'observations.json').write_text(json.dumps({'status': 'OBSERVATIONS_ONLY', 'protected': protected,
        'results': results, 'productionAcceptance': False, 'selectedRuntime': acceptance, 'baselineCommit': baseline_commit,
        'baselineSourceSha256': sha(out / 'baseline-exporter.java')}, indent=4) + '\n')


if __name__ == '__main__':
    main()

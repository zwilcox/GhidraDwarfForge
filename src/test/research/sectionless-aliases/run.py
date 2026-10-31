#!/usr/bin/env python3
"""Research sectionless alias packaging using existing accepted alias fixture artifacts.

This does not enable the production alias planner, import a sectionless program,
or establish support for any new target. It isolates ELF/GDB consumer behavior.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from inventory import Inventory, Unsupported
from mirror import merge

source = Path(__file__).resolve().parent
repository = source.parents[3]
integration = repository / 'src/test/integration'
spec = importlib.util.spec_from_file_location('fixtures', source / 'inventory-fixtures.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ghidra', type=Path, required=True)
    parser.add_argument('--base-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix='consumer.', dir=args.output.resolve()))
    module = args.ghidra.resolve() / 'Ghidra/Extensions/GhidraDwarfForge'
    jar = module / 'lib/GhidraDwarfForge.jar'
    java = Path(os.environ['FORGE_JAVA21_HOME']) / 'bin/java'
    javac = Path(os.environ['JAVA_HOME']) / 'bin/javac'
    classes = root / 'classes'
    classes.mkdir()
    protected = {str(p): digest(p) for p in module.rglob('*') if p.is_file()}
    protected.update({str(p): digest(p) for p in source.glob('*') if p.is_file()})
    protected.update({str(integration / name): digest(integration / name) for name in
        ('local-symbol-merge-gdb.py', 'local-symbol-merge-gdb.sh', 'qemu-socket.sh',
         'elf-layout-gdb-oracle.sh', 'check-dwarfdump.py')})

    def run(case, name, command, expected=0):
        command = list(map(str, command))
        (case / (name + '.command.json')).write_text(json.dumps(command, indent=4) + '\n')
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        (case / (name + '.log')).write_bytes(result.stdout)
        (case / (name + '.stderr')).write_bytes(result.stderr)
        if expected is not None:
            assert result.returncode == expected and not result.stderr, (name, result.returncode, result.stderr)
        return result

    run(root, 'compile', [javac, '--release', '21', '-cp', jar, '-d', classes,
        source / 'SectionlessSymbolProbe.java'])
    protected.update({str(p): digest(p) for p in classes.rglob('*.class')})
    cases = []
    for path in sorted(args.base_root.resolve().glob('*/metadata.json')):
        base = path.parent
        metadata = json.loads(path.read_text())
        if metadata['inputSymbols'] != 'stripped':
            continue
        assert json.loads((base / 'result.json').read_text())['status'] == 'PASS'
        assert json.loads((base / 'result.json').read_text())['jarSha256'] == digest(jar)
        compiler = Path(json.loads((base / 'gdb-driver.command.json').read_text())[-1])
        assert compiler.is_file()
        protected.update({str(p): digest(p) for p in base.glob('*') if p.is_file()})
        protected[str(compiler)] = digest(compiler)
        case = root / base.name
        case.mkdir()
        binary = case / 'aliases.input'
        fixtures.sectionless(base / 'aliases.input', binary)
        protected[str(binary)] = digest(binary)
        metadata['input'] = str(binary)
        (case / 'metadata.json').write_text(json.dumps(metadata, indent=4) + '\n')
        command = [java, '-cp', str(classes) + os.pathsep + str(jar),
            'ghidradwarfforge.elf.SectionlessSymbolProbe', binary,
            base / 'baseline.dbg', base / 'symbols.tsv']
        result = run(case, 'writer', [*command, case / 'unmirrored.dbg'])
        text = result.stdout.decode()
        assert 'java=21.' in text and jar.as_uri() in text.replace('file:/', 'file:///')
        shutil.copyfile(case / 'unmirrored.dbg', case / 'aliases.dbg')
        oracle = ['bash', integration / 'local-symbol-merge-gdb.sh', repository, case,
            metadata['target'], compiler]
        negative = run(case, 'unmirrored-gdb', oracle, expected=None)
        shutil.copyfile(case / 'forge-gdb.log', case / 'unmirrored-forge-gdb.log')
        lost_names = metadata['target'].startswith('mips') and metadata['role'] != 'exec'
        if lost_names:
            assert negative.returncode != 0 and 'No symbol "_ZN8observed6uniqueEi"' in (case / 'forge-gdb.log').read_text()
        else:
            assert negative.returncode == 0 and not negative.stderr
        row = {'case': str(case), 'target': metadata['target'], 'role': metadata['role'],
            'unmirroredLostNames': lost_names}
        try:
            inventory = merge(binary, case / 'unmirrored.dbg', case / 'aliases.dbg')
        except Unsupported as error:
            assert 'empty GNU hash' in str(error)
            row.update(status='EXPLICIT_COUNT_UNAVAILABLE', diagnostic=str(error))
        else:
            _, _, original = fixtures.elf_support.elf(base / 'aliases.input')
            assert inventory.raw == original['.dynsym'][1]
            assert inventory.strings == original['.dynstr'][1]
            merge(binary, case / 'unmirrored.dbg', case / 'repeat.dbg')
            assert digest(case / 'aliases.dbg') == digest(case / 'repeat.dbg')
            for option in ('info', 'abbrev', 'aranges', 'decodedline'):
                run(case, option, ['readelf', '--debug-dump=' + option, case / 'aliases.dbg'])
            run(case, 'headers', ['readelf', '-hSWs', case / 'aliases.dbg'])
            result = run(case, 'llvm', ['llvm-dwarfdump', '--verify', case / 'aliases.dbg'])
            assert b'No errors.' in result.stdout
            run(case, 'strict', ['python3', integration / 'check-dwarfdump.py', case / 'aliases.dbg',
                case / 'strict-checks.log', '--original', binary])
            run(case, 'mirrored-gdb', oracle)
            result = json.loads((case / 'forge-gdb.json').read_text())
            assert result['status'] == 'PASS' and len(result['calls']) == 4
            row.update(status='EXPERIMENTAL_MIRROR_PASS', countSources=inventory.counts,
                records=inventory.count, remapped=inventory.changes, sidecarSha256=digest(case / 'aliases.dbg'))
        cases.append(row)
        print(metadata['target'], metadata['role'], row['status'], flush=True)
    assert len(cases) == 12 and len({(c['target'], c['role']) for c in cases}) == 12
    assert sum(c['status'] == 'EXPERIMENTAL_MIRROR_PASS' for c in cases) == 8
    assert sum(c['unmirroredLostNames'] for c in cases) == 4
    assert all(digest(Path(p)) == h for p, h in protected.items())
    (root / 'result.json').write_text(json.dumps({'status': 'CONSUMER_RESEARCH_PASS',
        'scope': 'Independent experimental packaging; no production sectionless-alias acceptance',
        'jarSha256': digest(jar), 'cases': cases, 'protected': protected}, indent=4) + '\n')
    print(root, flush=True)


if __name__ == '__main__':
    main()

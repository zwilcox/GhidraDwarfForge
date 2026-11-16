"""Bind static-scope coverage to the complete existing compiler/debugger oracles."""
import hashlib
import json
from pathlib import Path


def sources():
    repository = Path(__file__).resolve().parents[3]
    harness = repository / 'src/test/integration'
    paths = [*harness.glob('lexical-statics*'), harness / 'recovered-statics-export.py',
        harness / 'integration_coverage.py', Path(__file__), harness / 'qemu-socket.sh',
        harness / 'check-lexical-statics.py', harness / 'check-code-address-index.py',
        harness / 'check-dwarfdump.py', repository / 'src/test/fixtures/lexical-statics.c',
        repository / 'src/test/java/ghidradwarfforge/nativeapi/StaticScopeSmoke.java']
    paths += [harness / 'ghidra_scripts' / name for name in (
        'PrepareLexicalStatics.java', 'PrepareRecoveredStatics.java', 'PrepareStaticControl.java',
        'StaticDecompilerFailureExport.java', 'CancelDuringElfCopy.java', 'RebaseFixtureProgram.java')]
    return {str(path.relative_to(repository)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(set(paths))}


def finish(collection, case, result, source_hashes, status, measurement):
    if not collection.enabled:
        return
    if sources() != source_hashes:
        raise ValueError('static scope test sources changed during measurement')
    evidence = {**result, 'status': status, 'oracleStatus': result['status'],
        'harnessSha256': source_hashes, 'measurement': measurement,
        'compilerObjects': json.loads((case / 'compiler-objects.json').read_text()),
        'labels': json.loads((case / 'labels.json').read_text()),
        'compilerObservations': json.loads((case / 'compiler-observations.json').read_text()),
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'debugger': 'GDB batch: values, types, addresses, lexical lookup, instruction stepping and exit 0'}
    path = case / (collection.record['suite'] + '-' + collection.record['layer'] + '-coverage-oracle.json')
    path.write_text(json.dumps(evidence, indent=4) + '\n')
    collection.finish(path)

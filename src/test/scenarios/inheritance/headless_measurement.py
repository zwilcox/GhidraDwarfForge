"""Measure the existing saved-program oracle without changing its export route."""
import json
from pathlib import Path

from measurement import coverage


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[3]


def sources():
    paths = [HERE / name for name in (
        'extract.py', 'headless_measurement.py', 'measurement.py', 'fixture.cpp',
        'produce.py', 'reference.py', 'gdb.py', 'gdb.sh', 'name-gdb.py', 'thunks-gdb.py',
        'PrepareInheritanceFixture.java', 'ProbeVtableBindings.java', 'RoundTripCxxProfile.java',
        'PrepareAdjustmentThunks.java', 'MutateVtableFixture.java', 'RebaseInheritanceFixture.java')]
    paths += [REPOSITORY / name for name in (
        'ghidra_scripts/GhidraDwarfForge.java', 'ghidra_scripts/GhidraDwarfForgeCxxProfile.java',
        'support/ghidra-dwarf-forge-headless', 'src/test/integration/integration_coverage.py',
        'src/test/coverage/launcher-headless.py', 'src/test/integration/check-object-parameters.py',
        'src/test/integration/qemu-socket.sh')]
    return {str(path.relative_to(REPOSITORY)): coverage.digest(path) for path in paths}


def collection(ghidra):
    return coverage.Collection('saved-inheritance',
        ghidra / 'Ghidra/Extensions/GhidraDwarfForge/lib/GhidraDwarfForge.jar', 'headless')


def finish(measured, case, result, source_hashes, details):
    if not measured.enabled:
        return
    if source_hashes != sources():
        raise ValueError('saved inheritance harness changed during measurement')
    evidence = {**result, **details, 'status': 'PASS_SAVED_INHERITANCE_MEASUREMENT',
        'harnessSha256': source_hashes,
        'validators': ['readelf', 'llvm-dwarfdump', 'libdwarf-consumer'],
        'debugger': 'GDB batch: dynamic types, inherited values, vtables and exit 0'}
    path = case / 'coverage-oracle.json'
    path.write_text(json.dumps(evidence, indent=4) + '\n')
    measured.finish(path)

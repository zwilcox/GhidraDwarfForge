"""Opt-in measurement of the packaged producer used by the C++ runtime oracles."""
import importlib.util
import os
from pathlib import Path


SPEC = importlib.util.spec_from_file_location('inheritance_integration_coverage',
    Path(__file__).resolve().parents[2] / 'integration/integration_coverage.py')
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


def collection(suite, classpath):
    jars = [Path(path) for path in classpath.split(os.pathsep)
        if Path(path).name == 'GhidraDwarfForge.jar']
    if os.environ.get('FORGE_INTEGRATION_COVERAGE_OUTPUT') and len(jars) != 1:
        raise ValueError('inheritance coverage requires one packaged production JAR')
    return coverage.Collection(suite, jars[0] if jars else None, 'native-java',
        test_classes=('ghidradwarfforge.nativeapi.InheritanceProducerProbe',
            'ghidradwarfforge.elf.VtablePackagingProbe'))

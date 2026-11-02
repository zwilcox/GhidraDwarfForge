#!/usr/bin/env python3
"""The negative-profile diagnostic accounting must not conceal unrelated warnings."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('diagnostics', Path(__file__).with_name('abi-profile-diagnostics.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
warning = module.MISSING_FREEBSD
assert module.normalize('clean', 'clean', 0) == ('clean', 0)
assert module.normalize(warning * 2 + 'warning: broken DWARF\n', warning * 2, 9) == ('warning: broken DWARF\n', 2)
for actual, reference, osabi in [(warning, warning * 2, 9), (warning * 2, '', 9),
        (warning * 3, warning * 3, 9), (warning * 2, warning * 2, 0),
        (warning.replace('aarch64', 'arm') * 2, warning * 2, 9)]:
    try:
        module.normalize(actual, reference, osabi)
        raise RuntimeError('unexpected diagnostic accepted')
    except AssertionError:
        pass
print('abi-profile-diagnostics-test=PASS')

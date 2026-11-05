import importlib.util
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / 'performance/headless-observations.py'
spec = importlib.util.spec_from_file_location('headless_observations', path)
observations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observations)


class HeadlessObservationTest(unittest.TestCase):
    def test_runtime_and_actual_script(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / 'module'
            (module / 'ghidra_scripts').mkdir(parents=True)
            script = module / 'ghidra_scripts/GhidraDwarfForge.java'
            script.write_text('selected script')
            log = root / 'export.log'
            log.with_suffix('.stderr').write_text('openjdk version "21.0.12.1"\n')
            log.write_text(f'INFO  SCRIPT: {script} (HeadlessAnalyzer)  \n')
            result = observations.verify(log, module, exported=True)
            self.assertEqual(result['javaVersions'], ['21.0.12.1'])
            self.assertEqual(result['packagedScript'], str(script.resolve()))
            old = root / 'GhidraDwarfForge.java'
            old.write_text('old shared-install script')
            log.write_text(f'INFO  SCRIPT: {old} (HeadlessAnalyzer)  \n')
            with self.assertRaises(ValueError):
                observations.verify(log, module, exported=True)
            log.write_text(f'INFO  SCRIPT: {script} (HeadlessAnalyzer)  \n')
            for version in ('25.0.4.1', ''):
                log.with_suffix('.stderr').write_text(f'openjdk version "{version}"\n')
                with self.assertRaises(ValueError):
                    observations.verify(log, module, exported=True)
            log.with_suffix('.stderr').write_text('')
            with self.assertRaises(ValueError):
                observations.verify(log, module, exported=True)


if __name__ == '__main__':
    unittest.main()

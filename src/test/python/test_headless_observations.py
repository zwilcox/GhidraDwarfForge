import importlib.util
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / 'performance/headless-observations.py'
spec = importlib.util.spec_from_file_location('headless_observations', path)
observations = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observations)


class HeadlessObservationTest(unittest.TestCase):
    def test_saved_project_entry_point_and_delegated_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / 'Ghidra/Extensions/module/ghidra_scripts'
            scripts.mkdir(parents=True)
            (root / 'Ghidra/application.properties').write_text('application.java.compiler=25\n')
            direct = scripts / 'GhidraDwarfForge.java'
            direct.touch()
            read_only = scripts / 'GhidraDwarfForgeReadOnly.java'
            log = root / 'export.log'
            log.with_suffix('.stderr').write_text('openjdk version "25.0.4"\n')
            direct_record = f'INFO  SCRIPT: {direct} (HeadlessAnalyzer)\n'
            selected = f'INFO  SCRIPT: {read_only} (HeadlessAnalyzer)\n'
            completed = 'INFO  GhidraDwarfForge.java> GhidraDwarfForge symbol export PASS (GhidraScript)\n'
            log.write_text(direct_record)
            self.assertEqual(observations.verify(log, scripts.parent, saved_project=True)['packagedScript'],
                str(direct.resolve()))
            read_only.touch()
            log.write_text(selected + completed)
            self.assertEqual(observations.verify(log, scripts.parent, saved_project=True)['packagedScript'],
                str(read_only.resolve()))
            with self.assertRaises(ValueError):
                observations.verify(log, scripts.parent, exported=True)
            other = root / read_only.name
            other.touch()
            for transcript in (selected, selected + completed * 2, selected * 2 + completed,
                    direct_record + completed, direct_record + selected + completed,
                    selected.replace(str(read_only), str(other)) + completed):
                log.write_text(transcript)
                with self.subTest(transcript=transcript), self.assertRaises(ValueError):
                    observations.verify(log, scripts.parent, saved_project=True)

    def test_runtime_and_actual_script(self):
        with tempfile.TemporaryDirectory(prefix='forge-headless-observation-') as temporary:
            root = Path(temporary)
            module = root / 'Ghidra/Extensions/module'
            scripts = module / 'ghidra_scripts'
            scripts.mkdir(parents=True)
            (root / 'Ghidra/application.properties').write_text('application.java.compiler=25\n')
            script = scripts / 'GhidraDwarfForge.java'
            script.write_text('// observation fixture\n', encoding='utf-8')
            log, stderr = root / 'export.log', root / 'export.stderr'
            banner = 'openjdk version "25.0.5" 2026-10-20 LTS\n'
            selected = f'INFO  SCRIPT: {script} (HeadlessAnalyzer)\n'
            old = root / 'old/GhidraDwarfForge.java'
            old.parent.mkdir()
            old.write_text('old shared-install script')
            for out, err in ((selected, banner), (banner + selected, ''),
                    ('\x1b[31;1m' + banner.rstrip() + '\x1b[0m\n' + selected, ''),
                    (selected, '\x1b[31;1m' + banner.rstrip() + '\x1b[0m\n')):
                log.write_text(out, encoding='utf-8')
                stderr.write_text(err, encoding='utf-8')
                observed = observations.verify(log, module, exported=True)
                self.assertEqual(observed['javaVersions'], ['25.0.5'])
                self.assertEqual(observed['packagedScript'], str(script.resolve()))
            log.write_text(selected.rstrip() + '  \n', encoding='utf-8')
            stderr.write_text('openjdk version "25.0.4.1"\n', encoding='utf-8')
            self.assertEqual(observations.verify(log, module, exported=True)['javaVersions'], ['25.0.4.1'])
            for out, err in ((selected, ''), ('mentioned ' + banner + selected, ''),
                    (banner + selected, 'java version "21.0.1"\n'),
                    ('\x1b[31;1m' + banner.replace('25.', '21.') + '\x1b[0m' + selected, ''),
                    (banner, ''), (banner + selected * 2, ''), (selected, 'openjdk version ""\n'),
                    (selected.replace(str(script), str(old)), banner),
                    (banner + selected.replace(str(script), str(root / 'wrong/GhidraDwarfForge.java')), ''),
                    ('\x1b[2K' + banner + selected, '')):
                log.write_text(out, encoding='utf-8')
                stderr.write_text(err, encoding='utf-8')
                with self.subTest(out=out, err=err), self.assertRaises((ValueError, FileNotFoundError)):
                    observations.verify(log, module, exported=True)


if __name__ == '__main__':
    unittest.main()

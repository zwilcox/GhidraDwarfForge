"""Fail-closed completion and provenance controls without launching Ghidra."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


spec = importlib.util.spec_from_file_location('headless_coverage',
    Path(__file__).with_name('headless-coverage.py'))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='coverage-receipt-')
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name)
        self.jar = self.output / 'production.jar'
        self.jar.write_bytes(b'original production population')
        for index in range(2):
            (self.output / f'headless-{index}.exec').write_bytes(bytes([index]))
        self.receipt = self.output / 'receipt.json'
        self.record = {'schema': 1, 'status': 'PASS',
            'productionJarSha256': coverage.digest(self.jar),
            'execution': {f'headless-{i}.exec': coverage.digest(self.output / f'headless-{i}.exec')
                for i in range(2)}}
        self.write()

    def write(self):
        self.receipt.write_text(json.dumps(self.record))

    def validate(self):
        return coverage.validate_receipt(self.output, self.jar)

    def test_unchanged_completed_session(self):
        self.assertEqual('PASS', self.validate()['status'])

    def test_failed_or_incomplete_session(self):
        for status in ('INCOMPLETE', 'FAIL', None):
            self.record['status'] = status
            self.write()
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                self.validate()

    def test_changed_production_classes(self):
        self.jar.write_bytes(b'new compilation')
        with self.assertRaisesRegex(ValueError, 'production classes changed'):
            self.validate()

    def test_changed_execution(self):
        (self.output / 'headless-0.exec').write_bytes(b'foreign execution')
        with self.assertRaisesRegex(ValueError, 'execution data changed'):
            self.validate()

    def test_missing_session(self):
        (self.output / 'headless-1.exec').unlink()
        with self.assertRaisesRegex(ValueError, 'unrecorded or missing'):
            self.validate()

    def test_extra_execution(self):
        (self.output / 'stale.exec').write_bytes(b'old run')
        with self.assertRaisesRegex(ValueError, 'unrecorded or missing'):
            self.validate()

    def test_manifest_cannot_select_other_files(self):
        self.record['execution'] = {'../../other.exec': '0' * 64}
        self.write()
        with self.assertRaisesRegex(ValueError, 'unexpected recorded'):
            self.validate()


@unittest.skipUnless(os.name == 'posix', 'the installed coverage sample is Linux-only')
class ProcessOwnershipTests(unittest.TestCase):
    def test_timeout_stops_descendant_writes(self):
        self.check_descendants('timeout')

    def test_failed_launcher_stops_descendant_writes(self):
        self.check_descendants('failure')

    def test_sigterm_stops_descendant_writes(self):
        self.check_descendants('interrupted')

    def check_descendants(self, mode):
        with tempfile.TemporaryDirectory(prefix='coverage-process-') as temporary:
            root = Path(temporary)
            ready, release, witness = (root / name for name in ('ready', 'release', 'witness'))
            worker = (
                'import os,time; from pathlib import Path; '
                f'Path({str(ready)!r}).write_text(str(os.getpid())); '
                'deadline=time.monotonic()+5\n'
                f'while not Path({str(release)!r}).exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                f'if Path({str(release)!r}).exists(): Path({str(witness)!r}).write_text("orphan wrote after return")\n')
            launcher = (
                'import os,signal,subprocess,sys,time; from pathlib import Path; '
                f'subprocess.Popen([sys.executable,"-c",{worker!r}]); '
                'deadline=time.monotonic()+2\n'
                f'while not Path({str(ready)!r}).exists() and time.monotonic()<deadline: time.sleep(.01)\n'
                + {'timeout': 'time.sleep(5)\n', 'failure': 'sys.exit(7)\n',
                    'interrupted': 'os.kill(os.getppid(),signal.SIGTERM); time.sleep(5)\n'}[mode])
            try:
                expected = {'timeout': subprocess.TimeoutExpired,
                    'failure': subprocess.CalledProcessError, 'interrupted': KeyboardInterrupt}[mode]
                with self.assertRaises(expected):
                    coverage.run_logged([sys.executable, '-c', launcher], root, mode, timeout=.5)
                self.assertTrue(ready.is_file(), 'descendant did not start; control is inconclusive')
                release.touch()
                # The child was started and waiting for this signal. If it is
                # still alive, it can write after the failed command returns.
                time.sleep(1)
                self.assertFalse(witness.exists(), 'failed command left a writable descendant')
            finally:
                release.touch()
                if ready.is_file():
                    try:
                        os.kill(int(ready.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()

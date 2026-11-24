"""Exercise the CI package installer across temporary and permanent failures."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


INSTALLER = Path(__file__).with_name("install-target-packages.sh").resolve()
PACKAGES = ["gdb-multiarch", "lldb-18=1:18.1.3-1ubuntu1"]


class TargetInstallerTest(unittest.TestCase):
    def run_scenario(self, outcomes, expected_status, expected_calls):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            programs = {
                "sudo": 'exec "$@"',
                "sleep": 'exit 0',
                "apt-get": '''
echo "$*" >> calls
head -c 20000 /dev/zero
echo "apt diagnostic"
status=$(head -n 1 outcomes)
sed -i '1d' outcomes
exit "${status:?unexpected invocation}"
''',
            }
            for name, body in programs.items():
                program = root / name
                program.write_text("#!/bin/sh\n" + body + "\n")
                program.chmod(0o755)
            (root / "outcomes").write_text("".join(f"{status}\n" for status in outcomes))
            result = subprocess.run(["bash", INSTALLER, *PACKAGES], cwd=root,
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}"},
                capture_output=True, timeout=10)
            self.assertEqual(result.returncode, expected_status, result.stderr)
            calls = [line.split() for line in (root / "calls").read_text().splitlines()]
            phases = []
            for call in calls:
                if "update" in call:
                    self.assertIn("APT::Update::Error-Mode=any", call)
                    phases.append("indexes")
                else:
                    self.assertEqual(call[-len(PACKAGES):], PACKAGES)
                    self.assertIn("--no-install-recommends", call)
                    self.assertIn("install", call)
                    phases.append("packages" if "--download-only" in call else "install")
                    if phases[-1] == "install":
                        self.assertIn("--no-download", call)
            self.assertEqual(phases, expected_calls)
            logs = list((root / "build/test-results/target-toolchain").glob("*.log"))
            self.assertEqual(len(logs), sum(phase != "install" for phase in phases))
            for log in logs:
                self.assertEqual(log.stat().st_size, 16384)
                self.assertTrue(log.read_bytes().endswith(b"apt diagnostic\n"))

    def test_recover_and_install_once(self):
        self.run_scenario([100, 0, 100, 0, 0], 0,
            ["indexes", "indexes", "packages", "packages", "install"])

    def test_fetch_exhausted(self):
        self.run_scenario([0, 100, 100], 100, ["indexes", "packages", "packages"])

    def test_install_error_propagates(self):
        self.run_scenario([0, 0, 42], 42, ["indexes", "packages", "install"])


if __name__ == "__main__":
    unittest.main()

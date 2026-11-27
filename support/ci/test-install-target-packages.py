"""Exercise the CI package installer across temporary and permanent failures."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


INSTALLER = Path(__file__).with_name("install-target-packages.sh").resolve()
PACKAGES = ["gdb-multiarch", "lldb-18=1:18.1.3-1ubuntu1"]


class TargetInstallerTest(unittest.TestCase):
    def run_scenario(self, outcomes, expected_status, expected_calls, *,
            workflow_command=None, packages=PACKAGES, recommends=False):
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
            command = ["bash", INSTALLER, *packages]
            if workflow_command is not None:
                (root / "support").mkdir()
                (root / "support/ci").symlink_to(INSTALLER.parent)
                command = ["bash", "-e", "-c", workflow_command]
            result = subprocess.run(command, cwd=root,
                env={**os.environ, "PATH": f"{root}:{os.environ['PATH']}"},
                capture_output=True, timeout=10)
            self.assertEqual(result.returncode, expected_status, result.stderr)
            calls = [line.split() for line in (root / "calls").read_text().splitlines()]
            phases = []
            for call in calls:
                self.assertIn("Dir::Etc::sourcelist=sources.list.d/ubuntu.sources", call)
                self.assertIn("Dir::Etc::sourceparts=-", call)
                if "update" in call:
                    self.assertIn("APT::Update::Error-Mode=any", call)
                    phases.append("indexes")
                else:
                    self.assertEqual(call[-len(packages):], packages)
                    self.assertEqual("--install-recommends" in call, recommends)
                    self.assertEqual("--no-install-recommends" in call, not recommends)
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
            return calls

    def test_hosted_tool_installation_steps(self):
        workflow = INSTALLER.parents[2] / ".github/workflows/ci.yml"
        jobs = yaml.safe_load(workflow.read_text())["jobs"]
        for job, step, packages, recommends in (
            ("cortex-m-profile", "Install Cortex-M compiler and system debugger",
             ["gcc-arm-none-eabi=15:13.2.rel1-2", "binutils-arm-none-eabi=2.42-1ubuntu1+23",
              "qemu-system-arm", "gdb-multiarch", "llvm", "binutils"], False),
            ("perf-build-id", "Install native perf fixture and validation tools",
             ["gcc", "binutils", "llvm", "gdb", "linux-tools-generic", "util-linux"], True),
        ):
            with self.subTest(job=job):
                command = next(s["run"] for s in jobs[job]["steps"] if s.get("name") == step)
                self.run_scenario([0, 0, 0], 0, ["indexes", "packages", "install"],
                    workflow_command=command, packages=packages, recommends=recommends)

    def test_unrelated_runner_repository_is_never_consulted(self):
        calls = self.run_scenario([0, 0, 0], 0, ["indexes", "packages", "install"])
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory)
            (config / "sources.list").touch()
            sources = config / "sources.list.d"
            sources.mkdir()
            (sources / "ubuntu.sources").write_text(
                "Types: deb\nURIs: https://ubuntu.invalid/ubuntu\n"
                "Suites: noble noble-updates noble-security\nComponents: main universe\n")
            (sources / "vendor.list").write_text("deb https://vendor.invalid/ubuntu noble main\n")
            apt = ["apt-get", "-o", f"Dir::Etc={directory}", "--print-uris"]
            unscoped = subprocess.check_output([*apt, "update"], text=True)
            self.assertIn("vendor.invalid", unscoped)
            for call in calls:
                options = []
                for i, value in enumerate(call):
                    if value == "-o":
                        options.extend(call[i:i + 2])
                uris = subprocess.check_output([*apt, *options, "update"], text=True)
                self.assertNotIn("vendor.invalid", uris)
                for suite in ("noble", "noble-updates", "noble-security"):
                    self.assertIn(f"https://ubuntu.invalid/ubuntu/dists/{suite}/InRelease", uris)

    def test_recover_and_install_once(self):
        self.run_scenario([100, 0, 100, 0, 0], 0,
            ["indexes", "indexes", "packages", "packages", "install"])

    def test_fetch_exhausted(self):
        self.run_scenario([0, 100, 100], 100, ["indexes", "packages", "packages"])

    def test_index_failure_stops_before_downloading_packages(self):
        self.run_scenario([100, 100], 100, ["indexes", "indexes"])

    def test_install_error_propagates(self):
        self.run_scenario([0, 0, 42], 42, ["indexes", "packages", "install"])


if __name__ == "__main__":
    unittest.main()

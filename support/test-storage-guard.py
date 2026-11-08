#!/usr/bin/env python3
"""Small local process/filesystem controls; no builds, downloads or large files."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("storage-guard.py")
spec = importlib.util.spec_from_file_location("storage_guard", SCRIPT)
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class StorageGuardTests(unittest.TestCase):
    def setUp(self):
        scratch = SCRIPT.parent.parent / ".forge-work" / "scratch"
        scratch.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="storage-test-", dir=scratch)
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.guard = storage.Guard(self.repo, limits={
            "scratch": 128 * 1024, "cache": 128 * 1024, "evidence": 128 * 1024},
            reserve=0, interval=0.02)
        self.output = io.StringIO()
        self.enterContext(contextlib.redirect_stdout(self.output))
        self.enterContext(contextlib.redirect_stderr(self.output))

    def run_python(self, source):
        return self.guard.run([sys.executable, "-B", "-c", source])

    def scratch(self):
        path = self.guard.workspace / "scratch"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def test_shared_environment_exit_status_and_temp_cleanup(self):
        result = self.run_python(
            'import os,json,pathlib; '
            'pathlib.Path(os.environ["FORGE_SCRATCH_DIR"],"env.json").write_text(json.dumps(dict(os.environ))); '
            'pathlib.Path(os.environ["TMPDIR"],"temporary").write_text("test"); '
            'raise SystemExit(7)')
        self.assertEqual(result, 7)
        env = json.loads((self.scratch() / "env.json").read_text())
        self.assertEqual(env["GRADLE_USER_HOME"], str(self.guard.workspace / "cache/gradle"))
        self.assertEqual(env["XDG_CACHE_HOME"], str(self.guard.workspace / "cache/xdg"))
        self.assertEqual(env["HOME"], os.environ["HOME"])
        self.assertFalse(Path(env["TMPDIR"]).exists())
        self.assertFalse(list(self.scratch().glob("run-*")))

    def test_existing_oversize_refuses_before_launch(self):
        (self.scratch() / "oversize").write_bytes(b"x" * (256 * 1024))
        result = self.run_python('from pathlib import Path; Path("launched").touch()')
        self.assertEqual(result, 75)
        self.assertFalse((self.scratch() / "launched").exists())

    def test_low_free_space_refuses_before_launch(self):
        self.guard.reserve = 1
        with mock.patch.object(storage.shutil, "disk_usage", return_value=types.SimpleNamespace(free=0)):
            result = self.run_python('from pathlib import Path; Path("launched").touch()')
        self.assertEqual(result, 75)
        self.assertFalse((self.scratch() / "launched").exists())

    def test_legacy_evidence_counts_without_deletion(self):
        legacy = self.repo / "old-evidence"
        legacy.mkdir()
        (legacy / "archive").write_bytes(b"x" * (256 * 1024))
        self.guard.workspace.mkdir()
        self.guard.config.write_text(json.dumps({"legacy_roots": {"evidence": [str(legacy)]}}))
        report = self.guard.snapshot()
        self.assertEqual(report["status"], "REFUSED")
        self.assertGreater(report["usageBytes"]["evidence"], self.guard.limits["evidence"])
        self.assertTrue((legacy / "archive").exists())

    def test_growth_stops_child_and_term_ignoring_grandchild(self):
        grandchild = ('import signal,time,pathlib; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                      'p=pathlib.Path("heartbeat");\n'
                      'while True:\n    p.write_text(str(time.monotonic())); time.sleep(.01)\n')
        source = ('import subprocess,sys,time,pathlib; '
                  f'subprocess.Popen([sys.executable,"-c",{grandchild!r}]); '
                  'p=pathlib.Path("heartbeat");\n'
                  'while not p.exists(): time.sleep(.01)\n'
                  'pathlib.Path("oversize").write_bytes(b"x"*1048576)\n'
                  'time.sleep(10)\n')
        self.assertEqual(self.run_python(source), 75)
        heartbeat = self.scratch() / "heartbeat"
        value = heartbeat.read_text()
        time.sleep(0.1)
        self.assertEqual(heartbeat.read_text(), value)
        self.assertFalse(list(self.scratch().glob("run-*")))

    def deferred_fixture(self):
        legacy = self.repo / "old-evidence"
        legacy.mkdir()
        archive = legacy / "archive"
        archive.write_bytes(b"x" * (256 * 1024))
        info = archive.stat()
        record = {"path": str(archive), "identity": [info.st_dev, info.st_ino,
            info.st_size, info.st_mtime_ns, info.st_blocks * 512]}
        config = {"legacy_roots": {"evidence": [str(legacy)]},
            "deferred_evidence": {"scope": "test goal", "authorization": "test approval",
                "files": [record]}}
        self.guard.workspace.mkdir()
        self.guard.config.write_text(json.dumps(config))
        return archive, config

    def test_deferred_files_stay_visible_and_new_growth_is_charged(self):
        archive, config = self.deferred_fixture()
        report = self.guard.snapshot()
        self.assertEqual(report["status"], "READY")
        self.assertGreater(report["usageBytes"]["evidence"], self.guard.limits["evidence"])
        self.assertEqual(report["usageBytes"]["evidence"] - report["budgetUsageBytes"]["evidence"],
            archive.stat().st_blocks * 512)
        (archive.parent / "new-artifact").write_bytes(b"x" * (256 * 1024))
        self.assertEqual(self.guard.snapshot()["status"], "REFUSED")

    def test_deferred_modification_and_disappearance_fail_closed(self):
        archive, config = self.deferred_fixture()
        archive.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.guard.snapshot()
        archive.unlink()
        with self.assertRaises(FileNotFoundError):
            self.guard.snapshot()

    def test_deferred_duplicate_or_unapproved_scope_fails_closed(self):
        archive, config = self.deferred_fixture()
        config["deferred_evidence"]["files"] *= 2
        self.guard.config.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            self.guard.snapshot()
        config["deferred_evidence"]["files"].pop()
        config["deferred_evidence"]["authorization"] = ""
        self.guard.config.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            self.guard.snapshot()

    def test_missing_legacy_storage_and_invalid_config_fail_closed(self):
        self.guard.workspace.mkdir()
        for config in ([], {"legacy_roots": []}, {"limits": {"scratch": 999}},
                       {"legacy_roots": {"evidence": [str(self.repo / "missing")]}}):
            with self.subTest(config=config):
                self.guard.config.write_text(json.dumps(config))
                with self.assertRaises(ValueError):
                    self.guard.snapshot()

    def test_short_command_overflow_is_caught_after_exit(self):
        self.assertEqual(self.run_python(
            'from pathlib import Path; Path("oversize").write_bytes(b"x"*1048576)'), 75)

    def test_lock_refuses_second_command(self):
        self.guard.workspace.mkdir()
        with (self.guard.workspace / "run.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_python('raise SystemExit(99)'), 75)

    def test_measurement_error_stops_process_and_cleans_temp(self):
        original = self.guard.snapshot
        calls = 0

        def fail_after_launch():
            nonlocal calls
            calls += 1
            if calls > 1:
                raise PermissionError("injected unreadable storage")
            return original()

        with mock.patch.object(self.guard, "snapshot", side_effect=fail_after_launch):
            with self.assertRaises(PermissionError):
                self.run_python('import time; time.sleep(10)')
        self.assertFalse(list(self.scratch().glob("run-*")))

    def test_root_symlink_and_shm_are_refused(self):
        self.guard.workspace.mkdir()
        (self.guard.workspace / "cache").symlink_to(self.repo, target_is_directory=True)
        report = self.guard.snapshot()
        self.assertTrue(any("symlinks" in p for p in report["problems"]))
        self.guard.config.write_text(json.dumps({"legacy_roots": {"scratch": ["/dev/shm"]}}))
        report = self.guard.snapshot()
        self.assertTrue(any("/dev/shm" in p for p in report["problems"]))

    def test_hardlinks_are_not_double_counted(self):
        first = self.repo / "first"
        first.write_bytes(b"x" * 8192)
        second = self.repo / "second"
        os.link(first, second)
        self.assertEqual(storage.allocated([first]), storage.allocated([first, second]))

    def test_more_than_one_extra_worktree_refused(self):
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=Storage Test",
                        "-c", "user.email=storage-test@example.invalid", "commit", "-q",
                        "--allow-empty", "-m", "storage fixture"], check=True)
        for name in ("one", "two"):
            subprocess.run(["git", "-C", str(self.repo), "worktree", "add", "-q",
                            "--detach", str(self.repo / name)], check=True)
        report = self.guard.snapshot()
        self.assertTrue(any("maximum is one" in p for p in report["problems"]))

    def test_sigterm_stops_guarded_process(self):
        marker = self.repo / "heartbeat"
        child = ('import time,pathlib; p=pathlib.Path(' + repr(str(marker)) + ');\n'
                 'while True:\n    p.write_text(str(time.monotonic())); time.sleep(.01)\n')
        driver = (
            'import importlib.util,sys; '
            f's=importlib.util.spec_from_file_location("guard",{str(SCRIPT)!r}); '
            'm=importlib.util.module_from_spec(s); s.loader.exec_module(m); '
            f'g=m.Guard({str(self.repo)!r},reserve=0,interval=.02); '
            f'sys.exit(g.run([sys.executable,"-c",{child!r}]))')
        process = subprocess.Popen([sys.executable, "-B", "-c", driver],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=5), 130)
            value = marker.read_text()
            time.sleep(0.1)
            self.assertEqual(marker.read_text(), value)
            self.assertFalse(list(self.scratch().glob("run-*")))
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)

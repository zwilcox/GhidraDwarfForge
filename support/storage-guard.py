#!/usr/bin/env python3
"""Linux development storage guard. Monitoring is not a filesystem quota."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


GIB = 1024 ** 3
LIMITS = {"scratch": 20 * GIB, "cache": 10 * GIB, "evidence": 5 * GIB}
RESERVE = 50 * GIB
INTERVAL = 5
REPO = Path(__file__).resolve().parent.parent


def allocated(paths):
    """Count allocated blocks once per inode; never traverse nested symlinks."""
    seen = set()
    total = 0
    pending = list(paths)
    while pending:
        path = pending.pop()
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        key = (info.st_dev, info.st_ino)
        if key in seen:
            continue
        seen.add(key)
        total += info.st_blocks * 512
        if stat.S_ISDIR(info.st_mode):
            pending.extend(path.iterdir())
    return total


def existing_parent(path):
    while not path.exists():
        if path.is_symlink():
            raise ValueError(f"Dangling storage-root symlink: {path}")
        path = path.parent
    return path


class Guard:
    def __init__(self, repo, limits=None, reserve=RESERVE, interval=INTERVAL):
        self.repo = Path(repo).resolve()
        self.workspace = self.repo / ".forge-work"
        if self.workspace.is_symlink():
            raise ValueError("The managed workspace must not be a symlink")
        self.limits = dict(LIMITS if limits is None else limits)
        self.reserve = reserve
        self.interval = interval
        self.config = self.workspace / "config.json"

    def roots(self):
        groups = {name: [self.workspace / name] for name in self.limits}
        groups["scratch"] += [self.repo / name for name in (
            "build", "dist", ".gradle", ".ghidra-test", "jna-wrapper/target", "src/temp")]
        config = json.loads(self.config.read_text()) if self.config.exists() else {}
        if not isinstance(config, dict) or set(config) - {"legacy_roots"}:
            raise ValueError("Unknown storage configuration field; limits are not configurable here")
        legacy = config.get("legacy_roots", {})
        if not isinstance(legacy, dict) or set(legacy) - set(groups):
            raise ValueError("Unknown legacy storage category")
        for category, paths in legacy.items():
            if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths):
                raise ValueError("Legacy roots must be lists of absolute paths")
            for name in paths:
                path = Path(name)
                if not path.is_absolute():
                    raise ValueError("Legacy roots must be absolute paths")
                if not path.exists():
                    raise ValueError(f"Registered legacy storage is unavailable: {path}; "
                                     "verify retirement or restore its mount before proceeding")
                groups[category].append(path)
        result = subprocess.run(
            ["git", "-C", str(self.repo), "worktree", "list", "--porcelain", "-z"],
            check=True, capture_output=True)
        trees = [Path(os.fsdecode(part[9:])).resolve() for part in result.stdout.split(b"\0")
                 if part.startswith(b"worktree ")]
        extra = [p for p in trees if p != self.repo and p.exists()]
        groups["scratch"] += extra
        return groups, extra

    def snapshot(self):
        groups, extra = self.roots()
        problems = []
        if len(extra) > 1:
            problems.append(f"{len(extra)} extra worktrees exist; maximum is one")
        filesystems = {}
        counts = {}
        for category, paths in groups.items():
            for path in paths:
                resolved = path.resolve()
                if resolved.is_relative_to(Path("/dev/shm")):
                    problems.append(f"Project storage in /dev/shm is forbidden: {path}")
                if path.is_symlink():
                    problems.append(f"Storage roots must not be symlinks: {path}")
                parent = existing_parent(path)
                device = parent.stat().st_dev
                if device not in filesystems:
                    free = shutil.disk_usage(parent).free
                    filesystems[device] = {"path": str(parent), "freeBytes": free}
                    if free < self.reserve:
                        problems.append(f"Less than {self.reserve / GIB:g} GiB free on {parent}")
            counts[category] = allocated(paths)
            if counts[category] > self.limits[category]:
                problems.append(f"{category}: {counts[category] / GIB:.2f} GiB exceeds "
                                f"{self.limits[category] / GIB:g} GiB budget")
        return {"status": "REFUSED" if problems else "READY", "usageBytes": counts,
                "limitsBytes": self.limits, "reserveBytes": self.reserve,
                "roots": {k: [str(p) for p in v] for k, v in groups.items()},
                "extraWorktrees": [str(p) for p in extra],
                "filesystems": list(filesystems.values()), "problems": problems}

    def save(self, report):
        # One bounded current report, not an accumulating history of snapshots.
        self.workspace.mkdir(exist_ok=True)
        destination = self.workspace / "last-storage-report.json"
        with tempfile.NamedTemporaryFile(mode="w", dir=self.workspace, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(report, stream, indent=4)
            stream.write("\n")
        try:
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    def report(self):
        report = self.snapshot()
        self.save(report)
        print(json.dumps(report, indent=4), flush=True)
        return report

    def run(self, command, cwd=None):
        self.workspace.mkdir(exist_ok=True)
        with (self.workspace / "run.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("REFUSED: another guarded command is active", file=sys.stderr)
                return 75
            before = self.report()
            if before["problems"]:
                return 75
            scratch = self.workspace / "scratch"
            cache = self.workspace / "cache"
            for path in (scratch, cache, self.workspace / "evidence"):
                path.mkdir(exist_ok=True)
            destination = Path(cwd).resolve() if cwd else scratch
            allowed = [self.repo, scratch, *map(Path, before["extraWorktrees"])]
            if not any(destination == p or destination.is_relative_to(p) for p in allowed):
                raise ValueError("Working directory must be the repository, its worktree, or scratch")
            if destination.is_relative_to(Path("/dev/shm")):
                raise ValueError("Working directory cannot be in /dev/shm")
            env = os.environ.copy()
            env.update({"GRADLE_USER_HOME": str(cache / "gradle"),
                        "XDG_CACHE_HOME": str(cache / "xdg"),
                        "PIP_CACHE_DIR": str(cache / "pip"),
                        "npm_config_cache": str(cache / "npm"),
                        "CCACHE_DIR": str(cache / "ccache"),
                        "FORGE_SCRATCH_DIR": str(scratch),
                        "FORGE_CACHE_DIR": str(cache),
                        "FORGE_EVIDENCE_DIR": str(self.workspace / "evidence")})
            env["GRADLE_OPTS"] = env.get("GRADLE_OPTS", "") + " -Dorg.gradle.daemon=false"
            process = None
            temporary = tempfile.TemporaryDirectory(prefix="run-", dir=scratch)
            previous = signal.signal(signal.SIGTERM, interrupt)
            try:
                env.update({key: temporary.name for key in ("TMPDIR", "TMP", "TEMP")})
                process = subprocess.Popen(command, cwd=destination, env=env,
                                           start_new_session=True)
                while process.poll() is None:
                    try:
                        process.wait(timeout=self.interval)
                    except subprocess.TimeoutExpired:
                        report = self.snapshot()
                        self.save(report)
                        if report["problems"]:
                            print(json.dumps(report, indent=4), file=sys.stderr, flush=True)
                            return 75
                code = process.returncode
                stop_group(process)
                process = None
                after = self.report()
                return 75 if after["problems"] else code
            except KeyboardInterrupt:
                return 130
            finally:
                if process is not None:
                    stop_group(process)
                temporary.cleanup()
                signal.signal(signal.SIGTERM, previous)


def interrupt(signum, frame):
    raise KeyboardInterrupt


def stop_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("status", help="Report usage, legacy artifacts and free-space limits")
    runner = commands.add_parser("run", help="Preflight and monitor one heavy command")
    runner.add_argument("--cwd", type=Path)
    runner.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        # All linked worktrees use the primary checkout's workspace and caches.
        trees = subprocess.check_output(
            ["git", "-C", str(REPO), "worktree", "list", "--porcelain", "-z"])
        primary = next(part[9:] for part in trees.split(b"\0") if part.startswith(b"worktree "))
        guard = Guard(Path(os.fsdecode(primary)))
        if args.action == "status":
            return 75 if guard.report()["problems"] else 0
        command = args.command
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            parser.error("run requires a command after --")
        return guard.run(command, args.cwd)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"REFUSED: unable to verify storage safety: {error}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())

# Local development storage

The user approved these limits after unbounded worktree and validation retention
exhausted storage. They apply to local agent work; they do not change the exporter
or the hosted CI acceptance matrix.

| Category | Limit | Accounted paths |
| --- | --- | --- |
| Scratch/build | 20 GiB | `.forge-work/scratch`, repository `build`, `dist`, `.gradle`, `.ghidra-test`, `jna-wrapper/target`, `src/temp`, and existing extra registered worktrees |
| Shared cache/tools | 10 GiB | `.forge-work/cache` and configured legacy caches |
| Retained evidence | 5 GiB | `.forge-work/evidence` and configured legacy evidence |
| Filesystem reserve | 50 GiB free | Each filesystem containing an accounted root |

Use the main checkout plus at most one extra worktree. Its new designated path
is `.forge-work/scratch/worktree`. All linked worktrees resolve the primary
checkout and use the same workspace and caches. An existing extra checkout
outside this location is counted, not deleted or duplicated. Missing/stale
registrations are not counted as live checkouts.

## Commands

From the repository:

```bash
python3 support/storage-guard.py status
python3 support/storage-guard.py run --cwd "$PWD" -- ./gradlew --no-daemon buildExtension
python3 support/storage-guard.py run -- python3 -c 'print("scratch command")'
python3 -B support/test-storage-guard.py
```

Without `--cwd`, commands run in `.forge-work/scratch`. Build output in the main
repository and the extra worktree is also accounted. `TMPDIR`, `TMP`, and `TEMP`
point to a unique per-run directory removed on completion, refusal during a run,
or handled interruption, after stopping the process group. Deliberate durable
outputs must go to scratch or evidence instead of that temporary directory.

The launcher supplies shared `GRADLE_USER_HOME`, `XDG_CACHE_HOME`, `PIP_CACHE_DIR`,
`npm_config_cache`, and `CCACHE_DIR`. It also supplies `FORGE_SCRATCH_DIR`,
`FORGE_CACHE_DIR`, and `FORGE_EVIDENCE_DIR`. Use the cache for reusable toolchains.
It does not change `HOME` or relocate existing user caches. Gradle daemons are
disabled in its environment; use the explicit `--no-daemon` option too.

Only one guarded command may run at a time. The guard checks before launch,
every five seconds while running, and after exit. A budget or reserve violation
returns exit 75 and stops the launched process group. Other command exit codes
are preserved. Ctrl-C/SIGTERM stops the process group and returns 130. Measurement
errors fail closed. One `last-storage-report.json` is overwritten in the
workspace; status checks do not accumulate logs or downloads.

## Existing data must remain visible

Machine-local `.forge-work/config.json` registers existing roots without moving
or deleting them. For example:

```json
{
    "legacy_roots": {
        "evidence": ["/mnt/external_drive/GhidraDwarfForge-agent-artifacts"]
    }
}
```

Roots must be absolute paths. They count against the same category budgets;
configuration cannot raise those limits. Keep this file until the corresponding
legacy data has actually been retired or deliberately reclassified with the
user. Do not erase the registration to make a refusal disappear. A large legacy
archive can therefore block all heavy commands even with an empty new workspace.
The status command remains usable to explain that refusal.
Missing registered legacy paths fail closed: verify that data was retired before
removing its registration, or restore an unavailable external mount.

## Cleanup and limits of enforcement

This is a **monitored soft guard**, not a filesystem quota or sandbox. Fast writes
can exceed a budget before the next completed scan. Commands can ignore cache
variables, follow symlinks or write outside accounted roots; those actions are
forbidden by the operating policy but are not contained by this launcher. Do not
run detached processes or daemons that escape its process group. A forced kill,
power loss, or uninterruptible process can prevent automatic cleanup. A hard
ceiling needs a separately provisioned filesystem quota; none is configured here.

Usage counts allocated blocks, deduplicates hardlinks within a category, and does
not traverse nested symlinks. Root symlinks and `/dev/shm` storage are refused.
Known external data must be registered explicitly; this does not inventory every
file on the machine or automatically discover old unregistered scratch data.

Before each download, account for the archive and extracted peak size. After each
task, discard owned intermediates and superseded downloads. Keep concise summaries,
hashes and CI links; retain only selected failure/acceptance artifacts within the
evidence budget. Remote artifacts can expire, so a link is not a perpetual backup.

Before removing the extra worktree, inspect `git status --untracked-files=all`,
review ignored files for anything unique, and verify commits are preserved in the
main repository. Remove only identified owned disposable outputs. Do not blindly
run `git clean`, delete branches or erase analyst projects. No bulk cleanup is
performed automatically by this tool.

## Local validation — 2026-11-08

`python3 -B support/test-storage-guard.py` passes 13 isolated tests in approximately
two seconds. They use tiny temporary Git repositories and at most a 1 MiB test
payload per case, then remove their own fixtures. Coverage includes pre-launch
budget/reserve refusal, legacy evidence accounting, missing/invalid configuration,
live growth and short-command overflow, termination of a SIGTERM-ignoring
grandchild, interrupted cleanup, concurrent-launch refusal, failed measurement,
hardlink accounting, shared environment paths and the worktree count limit.

The actual machine's `status` command returns exit 75 with 115.84 GiB of registered
external evidence against the 5 GiB limit. This is an intentional refusal, not a
passing-capacity claim. These checks do not prove a hard quota, containment of
escaped processes/writes, Windows support, or exporter behavior. No production
build, native test matrix, artifact download or hosted workflow was started.

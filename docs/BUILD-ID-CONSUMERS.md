# Installed sidecars in LLDB and perf

**CONFIRMED locally (2026-11-06):** the production Linux installer passes
fresh-session LLDB 18.1.3 and offline perf 7.0.14 checks for x86-64 and AArch64,
both ET_EXEC and PIE. The tests install plain DWARF, explicitly refresh with a
compressed export, and remove the registration. They check the actual installed
path and retained source, with the selected export files absent during lookup.
This is a compression/generation refresh test; actual analyst name/type/member
edits have separate GDB coverage in the Linux command acceptance.

The receipt is [build-id-consumers.json](evidence/build-id-consumers.json).
Hosted acceptance, native Windows installation and protected integration remain
outstanding. These tests do not extend LLDB's validated target profile to ARM32
or MIPS, or establish sectionless automatic discovery.

## LLDB

Configure the root before creating the target in a fresh session:

```lldb
settings set target.debug-file-search-paths /home/me/debug-symbols
target create /home/me/program
breakpoint set --name recovered_function
source list --name recovered_function
run
```

That setting replaces the current search paths. Include any other roots you
need. The tests also disable external lookup so a system cache cannot supply
the expected symbols. They do not use `target symbols add` or an explicit symbol
module. The module's symbol-file path must equal the installer's registration,
and the line entries must name its retained source generation.

Each initial and refreshed generation passes ten runtime observations covering
scalar floating-point parameters, globals, source addresses and conservative
unavailability after register clobbering, followed by normal process exit.
AArch64 uses QEMU 8.2.2 with a Cortex-A53 CPU for the already documented LLDB 18
Neon transport profile. Empty-root, removed-registration and mismatched Forge
and compiler-DWARF controls find neither the function nor a compile unit.

## Offline perf lookup

An arbitrary GDB/LLDB debug root is not automatically a perf search root. The
tested portable arrangement uses a private filesystem mirror (`--symfs`):

1. Mirror the unchanged original at `<symfs>/<absolute-original-path>`.
2. Select `<symfs>/usr/lib/debug` as the Forge installation root.
3. Query the original with that same symfs, for example:

```bash
perf --buildid-dir /home/me/private-perf-cache probe \
    --symfs /home/me/symfs -x /home/me/program -L recovered_function
perf --buildid-dir /home/me/private-perf-cache probe \
    --symfs /home/me/symfs -x /home/me/program -V recovered_function
```

These are offline source-line and variable queries; they do not install a probe
or require collecting events. In the harness, the installer writes directly to
the symfs debug root. No manually staged replacement sidecar supplies the positive
lookup. Both initial and refreshed queries find the retained source and correct
parameter types. Removing the registration makes the queries fail, even though
the old generations and a separate perf cache entry still exist.

**CONFIRMED consumer limitation:** perf 7.0.14 accepts a different-build-ID file
placed at the expected `.build-id` pathname in this lookup path. Independent
compiler and Forge controls reproduce it in all four cases. LLDB rejects those
same mismatches. A successful perf query is therefore not identity validation.
Forge validates the original/sidecar/report binding before installation and
refuses mismatched pairs; keep the debug root under trusted ownership.

## perf's separate cache

The upstream [cache manual](https://raw.githubusercontent.com/torvalds/linux/master/tools/perf/Documentation/perf-buildid-cache.txt)
defines explicit add, update and removal operations. Forge installation does
not modify this cache. A new export can have the same build ID as the previous
export, so installing a refreshed generation does not refresh an existing cache.

The harness separately proves `perf buildid-cache --add`, `--update` and
`--remove` with a test-owned cache. It uses an **independent snapshot** of the
installed sidecar: this perf build hard-links its input, whereas the installer's
managed files must remain single-link. Never pass a managed registration or
generation file directly to that cache operation. Before refreshing the snapshot,
replace its directory entry; truncating an existing hard-linked snapshot would
also alter the cached inode. The test verifies that the cached bytes remain old
until explicit update, and that the registration remains single-link throughout.

Cache-only `perf probe` queries did not find source or variables in the tested
version, even after a successful cache add. The explicit symfs lookup is the
validated route. Cache manipulation alone is not proof of source discovery,
sample symbolization or `perf report` behavior. Event recording and report
symbolization remain **UNVERIFIED** here; the local host restricts perf events.

## Reproduce

`src/test/integration/build-id-consumers.py` takes two configurations produced
by `build-id-matrix.py`, floating-fixture labels, a different-build-ID Forge
sidecar and its matching compiler reference, and explicit Java/Ghidra/LLDB/perf
paths. Its output directory must be new and on the supported Linux filesystem.
The cross-architecture workflow invokes it for both exec and PIE on x86-64 and
AArch64. It retains every command, stdout/stderr, generation, runtime observation,
input hash and result. The four local runs total eight LLDB runtime sessions
(80 observations), sixteen LLDB absence/mismatch sessions and 64 perf queries.

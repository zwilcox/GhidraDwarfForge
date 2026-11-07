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
symbolization are characterized separately below; the local host restricts perf
events, so recording uses the dedicated hosted job.

## Sample and report characterization

**CONFIRMED characterization (2026-11-06):** `build-id-perf-report.py` runs an
independent native x86-64 exec/PIE experiment, required by the `perf-build-id` CI job. It builds a
small CPU-loop fixture, exports a saved analyst name through packaged Ghidra,
saves a second analyst name, reopens the program and exports again. The actual
installer installs, refreshes and removes those generations under the selected
symfs root. Original exports are hidden during consumer checks.

The sampling run uses `cpu-clock:u` and retains the actual `perf.data`, build-ID
list, reports and individual sample symbolizations. Its compiler reference must
resolve at least 30 hot-function samples before the Forge results are assessed.
A second independent compiler control removes only the hot function's ELF
symbol while retaining its DWARF; GDB must still find that function's DIE.
This distinguishes ELF symbol-table lookup from DWARF lookup. The experiment
fails if Forge cannot resolve a name where that compiler DWARF-only control can.
If both fail, it records the observed consumer limitation explicitly; a passing
characterization is not a claim of successful recovered-name symbolization.
Installed initial and refreshed names are assessed separately, including source
paths when symbolization succeeds, followed by an absent-registration control.

CI elevates only the bounded recorder and uses `setpriv` to run the source-built
fixture as the ordinary runner user. The fixture itself refuses UID/EUID zero.
It does not change kernel policy or populate perf's cache. Local `--prepare-only`
runs validate exports, production installation, GDB lookup and offline perf
queries; they report `PREPARED_SAMPLING_UNVERIFIED`, never sample acceptance.
The ordinary full invocation requires permission to record events; CI explicitly
selects `--record-with-sudo`. No unsupported recording attempt is skipped into a
passing result.

### Observed recording results

The [recording receipt](evidence/build-id-perf-recording.json) binds successful
job [128221726634](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42312429042/job/128221726634)
to tested head `f6d1547` and its retained artifact. Hosted perf 6.8.12 recorded
136 hot-function samples for ET_EXEC and 137 for PIE. Both controls and all
installation phases use the same recordings.

| Input at the expected build-ID path | Observed sample names |
| --- | --- |
| Compiler ELF with its function symbol | `profile_hot`, with compiler source lines |
| Compiler ELF with only that function symbol removed, DWARF retained | `frame_dummy`, the remaining neighboring ELF symbol; compiler source lines still resolve |
| Initial and refreshed Forge generations | `[unknown]` in `perf script`; raw addresses in `perf report`, without recovered names or source paths |
| Empty root and removed registration | No recovered names |

GDB independently finds the compiler DWARF-only function, and offline perf
queries plus GDB find each installed Forge name and retained source. These
positive checks do not establish sampled-report support. **Recovered-name perf
sample reporting is unsupported by this tested path.** No claim about other
perf versions or target architectures follows from these x86-64 recordings.

Independent review verifies 168 files in four generation manifests, reparses
original/export/installed strict logs with exact inherited-frame corroboration,
and checks the retained GNU/LLVM results. Replaying the actual recordings with
local perf 7.0.14 and exact installed sidecar bytes produces the same ordered
sample addresses and unknown names. That replay uses separate test-owned symfs
trees; it is a consumer replay, not another production installation test.
The hosted report's missing `tips.txt` footer concerns the tool's auxiliary tips
file; report stderr is empty. Original compiler-frame diagnostics are separately
corroborated as recorded in the receipt.

The enclosing CI run is not full acceptance: its architecture jobs stopped at
a missing fixture inventory entry. The correction and production lock fix must
pass the complete latest-head gate, including native Windows installation.

## Reproduce

`src/test/integration/build-id-consumers.py` takes two configurations produced
by `build-id-matrix.py`, floating-fixture labels, a different-build-ID Forge
sidecar and its matching compiler reference, and explicit Java/Ghidra/LLDB/perf
paths. Its output directory must be new and on the supported Linux filesystem.
The cross-architecture workflow invokes it for both exec and PIE on x86-64 and
AArch64. It retains every command, stdout/stderr, generation, runtime observation,
input hash and result. The four local runs total eight LLDB runtime sessions
(80 observations), sixteen LLDB absence/mismatch sessions and 64 perf queries.

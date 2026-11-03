# Validator process ownership

**CONFIRMED locally on Linux; PRESENT, UNVERIFIED on native Windows:**
`ValidatorSupervisor` invokes a separate native process owner, retains bounded
raw stdout/stderr and complete lifecycle evidence, and refuses nonzero exit,
timeout, cancellation, leftover descendants, output overflow or incomplete
cleanup. This is the production execution component for #72's live validator
service. It does not interpret DWARF diagnostics, approve attachment, supply
metadata preservation, or expose a public attachment command.

The baseline remains Ghidra 12.0.3 and Java 21-compatible bytecode. No libdwarf
producer declaration changes. The helpers are standalone C executables, so
validator crashes do not execute native code in Ghidra's JVM. The existing
libdwarf revision and native producer build are unchanged.

## Protocol

The explicit argv is:

```text
supervisor timeout-ms per-stream-byte-cap status-new stdout-new stderr-new -- absolute-tool [arguments...]
```

The Java caller creates an owned directory under the selected evidence parent.
The helper exclusively creates its three files; it does not truncate an existing
file or follow an existing symlink. The selected tool receives an empty stdin,
and stdout/stderr pipes are drained concurrently in bounded chunks to the logs.
The byte cap applies to bytes actually retained on disk, separately per stream.
Crossing it terminates the run and records the observed and retained counts.

Java keeps the helper's stdin cancellation pipe open while the run is active.
Closing it requests cleanup; it is not the tool's stdin. Java thread interruption
also requests cleanup and restores the interrupt flag after reconciliation.
A throwing cancellation callback triggers cleanup before reporting its failure.
No reader thread waits on a child-held output pipe in the JVM.

The monotonic execution deadline is at most one hour; each stream cap is at
most 256 MiB. Cleanup has a separate five-second native allowance. Java allows
another two seconds for helper reconciliation. Tool/helper file bytes and
ordinary identity/size/mtime observations are checked before and after execution.
These observations and log hashes are retained in the returned evidence; they
are not authenticated provenance or an adversarial filesystem snapshot.

A schema-1 status records reason, exit code/signal, cleanup completion and both
stream counters. Java reads at most 4096 bytes and rejects duplicate/unknown
fields, wrong primitive types, malformed/out-of-range integers and inconsistent
counts. It checks actual log lengths and hashes. A lifecycle `completed` result
only establishes execution/cleanup; a validator policy must still reject invalid
DWARF, unexplained diagnostics and incomplete or exit-zero failing reports.

## Linux ownership and API audit

The helper sets `PR_SET_CHILD_SUBREAPER` before fork, resets SIGCHLD to its normal
waitable disposition, closes unrelated child descriptors with `close_range`,
disables child core dumps and calls `execv` directly. Linux 5.9+ and a libc
providing `close_range` are required; CI uses the existing Ubuntu 24.04 host.
The Java runner requires UTF-8 native/JNU argument encoding, independently of
`file.encoding`, before creating evidence. It does not silently replace a path's
non-ASCII bytes in a legacy locale.

Orphaned descendants reparent to the helper. Cleanup enumerates its own direct,
unreaped children, sends SIGKILL, then reaps and repeats. This single-threaded
helper does not reap during enumeration/signalling: an exiting selected direct
child remains a zombie and its PID cannot be reused during that operation.
It never signals a late process-group identifier or treats an empty descendant
snapshot as proof of cleanup. Completion requires `waitpid` to establish ECHILD
and both output pipes to reach EOF.

The `/proc/.../children` interface can omit children during concurrent exit.
Repeated enumeration is therefore only a way to find work; ECHILD is the
completion authority. An omitted surviving child prevents success. Failure to
read the interface is checked before launching a tool and fails cleanup if it
occurs later. API references:
[child subreapers](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html),
[wait/reaping](https://man7.org/linux/man-pages/man2/waitpid.2.html),
[child-list limitations](https://man7.org/linux/man-pages/man5/proc_tid_children.5.html).

## Windows ownership and API audit

The helper uses native UTF-16 argv and `CreateProcessW` with an explicit executable
path and correctly quoted CRT arguments; it never invokes a shell. It creates
an unnamed Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and neither
breakaway flag. The child starts suspended, is assigned to that job, and resumes
only after assignment succeeds. An explicit inherited-handle list contains only
NUL stdin and the two output pipe writers; status/log/job/control handles are
not inherited. Cleanup terminates the job and requires its active-process count
to reach zero, the root process handle to signal and both pipes to reach EOF.

Sources use SDK types/prototypes rather than handwritten JNA structures. C
static assertions check DWORD/WCHAR/ULONGLONG widths. Local cross-compilation
passes with only KERNEL32/MSVCRT dependencies; that is not native execution proof.
CI exercises native cleanup, inherited pipes, attempted job breakaway, arguments
with spaces/quotes/backslashes/non-ASCII and actual Java interruption.
References: [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[explicit inherited handles](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[CRT argument parsing](https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments).

This is ownership for selected trusted validator programs and their ordinary
fork/exec or CreateProcess descendants, not a security sandbox. External service
brokers, hostile namespace/ptrace manipulation and external SIGKILL of the Linux
owner are not containment claims. A kernel/filesystem operation that cannot be
interrupted can outlive the cleanup budget. Such a run is an explicit failure,
with retained evidence and supervisor PID; Java does not kill the Linux owner
and abandon its descendants or turn the uncertainty into attachment approval.
No target replacement may follow incomplete validation.

## Packaging and evidence

`support/build-validator-supervisor.sh` compiles the helper twice and requires
byte-identical results. It records source commit, exact source/binary hashes,
compiler/options and dependencies; Windows also records installed SDK/CRT
package versions. Release assembly requires both helpers/provenance records and
matches their source hashes against the checked-out source and binary hashes
against the selected files. Platform and whole-release manifests include them.
`PackagedNativeLibraries.resolveSupervisor` uses the verified complete native
file set and rejects a missing/nonregular helper. Normal libdwarf resolution and
default export do not invoke the supervisor. Linux executable permissions are
retained in the packaged file; installed GUI execution still needs its own
end-to-end acceptance when the validator service is connected.

Local evidence in `build/supervisor/` and
`build/test-results/validator-supervisor/` includes:

- Thirteen native Linux cases: exact arguments/raw streams, nonzero/signal exit,
  stdout/stderr flooding, double-fork/session-changing orphans with retained or
  closed output pipes, timeout, cancellation, TERM and exclusive-file collisions.
- Thirty-two actual Java 21 checks: successful evidence, failure/overflow/orphans,
  timeout, cancellation, callback failure, thread interruption and malformed
  status controls. Independently observed fixture PIDs are gone after cleanup.
- Header-dependency/hash inventories for local Linux and MinGW compilation;
  native Windows runtime acceptance remains **PRESENT, UNVERIFIED**.
- Extension build, packaged-helper checksum/tamper checks, release assembly
  reproducibility/provenance rejection, workflow lint and architecture isolation.

The first Java compile used `bytes()` instead of the existing `byteCount()`
accessor; its failed log is retained. The first release regression omitted the
new required helper from a fixture intended to test missing third-party notices;
its trace is retained and the fixture now isolates the intended rejection.
Neither failure is counted as passing validation.

**PLANNED:** connect fresh GNU/LLVM/pinned-libdwarf execution and strict output
policy to `AttachmentOperation.Validator`, bind tool/output evidence to the
selected export, implement both production metadata hosts and expose explicit
CLI/GUI attachment. The helper and runner do not complete #72 or its A1–A7 rows.

### First hosted helper build follow-up

Run 41585498613 at `61e56f5` passed the Linux helper's build and lifecycle
checks. Windows compiled both helper copies and compared them successfully,
but metadata capture failed because the MSYS2 environment did not contain
`git`. Its native runtime tests therefore did not run. The raw job log is
retained locally at `build/supervisor/windows-ci.log`. The workflow now
explicitly installs MSYS2 Git; source revision capture remains mandatory.
Workflow lint passes. Corrected native Windows execution remains **PRESENT,
UNVERIFIED**, and this dependency correction does not complete live validation
or attachment host support.

The corrected dependency run 41586119200 built both Windows helper copies,
but its first ordinary successful Python invocation was reported as `descendants`
(exit code 0, complete cleanup, exact expected stdout/stderr). Raw job evidence
is retained at `build/supervisor/windows-runtime-ci.log`; the diagnostic archive
SHA-256 is `b062d063e094830ab6ff643a2f6d70b42424f0cbbab0f9344ee73f19f1bd8423`.
Microsoft's [job accounting contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)
counts a terminated process until its references are released. The helper kept
its own root process handle while requiring that accounting count to become
zero. It now records the signaled exit/code and closes that handle before querying
the job. Completion still requires zero active processes and both pipe EOFs;
the correction does not reinterpret a nonzero count as success. Twenty repeated
successful-exit controls supplement the existing orphan, timeout, cancellation,
breakaway and output-limit cases. Cross-compilation passes; corrected native
Windows runtime acceptance remains **PRESENT, UNVERIFIED**.

The repeated-exit controls in run 41587157999 caught a remaining race after
the handle correction: job accounting need not settle in the same observation
as the root's signaled exit. The helper now allows the entire job to finish
within the original execution deadline. It does not add a fixed sleep or accept
a nonzero count as cleanup. At expiry, unresolved membership is terminated and
reported as `descendants`; active-root expiry remains `timeout`. Either failure
still requires verified job-zero and both pipe EOFs before cleanup is reported
complete. Existing persistent-orphan tests retain their failure expectation.
The failed raw log is `build/supervisor/windows-root-fix-ci.log`; corrected
native Windows evidence remains required.

## Fresh strict DWARF check component

`StrictDwarfCheck` runs an explicitly selected raw libdwarf 2.3.2 checker through
`ValidatorSupervisor`, with `--file-name` selecting the existing pinned
configuration (SHA-256 `842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef`).
It preflights checker/configuration paths against every bound export input,
rechecks the full `AttachmentExportBinding` before/after validation, retains raw
bounded streams and rechecks their hashes. Empty stderr, successful process
cleanup and complete report interpretation are all required. The two-minute
execution deadline and 32 MiB per-stream cap are explicit resource limits;
exceeding either is failure, not partial validation.

The package-private `StrictDwarfReport` reads the pinned modern output format,
requiring compiler completion, every category in every check table, table sums
and the final tag-use report. Its returned analysis explicitly carries frame
diagnostics needing proof; parsing alone does not approve them. Other diagnostics,
unknown/missing/duplicate categories, truncation and overflowing counters fail.
The first local run exposed an invalid added assumption that global check counts
must equal the compiler-scoped counts: the retained clean 2.3.2 fixture has
function_coverage 20 for its compiler and 21 globally. The corrected parser
checks each table's complete arithmetic, matching the existing Python oracle.

For named `.eh_frame` sections, `InheritedFrameBytes` requires matching ELF
identity, PROGBITS section address/flags/size and exact payload bytes. The same
supervised checker must independently produce the same diagnostic multiset from
the unmodified original. The tool/helper hashes must agree across both runs.
This component does not yet corroborate frames in sectionless originals: the
complete validator still needs an independently bound section oracle path.
No requirement for sectionless attachment is waived by that implementation gap.

Local evidence under `build/test-results/strict-report/`:

- `runtime.log`: 271 actual Java 21 parser checks using retained clean, exit-zero
  failing, original-only, x86-64, AArch64 and MIPS BE reports and damaged copies.
- `*-java21/`: fresh supervised checks on three real Forge exports; three x86
  and five AArch64 frame diagnostics are independently corroborated, MIPS has zero.
  The initial direct Gradle test-class launch used local Java 25 test bytecode
  and failed on Java 21 before execution. The corrected probe is explicitly
  compiled with `javac --release 21` against the built production JAR.
- `controller-*-exec-final/`: full x86-64/AArch64/MIPS BE harness runs, including
  fresh GNU/LLVM/strict validation, supervised production checks, independent
  Python report interpretation, commit/rollback, automatic GDB source/type/value
  behavior and CRC mismatch rejection. The host and commit-time validator adapter
  are still explicitly test-only. Raw supervised evidence and tool/configuration
  provenance are retained separately from driver logs.
- Negative cases reject empty/truncated exit-zero reports, a modified configuration
  before launch, different original/sidecar frame diagnostic offsets, and an
  actual oversized DWARF unit with a freshly matching export-report hash. The
  latter reaches the real checker; a stale hash is not its rejection reason.

Target CI invokes this component with the helper in the installed release and
adds its controls to the existing real-ELF harness. Linux/Windows parser smoke
lists include the new test. Diagnostic artifact uploads explicitly retain the
owned hidden supervisor directories; otherwise their raw reports would be absent.
Native Linux supervisor regression (13 cases), extension build, workflow lint,
architecture isolation and diff checks pass. Corrected exact-head hosted checks
remain required. Neither this component nor its test adapters constitute the
complete `AttachmentOperation.Validator`: GNU/LLVM result policy, sectionless
frame corroboration, combined evidence publication, production host metadata and
public CLI/GUI remain open. Default export never invokes attachment.

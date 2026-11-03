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

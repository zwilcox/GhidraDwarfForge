# Synthetic source directory and perf lookup

**CONFIRMED locally; combined hosted acceptance pending:** the exporter records the
synthetic source output directory in the compilation unit's `DW_AT_comp_dir`,
using the same normalized directory already emitted in `.debug_line`. This is
truthful generated-source metadata, not a recovered original compilation path.
Default executable preservation, source contents and address mappings are unchanged.

## Observed consumer failure

The local perf 7.0.14 build discovers the matched Forge sidecar through a
private symfs build-ID directory, and lists its variables, but source listing
crashes when the CU has no `DW_AT_comp_dir`. The compiler control succeeds on
the same original bytes. A GDB backtrace reaches `path__join` from
`find_source_path`, with a null compilation-directory argument. The
[Linux v7.0 source](https://github.com/torvalds/linux/blob/v7.0/tools/perf/util/probe-finder.c)
passes that argument into `path__join` before its later null checks. Disabling
debuginfod does not bypass that path. Explicit `perf probe --source /` does.
An absent attribute is legal DWARF; the earlier artifact's structural validators
passed. Supplying the meaningful directory avoids this consumer crash and
makes the CU and line-table source contexts consistent.

## Native ABI and isolation

The binding adds only `dwarf_add_AT_comp_dir_a`, audited against exact source
commit `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993` (`v2.3.2`). All three downloaded
headers match the retained release headers byte for byte. Linux and MinGW64 C
signature probes compile with warnings as errors; the retained Linux and Windows
producer binaries both export the function. The Linux isolated Java producer
passes sixteen complete lifecycles, controlled errors and deterministic sections
before the new call is invoked inside headless Ghidra. Cross-compilation and
export inspection do not establish Windows JVM execution; the hosted native and
Windows exporter jobs remain required.

## Regression contract

`perf-source-lookup.py` consumes the existing floating-register fixture through
an owned original copy and a symfs build-ID root. It checks the CU directory,
actual source lines and float parameter declarations with compiler and Forge
symbols. Empty-root controls must fail with missing-debug information; a crash
is never accepted as a negative result. No explicit sidecar filename, source
prefix workaround or inherited user debug cache supplies the positive lookup.
The script preserves all input hashes and retains commands and raw results.

The existing floating-register pipeline invokes this check on x86-64 and
AArch64 non-PIE and PIE exports. The producer also runs rebased and repeated
exports, GNU/LLVM/pinned strict validation, GDB behavior, LLDB values and its
separate build-ID discovery controls. CI installs the generic Linux perf tools
and runs the actual installed binary for offline lookup, independently of the
runner's kernel version; each receipt records the observed perf version.

This check does not record events, install live probes or establish perf's
record/report cache behavior. The local host denies `perf record` with
`perf_event_paranoid=4`; no host setting was changed. It also does not implement
#109's production installer, source relocation, collision/update/removal policy
or interruption recovery. Those remain required work after #110 acceptance.

## Local acceptance checkpoint

The [receipt](evidence/synthetic-compilation-directory.json) binds the tested
native-inclusive package, all 210 production sources, exact header snapshots,
commands and raw archive. Twelve fresh exports pass on x86-64/AArch64 exec/PIE
with baseline, rebased and repeat samples. GNU/LLVM/pinned strict checks and
sixteen GDB sessions pass. Twenty-four LLDB scalar sessions and twenty-four
separate discovery sessions pass. The four perf cases pass sixteen positive
source/variable queries and sixteen empty-root rejection controls. Repeat
sidecars/source are byte-identical, and generated source is byte-identical to
the corresponding pre-change exporter output.

The archive preserves the original perf crash and failed harness attempts.
The first harness expected a different missing-debug diagnostic; the corrected
assertion retains both observed bounded forms and still rejects crashes. A
subsequent complete set of runtime checks ended in a shell error after that
script was edited during execution, so it is not counted as a passing run.
The accepted final run executes a frozen text snapshot, confirms the source
stayed unchanged, reaches the final success marker and exits zero. Workflow
Actionlint with ShellCheck and the script's recursive ShellCheck pass.

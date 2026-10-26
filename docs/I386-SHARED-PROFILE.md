# Bounded i386 shared-library profile

**CONFIRMED locally on the calling-convention candidate; hosted acceptance pending:**
fresh shared/direct revalidation passes eight roles, sixteen deterministic
exports and 3,000 GDB observations with the new producer JAR. Independent raw
review verifies identity, exact locations/types/names and byte-identical shared
inputs. Twenty-two actual Java 21 suites apply to the identical production JAR;
sixteen fresh packaged i386 producer lifetimes also pass. Receipt SHA-256
`9d5a8efaf99b9aa84176c41e84005a9372686bea62fa686eaa81e1a23794b900`.
Submission remains held until PR65's correctness fix completes its hosted gate.

**CONFIRMED locally; hosted acceptance pending (2026-10-25).** The
i386 production exporter with PR64's control-flow correction handles a dynamically loaded integer/stack library
from non-PIE and PIE drivers, with ordinary and explicitly rebased Ghidra
programs. The added code is fixture, harness and CI coverage. This extends the
evidence in [the initial profile](I386-INTEGER-PROFILE.md), which was accepted
through PR63. This shared-library extension requires its own hosted gate.

The fixture uses the system 32-bit Linux loader and no libc functions or startup
objects. CI explicitly installs `libc6-i386` for that loader. It does not claim
libc ABI coverage, alternate calling conventions, x87/SSE/vector locations,
aggregate returns, injected calls, arbitrary shared-loader configurations or
Windows-hosted i386 runtime/GUI support.

## Evidence and name lookup

One committed conditional C fixture produces the original standalone program,
a PIC shared library and a freestanding driver. All four shared cases have
byte-identical compiler references and stripped library inputs, including build
IDs. Driver roles differ between ET_EXEC and PIE. Rebase roles change only the
saved Ghidra address space; emitted locations remain normalized to the original
library's link-time addresses.

Ghidra receives the library with compiler debug information and the ordinary
symbol table removed. Required dynamic symbols remain. The analyst-curated
names `forge_scalar`, `forge_wide` and `forge_aggregate` are absent from those
original tables. Explicit signatures use Ghidra-computed stack storage. Reopened
read-only exports preserve the saved choices and produce identical output pairs.

The debugger disables automatic shared-library symbols and debuginfod. It stops
in the driver after loader startup, independently observes the mapped library
base, and explicitly loads the compiler reference or Forge sidecar at that bias.
Before loading Forge, all three curated names must be absent. Afterwards both
original and curated expressions resolve to the same function addresses. Every
selected function source record belongs to the explicitly loaded artifact.

Three input sets exercise signed scalars, a 64-bit stack argument/return and an
eight-byte by-value integer structure. Every instruction in all three functions
is checked, including PIC helper calls and stack adjustments. Raw incoming stack
bytes, named parameters and nine returns agree with the compiler oracle. Positive
first-use stack locals retain name/type while remaining unavailable under the
existing conservative policy. Source `list`, `ptype`, `next` and `step` work; a
fresh second invocation verifies source navigation without corrupting return
observations. The driver's single ROUND source line can step directly from the
scalar return into the next function; that destination's exact arguments and
source position are checked.

Independent raw review decodes each ELF32 location list and evaluates every
SP-relative expression against recorded runtime ESP and entry ESP. It also
checks dynamic symbol type/address/size, signed types and structure layout,
original/build identity, runtime instruction bytes, source ownership, unavailable
local DIEs, project preservation and byte-identical repeats. GNU/LLVM pass and
strict checking reports zero errors for every reference and emitted sidecar.

This is positive coexistence of curated DWARF names and preserved original ELF
symbols. It does not implement `DW_AT_linkage_name`, manufacture symbols from
imported labels, or complete aliases, C++ namespaces or linkage classification.

## Local acceptance

Four shared roles pass eight exports and 1,560 compiler/Forge instruction-boundary
observations. All four original direct roles are rerun because their shared GDB
and curation helpers changed: eight more exports and 1,440 observations pass.
**HISTORICAL preceding-package checkpoint:** 16 exports and 3,000 GDB
observations used the then-unchanged production JAR:
`fc5a90f5e4ce609e5534acb8493a56cc4f312a44c1dc2d1710cad8d90872a5ab`.
Its preceding twenty actual-Java-21 suites and sixteen isolated producer
lifetimes remain applicable; they were not rerun or counted as new executions.
These local headless exports use Java 25.

```text
build/i386-shared-review/acceptance.json
SHA-256 17770729f345af7ca5213fb06a578fa6dd37caaf1eeddd20e932dce0ced5f34d
final inventory: build/i386-shared-review/identical-input-matrix.log
shared cases: exec.i4hizlg5, exec-rebased.trp2wt4f,
              pie.9hd7fv4o, pie-rebased.g9kr27ca
direct cases: exec.ivktaqlw, sectionless.d17fg0n9,
              pie.7vrethft, pie-rebased.w4ikzikt
```

With a packaged Ghidra installation, 32-bit loader, GCC/GDB and configured strict
checker, run `src/test/integration/i386-shared-profile-export.py` with that
installation and each `--role exec`, `exec-rebased`, `pie` and `pie-rebased`.
The existing direct harness retains its four-role regression coverage.

The full hosted gate and independent downloaded-package/runtime/GUI review remain
**PRESENT, UNVERIFIED** for this follow-up. No release publication is included.

## Retained failures and superseded evidence

The first shared pilot `exec.hoj236dh` passed all value/return checks but rejected
a source step into `forge_wide`: its oracle incorrectly allowed only scalar or
the caller. The original script/log are retained. The corrected check requires
that destination's exact first-round arguments and records both source stops.

The first eight-role matrix passed its individual tests, but generated source
paths changed library build IDs across cases. Its sources, log and explicit
comparison limitation remain under `retained-generated-source-matrix/`; the final
committed-source matrix above replaces it for rebase comparison.

The first independent review incorrectly expected an original-source path when
the direct Forge program stepped into its own synthetic `_start`. That audit
failure and source remain as `retained-audit-direct-source.*`. The corrected
review distinguishes the separate shared driver from a directly exported
program; it changes no artifact or runtime test and passes the final receipt.

Workflow lint, seven architecture controls, all five ordinary fixture
reproducibility profiles and the extension build also pass locally. An initial
verification command used a nonexistent `.sh` spelling for the Python architecture
smoke; the exit-127 log is retained and the corrected `.py` invocation passes.

## Corrected exporter revalidation

PR64's control-flow correction was merged through normal history before the
shared-library submission. Fresh shared exec/exec-rebased/PIE/PIE-rebased and
direct exec/sectionless/PIE/PIE-rebased cases pass sixteen exports, 3,000 GDB
observations and the complete independent raw audit, including byte-identical
shared inputs, library load biases, exact typed locations, curated/original
symbol lookup and source ownership at every tested instruction.

Corrected JAR SHA-256:
`7721cfd99fb86e791aebfd9bbde6f2a11ab19e749af62bdf8447093fe7f8bca7`.
The exact twenty-one actual Java 21 model-suite runs from the correction are
bound by that identical JAR; sixteen new isolated packaged i386 producer
lifetimes pass on actual Java 21. The original twenty-suite/producer receipt
above is historical and is not used as acceptance of the changed JAR.

Fresh independent receipt:
`build/i386-shared-review/flow-acceptance.json`
SHA-256 `b33566ade02c64de6d80034e5bb39c6e6d2c1a82693572ca5fa70fa16ea1822d`.
Runtime evidence: `flow-corrected-matrix.log`; native evidence:
`native21.klml1fj_/result.json`. Hosted submission remains held until the
correctness fix passes its complete gate and independent artifact review.

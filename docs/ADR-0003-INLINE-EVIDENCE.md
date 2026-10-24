# ADR 0003: Require explicit evidence for reconstructed inline instances

- Status: accepted; P3.4 investigation complete, inline export not implemented
- Decision date: 2026-10-23
- Inspected baseline: Ghidra 12.0.3, the supported extension host version

## Decision

Do not derive `DW_TAG_inlined_subroutine` or compiler `DW_AT_inline` claims
from Ghidra's `Function.isInline()` flag, decompiled text, comment strings, or
source rows alone. Keep inline-instance emission deferred until an explicit,
provenance-bearing instance model meets the acceptance conditions below.
This closes the bounded investigation, not an implementation milestone.

Retain the current exports of defensible function, type, variable and source
information. This decision does not discard Ghidra's imported locals or source
maps, and does not assert that every possible Ghidra extension, debug input or
future API lacks inline information. A separate evidence provider could be
implemented later without weakening the current honesty requirement.

## Information needed by a debugger

DWARF distinguishes an abstract subroutine from concrete inline instances.
An instance can carry its containing scope, machine-code ranges, origin
references, call coordinates and instance-specific parameter/local locations.
These relationships let a debugger present inline frames and distinguish
multiple expansions of the same subroutine. A function-level analysis flag
or a filename/line/address row does not establish that hierarchy. See
[DWARF 5, section 3.3.8](https://dwarfstd.org/doc/DWARF5.pdf).

## Ghidra 12.0.3 source findings

The research harness extracts these files from the selected installation's
source archives and help JARs and records their SHA-256 hashes. Paths below
are archive entries, not a moving upstream branch.

| Evidence | Observed behavior |
|---|---|
| `SoftwareModeling-src.zip`: `ghidra/program/model/listing/Function.java`, `FunctionDB.java` under `ghidra/program/database/function/` | `isInline()` / `setInline()` read and set a function flag; the database implementation delegates through thunks and disallows the flag on external functions. This is not a concrete instance record. |
| `SoftwareModeling-src.zip`: `ghidra/program/model/pcode/HighFunction.java`, `encode()` | Sends that flag as `ATTRIB_INLINE` to the decompiler. |
| `Base.jar`: `help/topics/FunctionPlugin/Variables.htm`; `Decompiler.jar`: `help/topics/DecompilePlugin/DecompilerAnnotations.html` | The flag directs analysis/decompilation to incorporate a called function's effects into its callers. This may happen while the executable still contains a real call. |
| `Base-src.zip`: `ghidra/app/util/bin/format/dwarf/DWARFFunctionImporter.java`, `processInlinedSubroutine()` | Reads existing compiler inline DIEs, optionally adds comments, and processes their children in the containing `DWARFFunction`. Qualifying inline locals can survive as locals of that parent. Imported inline information is **not** wholly discarded. |
| `Base-src.zip`: `ghidra/app/util/bin/format/dwarf/DWARFFunction.java`, `getFuncBody()` | The importer requests `flattenDisjoint=true` for the inline body used by that path. This reduces its ranges to one encompassing interval for comments/child processing; it is not a retained exact instance-range list. |
| `Decompiler-src.zip`: `ghidra/app/decompiler/ClangFunction.java`, `ClangNode.java` | `ClangFunction` groups one decompiled `HighFunction`; token nodes expose address bounds. These inspected interfaces do not supply a complete compiler-inline origin/call-site tree. |
| `SoftwareModeling-src.zip`: `ghidra/program/model/sourcemap/SourceMapEntry.java` | A source-map entry records source file, line, base address and length. It has no inline-instance parent/origin/call-site identity fields. |

The source analysis is deliberately limited to the APIs/import path the
current exporter could use. Original compiler DWARF may still exist in an
input file or imported memory. Parsing it again would be a separate evidence
provider, with image-identity, provenance and analyst-edit reconciliation
requirements; it would not be recovery from the inline flag.

## Reproducible probe

Run on Linux x86-64 with GCC, GNU readelf/objcopy, LLVM dwarfdump, GDB and the
Ghidra 12.0.3 distribution, including its source archives:

```bash
src/test/research/inline/run.sh /path/to/ghidra_12.0.3_PUBLIC
```

The harness builds the repository-owned `inline-evidence.c` with GCC `-O2 -g
-gdwarf-5`. It has two forced compiler-inline expansions and a separate
`noinline` callee/caller pair. A second input removes only compiler debug
sections, retaining ordinary function symbols so both probes select the same
machine functions. The harness runs both inputs and hashes them before and
after Ghidra. It never patches them or installs an extension.

For the debug input, readelf and LLVM establish actual inline DIEs and origin/
call-site attributes. GDB stops inside the first compiler-inline instance,
shows its frame and containing caller, reads the argument/local, and continues
to normal exit. Ghidra is then imported and analyzed with inline comments,
local-variable import and source-line import explicitly enabled. This is an
inspection-friendly configuration, not a claim about every default option.

The Java probe records listing functions/locals, source rows, comments,
decompiled C and markup node kinds. In each input it separately marks the
ordinary callee inline, uses a fresh decompiler to avoid cached results, and
compares high-pcode calls with actual instruction flows. It restores the flag
in `finally` and disposes each decompiler. Projects are temporary and deleted
by headless Ghidra; logs and source snapshots remain under
`build/test-results/inline-evidence/run.*/`.

### Observed result

**CONFIRMED:** the probe passes with GCC 13.3.0, GDB 15.1, LLVM 18.1.3 and
Ghidra 12.0.3 on Linux x86-64. A compact transcript and source hashes are
retained in
[`research/inline-evidence-12.0.3.txt`](research/inline-evidence-12.0.3.txt).

- GCC emits two `DW_TAG_inlined_subroutine` instances referencing one abstract
  `compiler_inline` definition, with separate ranges and call lines 12/13.
  GNU DWARF dumps have empty stderr; LLVM verification reports no errors.
- GDB presents `compiler_inline(value=4)` above `inline_caller` and reads
  `inline_local=11`; execution exits normally. This demonstrates the useful
  behavior a future exporter would need to reproduce. It is compiler-oracle
  behavior, not a Forge inline-frame test.
- The Ghidra debug import retains `inline_local` and `inline_local_1` as
  `IMPORTED` locals of `inline_caller`, 20 intersecting source rows, and two
  optional inline comments. It creates no separate listing function for the
  compiler-inline definition. The containing function's inline flag is false.
- With debug sections removed, the listing has default stack-local names,
  no imported inline locals, no source rows and no inline comments. The
  compiler-inline instructions still exist in the caller.
- Both decompiler outputs contain one `ClangFunction`, not nested function
  groups for the two compiler expansions. This is an observation of this
  fixture and these inspected APIs, not an exhaustive proof about all Ghidra
  metadata providers.
- The separate ordinary call remains present in machine instructions before
  and after `setInline(true)`. Its high-pcode call count changes from one to
  zero; decompiled C changes from a call to `ordinary_callee` to its arithmetic
  expression and an inlining warning. The flag is demonstrably independent of
  compiler inlining.
- Original file hashes match after both probes.

The Ghidra debug importer reports three unrecoverable `DW_OP_reg5` expressions
for this optimized input and comments that `first`/`second` cannot be resolved.
The transcript retains this diagnostic; passing the investigation does not
mean the importer preserved every optimized location. The two stack-backed
inline locals do survive. JVM 25 also logs its existing Felix `Unsafe`
deprecation warning. Neither warning is suppressed or described as a clean
Forge-export validator result; this probe does not emit a Forge sidecar.

## Conditions for implementing inline export

1. Introduce an explicit model for abstract/origin identity, each concrete
   instance's parent, exact nonempty ranges, any defensible call coordinates,
   and instance-specific parameters/locals. Record where each fact came from
   and what remains unknown. Do not infer identities by parsing comment text.
2. If compiler DWARF is the provider, verify it describes the same input image
   and define how current analyst edits take precedence. Preserve source
   provenance; do not present compiler lines as synthetic source lines or
   invent unavailable call coordinates. Existing debug-metadata replacement
   policy remains in force until an explicit merge design is validated.
3. Demonstrate multiple and nested instances, disjoint/overlapping optimized
   ranges, ordinary callees marked inline only for decompilation, stripped
   inputs without evidence, rebasing and changing/unavailable locations.
   Unknown evidence must not produce invented inline frames or values.
4. Implement and independently validate the DWARF origin/scope/range/location
   relationships. Prove GDB backtraces, frame selection, source stepping and
   local values at multiple instances against compiler or analyst evidence,
   while preserving original hashes and deterministic output. Extend target
   claims only after corresponding native/QEMU tests.

Until these conditions hold, no inline-DIE support claim is made. P3.4's
investigation has a concrete recorded outcome; implementation remains
deferred by this evidence policy and is not marked complete.

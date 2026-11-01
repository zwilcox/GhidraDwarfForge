# Wider MIPS aggregate alignment and live-session allocation

**CONFIRMED defects; candidate acceptance in progress.** This continues the
original P2.3a/#69 allocation requirements. It does not complete #69 or the
combined #68–#71 goal.

## Aligned aggregate slots

GCC 12.4's `mips_function_arg_boundary` caps parameter alignment at the ABI's
stack boundary. For N32/N64 this is 16 bytes, including types with stronger
explicit alignment. A 16-byte-aligned pair after one integer skips slot one
and uses `a2/a3`. The pinned Ghidra `MultiSlotDualAssign` uses datatype alignment
for stack allocation, but does not skip odd register slots. The preceding
candidate therefore selected `a1/a2`. A model regression fails on that exact
mismatch; independent compiler disassembly and ordinary execution corroborate
`a2/a3` in both N32 and N64.

The isolated allocation policy consumes an alignment hole using a temporary
word in its prototype input. It maps results back to the original parameter
indices, accounting for automatic hidden-return arguments, and never exports
the placeholder. The temporary aggregate shape caps alignment at 16. Original
return allocation, analyst signatures, types, custom storage and the saved
program remain unchanged. Neither the generic location engine nor native
bindings change.

Four added source functions exercise a 16-byte integer pair and a 32-byte-
aligned mixed floating/integer structure, including register exhaustion and
stack alignment. A compiler-required 32-byte object remains 32 bytes in the
formal type even though its argument boundary is capped at 16. Compiler body
values and all Forge entry/body values must match source-known literals.
Compiler entry displays remain observations before their stack homes exist.

## Prototype observation must not change the selected ABI

The live-import probe exposed another defect: newly analyzed N32 programs
serialize their default prototype differently from a reopened program.
`PrototypeModel.getKilledByCallList()` lazily changes null to an empty array;
serialization then adds `<killedbycall/>`. The exact hash guard rejected the
otherwise identical model, disabling the allocation correction during export
from that live session. A real old-package export displayed
`9.647379751405547e-101` instead of `1.25` for the first array element. Its
validators did not detect the semantic mistake.

The pinned Ghidra source and fresh/reopened XML comparison establish this exact
non-semantic difference. Fingerprinting now omits only `<killedbycall/>`.
Nonempty lists and all other serialized bytes remain strict. Tests reproduce
the getter-triggered rejection, prove identical allocation after observation,
and require rejection of a changed nonempty register list. The actual original
XML is retained when constructing the allocation model.

`mips-live-import-export.py` imports and analyzes an owned binary, curates its
types, then invokes the installed production exporter twice without closing the
program. `RepeatLiveAbiExport.java` requires byte-identical artifact pairs.
GNU/LLVM/pinned strict validation and the full layout GDB oracle run against the
live export. The main layout driver requires this additional check after its
existing saved-program and failure/cancellation checks. This is required
headless live-session coverage; it is not a new GUI acceptance claim.

## Evidence and limits

The allocation model passes 434 checks, including both ABIs and byte orders,
odd slots before and after register exhaustion, 16/32-byte-aligned types,
immutable/deterministic signatures, hidden-return alignment and strict guard
negatives. The shared dynamic/composite/indirect/custom-storage and MIPS call
policy regressions pass. Commands and raw results are retained under
`build/mips-aligned-composites/` in `work/mips-aligned-composites`.

Candidate v1 passes all 20 saved-program ABI/endian/layout cases, including
all failure/cancellation compositions. Each case requires 124 Forge entry/body
values and 62 compiler-body values. Receipt: `matrix-v1.json`.
ZIP: `6d24879cde2fc1eb8a62c09466c0f6d3294e0e00617396e739b5f2437de7fafe`.
JAR: `428b8ff40c2b7fa3f132e626424b41ddcf2fd64dfa9c005144ce143920e95b2b`.

Candidate v2 additionally corrects the live-session fingerprint. Its expanded
model tests and full rebased-PIE N32 big-endian and rebased-shared N64
little-endian driver replays pass, including saved exports, failure/cancellation
and live-session checks.
All 20 live-session cases pass: 40 exports and 2,480 exact values. An
independent review checks 1,200 new aligned-field values against literal source
inputs, artifact hashes and strict reports (`live-v2-review.json`). The runtime
receipt is `live-v2.json`.
ZIP: `1a75e5ca2de87ba0a74157f22498fa494110e8114c31622825f3c811d1cfd385`.
JAR: `791d4ed8dbebd718950616931c4bc3d19581894c3849cc5d13241e05cde5ffee`.
The failed v1 model, live export and GDB logs are retained, alongside the exact
fresh/reopened XML snapshots. No failed attempt is counted as a pass.

**PLANNED acceptance:** exact-head hosted validation, review and protected
integration remain. Broader all-instruction/clobber lifetimes, unnamed-slice
copy recovery, additional alignment and wider floating/return types, FPXX/FP64A
references, and every remaining original architecture requirement stay open.
PR127/PR128 must not be treated as completing live N32 allocation without this
follow-up correction. The existing restrictive debugger-call policy for the
new composite types remains unchanged.

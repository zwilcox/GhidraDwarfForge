# Standalone DWARF checker correction

This patch applies only to the independently built **validation executable**
from libdwarf 2.3.2. It must not enter the shipped producer/consumer library
builds, their source patch set, or release-native provenance manifests.

- Upstream revision: `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993` (`v2.3.2`).
- Source archive SHA-256:
  `7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`.
- `0001-check-line-sequences.patch` SHA-256:
  `69340f63ee78c06309731a40bb1e0e9e193b5d2f659e5f050ef413138649f696`.
- Modified upstream file: `src/bin/dwarfdump/print_lines.c` only.

The unmodified checker compares the final line-table address to a remembered
subprogram `high_pc`. A compiler may emit one instruction sequence covering
multiple functions; the remembered DIE boundary is not a sequence boundary.
This creates a false error on the source-built timestamp and large-file
container fixtures, whose DWARF is emitted by GCC and preserved by Forge.

[DWARF 5](https://dwarfstd.org/doc/DWARF5.pdf) defines an instruction sequence
independently of a subprogram in Section 6.2.1 (printed page 150), defines
`end_sequence` in Section 6.2.2 (page 151), and requires a terminating
`DW_LNE_end_sequence` in Section 6.2.5.3 (page 164). Its line matrix uses ordered
operation pointers within a sequence (Section 6.2.5, page 160). Sequence order
itself need not follow increasing code addresses.

The correction replaces the function-boundary assertion with checks that:

- Addresses do not decrease within a sequence; equal-address rows remain valid.
- Ordering restarts after an actual `end_sequence` row.
- The final non-skipped row has `end_sequence` set.

The existing address-bucket checks, error accounting and stripped/linkonce
`SkipRecord` policy remain intact. The pinned public API exposes the address
and end flag but no `op_index` accessor, so this patch checks the address
component only; it does not claim complete VLIW operation-pointer validation.
No shared-library source, public API, JNA declaration or Forge artifact changes.

## Focused regression

`src/test/integration/dwarfdump-line-sequences.py <patched-dwarfdump>` builds a
small compiler-DWARF ELF without frame tables. It preserves the original and
creates separate copies with controlled line programs. A compiler sequence
spanning three functions and ascending/reversed discontiguous sequences pass;
equal-address rows pass; backward addresses inside one sequence, a missing
final marker and addresses outside the image produce nonzero check summaries.
The test checks the actual summaries because libdwarf can return exit status
zero even after reporting errors.

Optional `--unpatched <dwarfdump-2.3.2>` reproduces the original compiler false
positive. Optional `--forge-fixture <sidecar>` checks a real Forge sidecar and
requires both CU and discontiguous-function direct DWARF 5 range lists. That
fixture must have no unrelated validator diagnostics. It also creates two
separate malformed range copies. LLVM must reject the corrupted parent/child
range relationship: current libdwarf alone misses these corruptions, just as
LLVM alone misses the out-of-image line-address control. Both validators are
therefore required; neither is a substitute for the other or for GDB behavior.

For example, after extracting the verified archive into a private directory:

```bash
patch -d /private/libdwarf-2.3.2 -p1 < support/validation/0001-check-line-sequences.patch
cd /private/libdwarf-2.3.2
./configure --enable-static --disable-shared --disable-dwarfgen
make -j4
```

From the repository:

```bash
src/test/integration/dwarfdump-line-sequences.py \
    /private/libdwarf-2.3.2/src/bin/dwarfdump/dwarfdump \
    --unpatched /private/unpatched/dwarfdump \
    --forge-fixture /private/arm32/scopes.dbg
```

## Local evidence, 2026-10-23

**CONFIRMED locally:** the static validation executable built from the pinned
archive and this patch. The complete focused regression passed in
`build/test-results/dwarfdump-line-sequences/run.4dilzq8t/`, including the
unpatched positive-to-negative control and a real ARM sidecar with entry-first
function ranges. An independent reviewer repeated it successfully in
`run.j6iv2ep4/`. Compiler input/source and the original Forge sidecar stayed
byte-identical. The four retained GCC timestamp/large-container artifacts lose
only the incorrect line-sequence diagnostics; their frame diagnostics remain.

Independent review also reran all 71 retained `.dbg` artifacts from the five
corrective target lanes: 43 have zero errors and 28 report only inherited
frame-length diagnostics. No line diagnostic, process failure or stderr remains.
Those 28 results are **not** a zero-error pass: the strict runner must separately
corroborate the exact original ELF frame bytes, target identity and complete
same-version diagnostics. This patch does not suppress frame errors or introduce
an original-DWARF exception. The combined strict pipeline and publication gates
remain the responsibility of the integrating change.

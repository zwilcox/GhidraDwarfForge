# Standalone DWARF validation corrections

These patches apply only to the independently built **validation executable**
from libdwarf 2.3.2, including its statically linked ELF consumer. Neither may
enter the shipped producer/consumer library builds, their source patch set,
or release-native provenance manifests.

- Upstream revision: `af7b278c6aa2ae9daad94fb7f8bffdc0e9980993` (`v2.3.2`).
- Source archive SHA-256:
  `7992e7b9019ebfabdda5773e86243517c48cf89fafed3209e853692bc9573efd`.
- `0001-check-line-sequences.patch` SHA-256:
  `69340f63ee78c06309731a40bb1e0e9e193b5d2f659e5f050ef413138649f696`.
- Modified upstream file: `src/bin/dwarfdump/print_lines.c` only.
- `0002-accept-bounded-extended-program-count.patch` SHA-256:
  `8468426396e6a28f755077681eec78d326744a535c7aade9d17d9a1acef73b46`.
- Second patch modifies `src/lib/libdwarf/dwarf_elf_load_headers.c` only, in
  the validation executable's private static dependency.

## Line-sequence checks

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
The line-sequence patch changes no library source, public API, JNA declaration
or Forge artifact. The separate reader correction below applies only to the
standalone executable's static consumer, never to shipped native libraries.

## Extended program-header counts

PR #22's first hosted run, `40061424810`, reached a separate upstream reader
limitation while corroborating frame diagnostics on the actual original ELF.
Both ELF32 and ELF64 readers reject every nonzero section-zero `sh_info` as
`DW_DLE_IMPROPER_SECTION_ZERO`, including valid `PN_XNUM` inputs. The x86-64
and AArch64 originals have canonical extended counts 65549 and 65545; their
sidecars have no program headers and were accepted, with only the expected
inherited frame diagnostics. The strict runner correctly refused to treat
the original's failed initialization as corroboration.

[Linux's ELF definitions](https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h)
and [glibc's ELF definitions](https://github.com/bminor/glibc/blob/master/elf/elf.h)
define `e_phnum = PN_XNUM (0xffff)` with the actual count in section zero's
`sh_info`. The Linux header also cites the Solaris linker documentation and
AMD64 ABI supplement. This extension must not be confused with the older
generic section-zero table that unconditionally lists `sh_info = 0`.

The second patch preserves the ordinary zero-`sh_info` rule and every existing
section-zero check. It permits the extended count only when it is at least
65535, the declared ELF header is at least the class's header size, the program
table starts after that header, each entry is at least the class's record size,
and the complete claimed table fits in the file. Subtraction and division avoid
overflow; there is no count-proportional allocation or scan. The consumer still
does not interpret program headers, and no public API or JNA signature changes.
Malformed inputs remain errors; the strict runner gains no diagnostic exception.

`src/test/integration/dwarfdump-extended-programs.py <patched-dwarfdump>` builds
independent small DWARF5 metadata fixtures in ELF32/64 and both byte orders.
Ordinary counts and genuine extended tables with 65535 and 65536 records pass.
Controls reject ordinary nonzero `sh_info`, zero/small/oversized extended
counts, absent/inside-header/overflowing table offsets, truncated tables,
zero/undersized entries, undersized/overlapping ELF headers and invalid
section-zero name/flags/address fields. Negative controls require an ordinary
checker return with empty stderr and the precise diagnostic; a native crash
does not count as a successful rejection.
A GCC-built fixture also passes before and after adding a real extended table;
LLVM independently verifies the extended compiler fixture. These metadata
fixtures do not establish new target execution support.

Optional `--previous-tool <line-patch-only-dwarfdump>` reproduces the original
rejection in all four class/endian combinations. Optional
`--hosted-root <digest-verified-extracted-target-artifacts>` rechecks the actual
x86-64 and AArch64 original/sidecar pairs through the strict helper, preserving
both input hashes and requiring exact inherited-frame corroboration.

Other upstream checker limits remain: its allocated-section envelope is coarse
and scans at most the first 50 sections. The sectionless fixture oracle compares
generated extents directly to every original nonempty `PT_LOAD` and checks all
emitted location intervals against executable segments independently. GNU,
LLVM and GDB tests remain complementary checks.

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

For a real fixture with inherited frame diagnostics, additionally pass
`--forge-original <original-elf>`. The positive check then delegates to
`check-dwarfdump.py --tool <patched-tool> --original <original-elf>`, which must
corroborate exact frame bytes, target identity and same-version diagnostics.
The sequence regression adds no diagnostic allowance of its own. It verifies
the original hash and still requires both malformed range copies to fail LLVM.
Without this option, the original zero-diagnostic positive check is unchanged.

For example, after extracting the verified archive into a private directory:

```bash
patch -d /private/libdwarf-2.3.2 -p1 < support/validation/0001-check-line-sequences.patch
patch -d /private/libdwarf-2.3.2 -p1 < support/validation/0002-accept-bounded-extended-program-count.patch
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

The main x86 integration fixture can exercise the same complementary range
controls after its real export:

```bash
src/test/integration/dwarfdump-line-sequences.py /private/patched/dwarfdump \
    --forge-fixture build/fixtures/x86_64/semantic.exec.ghidra-forge.dbg \
    --forge-original build/fixtures/x86_64/semantic.exec.stripped
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

**CONFIRMED locally:** the reader correction passes the extended-program
regression in `build/test-results/dwarfdump-extended-programs/run.nmxbmlqs/`:
16 positive checks (including the two exact hosted pairs), 60 rejecting
malformed-header controls, four reproductions using the previous tool, and the
compiler fixture's LLVM check. The actual hosted originals now produce exactly
the sidecars' three x86-64 and five AArch64 frame diagnostics. Neither original
nor sidecar changed. Full rerun evidence and publication gates belong to the
integrating change; this local result does not make the failed hosted run pass.

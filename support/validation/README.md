# Standalone DWARF validation corrections

## Pinned target debugger profiles

`build-mips-gdb.py` also builds an isolated, unmodified GDB 17.1 executable from
a checksum-pinned GNU archive. Its default MIPS profile remains unchanged.
`--target-profile arm32` selects `arm-linux-gnueabihf` for the BE8 floating
register-piece tests; ordinary ARM tests continue using the system debugger.
Each build records source/executable hashes, command logs, a Python smoke check
and its private data-directory path. It never installs over the system debugger.
See `../../docs/ARM-BE8-PROFILE.md` for the GDB 15.1 failure and the paired 17.1
reference. These debugger builds are validation tools, not shipped libraries.

## Private ARM emulator reference

`build-arm-qemu.py` is a separate, optional compiler-reference tool builder. It
pins QEMU 8.2.2 and can apply only
`qemu-8.2.2-arm-d-register-byte-order.patch` (SHA-256
`e1b8d5a11ec610961c10bc2b6d2af9c65be86340bf1ecbadb837d98c26b07f2f`).
The one-line correction makes ARM D-register remote writes use the same target
byte order as reads. It does not change Q-register writes, shipped libraries or
the system QEMU installation. See `../../docs/research/ARM-PCS-CALL-REFERENCE.md`
for paired unmodified/corrected evidence and remaining per-function PCS limits.
Build prerequisites are a C/C++ toolchain, Python 3.12, Ninja, pkg-config, GLib
and zlib development files; an optional `--dependency-root` points to privately
extracted Ubuntu development packages. A fresh private directory is required.

## Standalone libdwarf patches

These patches apply only to the independently built **validation executable**
from libdwarf 2.3.2, including its statically linked ELF consumer. None may
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
- `0003-preserve-bounded-harmless-diagnostics.patch` SHA-256:
  `e9f7eb0e613b4a4e859377ad12563ad514d24f7ee81b04378a30b8e99e403139`.
- Third patch changes `src/bin/dwarfdump/dwarfdump.c` and the validation-only
  static consumer's `src/lib/libdwarf/dwarf_harmless.c`; public APIs and shipped
  producer/consumer sources remain unchanged.

## Function-pointer calling conventions

The fourth patch recognizes `DW_AT_calling_convention` on
`DW_TAG_subroutine_type` in the checker's existing **extension** table. It does
not add the pair to the standard DWARF 5 table. DWARF 5 Appendix A omits this
pair; LLVM deliberately emits it for explicit function-pointer conventions
([LLVM 20.1.8 DwarfUnit.cpp](https://github.com/llvm/llvm-project/blob/llvmorg-20.1.8/llvm/lib/CodeGen/AsmPrinter/DwarfUnit.cpp)).
GDB reads the attribute, including `DW_CC_nocall`, when evaluating calls through
typed pointers. A local Clang 16 compiler-produced fixture reproduces the old
checker's rejection independently of Forge. The change recognizes that
established producer/consumer extension, not a new core-standard guarantee.

`0004-recognize-subroutine-calling-convention.patch` has SHA-256
`a1b5cc6d63795aeda62b5945bf8991360882c7334003e9912e274638ec073581`.
It updates `src/bin/tag_attr/tag_attr_ext.list` and its generated
`src/bin/dwarfdump/dwarfdump-ta-ext-table.h`. Other tag/attribute combinations,
forms, reference checks and strict diagnostic parsing remain active. The
validator evidence profile explicitly records the fourth patch. This patch is
excluded from shipped native libraries, like the other validation patches.

`dwarfdump-subroutine-conventions.py` builds 32 independent metadata cases
across ELF32/64 and both byte orders. Normal, no-call and LLVM Win64 conventions
pass. Invalid tag/attribute combinations, a reserved convention value, a string
form for the convention and a broken type reference fail strict checking.
LLVM independently rejects the broken reference but misses the invalid
convention form; its clean result alone is insufficient. The optional previous
checker reproduces the compatibility rejection for all twelve positives.
No target instructions execute in these metadata controls.

## Self-contained configuration

The standalone consumer also requires upstream `dwarfdump.conf`, even without
an explicit ABI selection. Missing configuration makes libdwarf 2.3.2 print
an error and suppress frame access while returning zero. PR #24 run
`40064815083`, native Linux job `120785718398`, exposed this before the first
50-frame capacity positive. Its verified diagnostic artifact is `12548957019`
(SHA-256 `7ea4ad1d70bc7a1a512977a73293708e6c28b3f27ba5e0918fb8f284e1944ba7`).
The strict helper correctly rejected it; local distro configuration had masked
the incomplete packaging. The earlier standalone bundle was not self-contained.

The builder now retains the ELF executable at `libexec/dwarfdump` and places
the unchanged pinned source configuration at `share/dwarfdump/dwarfdump.conf`,
SHA-256 `842bba9230de82059dfcef1485114cf3c33eae8be2973c649d176f4ad18972ef`.
The relocatable `bin/dwarfdump` Bash launcher verifies that hash and passes the
absolute path through upstream `--file-name`. It preserves the existing ABI
selection behavior; no target ABI is guessed. Missing/altered bundled config
and file-selection overrides fail before the checker runs. CWD, HOME and
system config files cannot replace this explicit selection. Coreutils and Bash
are Linux validation dependencies, not additions to the shipped extension.

`SHA256SUMS` covers launcher, real executable and configuration; metadata
identifies the configuration hash and both entry-point paths. The corresponding
source includes the launcher, builder, source archive and all patches. After
artifact download, CI restores executable permission on both executable files.
The existing GNU/LLVM/libdwarf diagnostic policy is unchanged.

`dwarfdump-configuration.py` exercises a relocated bundle in a path containing
spaces from a directory with an invalid host configuration. It reproduces the
old missing-config/frame-suppression error, proves complete strict frame checks
through the launcher, and rejects missing/altered bundled configuration and
upstream option aliases, including grouped short options. Capacity positives
use the launcher; allocation-failure tests invoke the real ELF with the same
explicit config so `LD_PRELOAD` does not instrument the shell/hash utilities.
Both test suites retain executable/config hashes and original fixture hashes.

## Complete bounded diagnostic evidence

The retained 10,000-function benchmark and its original each report 10,002
inherited frame-length errors. Upstream configures a 50-message circular list,
then retrieves it through a 50-pointer array whose final slot must be NULL.
Only 49 diagnostic texts survive in the output. The strict checker correctly
rejects the resulting incomplete evidence even when the two total counts match.
No configurable capacity option exists; suppressing harmless errors would hide
the evidence and is not used.

The third patch retains at most 65,536 messages and retrieves them through a
checked heap allocation of 65,537 pointers. It verifies the effective capacity
after requesting it and exits unsuccessfully on allocation failure, any count
above the bound, or any mismatch between reported and printed diagnostics.
The underlying fixed 300-byte message slots are allocated all-or-nothing;
failed resizing restores the previous buffer, ownership and counters.
This requires about 20 MiB per `Dwarf_Debug`, plus about 512 KiB for retrieval
on a 64-bit host; a tied object has its own bounded allocation. It is not an
unbounded diagnostic collector. Truncated message text or incomplete reports
still fail strict parsing. The limit applies to standalone validation only.

`dwarfdump-diagnostic-capacity.py` exercises real assembler-generated frame
records at and beyond the capacity, checks complete original/sidecar diagnostic
corroboration, and injects allocation failures in isolated subprocesses.
The helper compares exact diagnostic multiplicities before using a set for
efficient removal of already corroborated lines. A same-count duplicate control
ensures this optimization cannot reduce evidence to set equality.

Local regression `build/test-results/dwarfdump-diagnostic-capacity/run.16qkvtxf`
passes complete 50- and 65,536-message original/sidecar checks, rejects 65,537
with normal exit 1, and rejects missing/same-count duplicated diagnostics.
Isolated `calloc` failures for the internal pointer array, the 100th string and
the retrieval array fail normally. The static C API control preserves capacity
3, counter 5 and the last three messages after failed resizing. Original hashes
are unchanged. The Linux builder runs the full test, including this static API
control; no target code executes in these assembler fixture controls.

The retained paired 10,000-function benchmark independently passes with all
10,002 original diagnostics corroborated and every other category zero, plus
GNU/LLVM and full GDB behavior checks. This revalidation does not repeat or
change the historical timing measurements. See `docs/PERFORMANCE.md`.

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
patch -d /private/libdwarf-2.3.2 -p1 < support/validation/0003-preserve-bounded-harmless-diagnostics.patch
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


## GNU frame terminators in big-endian ELF64

The fifth patch, `0005-honor-eh-frame-zero-terminator.patch`, changes only the
validation consumer's `src/lib/libdwarf/dwarf_frame2.c`. SHA-256:
`d69033dbf8b67380c06b51932018c2c024e5610f3e5343cd75915e206ac16b08`.
The GNU frame-list reader recognizes four zero bytes before invoking the
historical IRIX length decoder. That decoder interprets a leading zero word
in big-endian ELF64 as the first half of an unmarked eight-byte length, so a
valid four-byte terminator previously caused an out-of-section read error.
The correction applies only to GNU `.eh_frame` traversal. It does not alter
`.debug_frame`, remove frame data, allow truncated prefixes or suppress a
validator diagnostic. Unmarked eight-byte IRIX frame entries retain the
existing parser and checks.

`dwarfdump-eh-terminators.py` tests both ELF classes and byte orders, empty and
populated terminated frame sections, padding and the end-of-list boundary.
Truncated prefixes/tails, nonzero incomplete lengths and truncated extended
lengths remain rejected. A valid IRIX `.debug_frame` still passes and a short
one still fails. `--previous-tool` proves the prior big-endian ELF64 failures
and verifies that the valid IRIX case passes both readers. The checker result,
not just its process status, determines success. Fixture, checker executable,
configuration and harness hashes are retained and rechecked.

The initiating unmodified GCC 12.4 MIPS N64 executable has exactly four zero
bytes in `.eh_frame`. GNU readelf and LLVM accept it; the previous strict
consumer fails; the corrected consumer reports zero errors. N32's identical
four-byte section already passed. These are compiler-reference observations,
not claims of complete N32/N64 exporter support. See
`../../docs/research/MIPS-ABI-COMPLETION.md` for the ongoing ABI investigation.

## GNU location views are section offsets

The sixth patch, `0006-locviews-are-not-die-references.patch`, changes only the
validation executable's `dd_trace_abstract_origin_etc.c`. SHA-256:
`54fce0dd7b7f19775cfb2bf95f610a4c3f4b96dd98d28ce99580d30c4e6aa879`.
For `DW_AT_GNU_locviews` encoded as `DW_FORM_sec_offset`, it retains attribute
reading/printing but does not traverse the numeric value as a `.debug_info`
DIE reference. GCC documents this attribute as a location-view list offset in
`.debug_loc` or `.debug_loclists`, not a DIE reference; see
[the GCC extension discussion](https://gcc.gnu.org/legacy-ml/gcc-patches/2019-03/msg00542.html).
Other attributes and forms keep the existing checks. This does not implement a
new GNU view-pair evaluator; GNU readelf separately inspects the actual lists.

**CONFIRMED locally:** a native debugger trace on the unmodified GCC 12.4 N32
reference shows the old checker following attribute `0x2137` into
`dwarf_offdie_b`, then rejecting bytes from the CU as abbreviation code 688.
GNU and LLVM accept that reference. The corrected checker reports zero errors.
`dwarfdump-locviews.py` constructs DWARF 4/5 fixtures in both ELF classes and
byte orders. Eight positive cases pass GNU, LLVM and the complete strict report;
sixteen malformed actual-type/reference-form cases remain rejected. With the
previous tool, all 24 cases reject, reproducing its eight false positives.
The checker is built afresh from the pinned archive and all six hashed patches.

The local 48-case receipt is
`build/test-results/dwarfdump-locviews/run.9w_ckkwp/result.json` in the active
MIPS allocation worktree. Eighteen retained N32/N64 compiler/Forge artifacts
also pass; `build/mips-wide-allocation/locviews-real-artifacts.json` records
those paths. The existing GNU/IRIX frame regression passes at
`build/test-results/dwarfdump-eh-terminators/run.xqd4ox09/`.
Hosted validation remains pending. Shipped Ghidra native libraries are unchanged.

The new bundle also passes the 97 evidence-capture/mutation controls at
`build/mips-wide-allocation/locviews-evidence-controls/run.kuzv0m3b/` and
extended-program-header controls at
`build/test-results/dwarfdump-extended-programs/run.i7hc23r1/`. Evidence records
now pin the sixth patch and use the explicit six-correction profile. The native
Linux CI job installs LLVM for the new independent structural controls and
retains their reports with its existing artifacts.

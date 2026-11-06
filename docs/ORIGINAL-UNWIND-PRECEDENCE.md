# Original unwind precedence and loader writes (#112)

**CONFIRMED locally:** the recovered-frame verifier now inventories original
frame coverage and selected ordinary loader write footprints before accepting
instruction bytes. The planner omits an entire instruction if any byte overlaps
an original FDE's declared coverage. It splits generated ranges at that omission
and retains the reason. Original records in unrelated functions do not suppress
recovery. Unknown original metadata fails inspection; it is never treated as an
empty inventory.

This is an integration checkpoint in the recovery components, not production
exporter acceptance. Existing frame ranges express precedence, not proof that
the original CFI instruction stream is semantically correct.

## Evidence and boundaries

`ElfRelocationEffects` derives REL/RELA/PLT/RELR destinations from the bounded
runtime inventory. `UnwindRelocationProfile` isolates the initial ordinary
ELF64 little-endian x86-64/AArch64 write shapes. It accounts for fixed-width data,
16-byte TLS descriptors, and COPY destinations bounded by the referenced
symbol's size. Symbol count comes from corroborated SHT_DYNSYM, SysV hash, or
nonempty GNU hash evidence; removing the last count source produces a diagnostic.
The previous sectionless production symbol-mirroring path retains its existing
count policy.

The selected profiles also include implicit loader destinations: the two
reserved GOT slots, GNU descriptor resolver GOT storage when declared, and the
value field of DT_DEBUG. These are conservative possible-write extents, not
claims that every binding mode writes every listed byte. NONE relocations do
not dereference their ignored symbol field. RELCOUNT/RELACOUNT prefixes must
fit their tables and contain only the selected relative encoding with symbol zero. REL COPY does not require an explicit
addend. Destinations must fit one unambiguous load memory extent; file-backed and
BSS portions are distinguished. Writes cannot mutate the relocation tables,
symbol records used for sizing, or dynamic metadata (except the loader's own
DT_DEBUG value). Unsupported types, known IFUNC/indirect-relative resolvers,
unknown loader extensions, and nonempty SFrame coverage reject qualification.

This models declared ordinary loader writes. It does not execute relocations or
prove arbitrary initialization callbacks, external symbol resolvers, injected
libraries, or self-modifying programs harmless. The same loaded-image and code
identity assumptions required for the recovered instruction model remain.
Original file identity must remain valid through eventual output publication.

`OriginalUnwindCoverage` protects both frame-source bytes and EH search metadata,
then merges declared original intervals. Queries use original link-time VAs;
Ghidra rebasing is normalized before the query. Empty original coverage is
accepted only after successful inspection. No new MIPS/ARM32 unwind synthesis
profile is claimed. Valid but unqualified original encodings still fail closed;
for example, the source collector currently requires PROGBITS frame sources.

## Pinned ABI/loader audit

The source/hash manifest is retained in the evidence archive:

- [AMD64 object-file ABI](https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/e1ce098331da5dbd66e1ffc74162380bcc213236/x86-64-ABI/object-files.tex).
- [AAELF64](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/aaelf64/aaelf64.rst)
  and [AArch64 System V ABI](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/sysvabi64/sysvabi64.rst).
- glibc `ef321e23c20eebc6d6fb4044425c00e6df27b05f`:
  [x86-64 loader](https://github.com/bminor/glibc/blob/ef321e23c20eebc6d6fb4044425c00e6df27b05f/sysdeps/x86_64/dl-machine.h),
  [AArch64 loader](https://github.com/bminor/glibc/blob/ef321e23c20eebc6d6fb4044425c00e6df27b05f/sysdeps/aarch64/dl-machine.h),
  [DT_DEBUG update](https://github.com/bminor/glibc/blob/ef321e23c20eebc6d6fb4044425c00e6df27b05f/sysdeps/generic/dl-debug.h).

AAELF64 describes COPY as ET_EXEC-only. The Linux compiler/loader experiment also
proves an LLD-built AArch64 PIE COPY case. The accepted ET_DYN case therefore
requires both DF_1_PIE and PT_INTERP and is explicitly tested rather than inferred
from the older wording. COPY remains rejected for an ordinary shared library.
The glibc implementation bounds the copy by the smaller provider/reference size;
the reference size used here is a conservative destination bound.

## Validation

- 282 effect checks: COPY/descriptor boundaries, BSS/file-backed footprints,
  nested writes, implicit slots, symbol-count disagreement, unsupported metadata,
  resolver refusals, all cancellation polls, retries, and late input mutation.
- 4352 native Ghidra checks: existing 26 fixtures plus partial/full/unrelated
  original-coverage controls on both targets; whole-instruction omission,
  malformed-source refusal, half-open boundaries, and cancellation/retry.
- Four loader executions: x86-64/AArch64 non-PIE and PIE read all 37 copied bytes
  and resolve external TLS via a descriptor. GNU relocation/symbol evidence
  independently establishes the tested COPY and descriptor shapes. Six original
  ELF artifacts and six sectionless variants have identical Java inventories.
- Four recovered-CFI runtime cases still pass GNU/LLVM/strict structural checks
  and GDB comparisons: eight plain/compressed sidecars and sixteen GDB sessions.
  Rebased recovery plans and deterministic reruns remain checked by that harness.
- Existing inventory regressions pass: 932 runtime relocation, 1158 original
  source, 4275 original range, and 1730 sectionless dynamic symbol checks.
  Extension build, architecture guard, and workflow lint pass.

The raw command logs retain fixture-development failures: non-PIC x86 PIE link
rejection, initially missing GNU TLS descriptor tag handling, the local QEMU
binary being named `qemu-aarch64-static`, GNU AArch64 PIE using a GOT reference,
GNU ld refusing the direct PIE COPY reference, and invoking LLD's generic-driver
symlink for its version. The final harness explicitly uses LLD 18 for AArch64,
selects the installed QEMU executable, and asserts that COPY/TLSDESC really exist.
No ignored linker option or incidental successful execution substitutes for that
assertion. New CI steps are **PRESENT, UNVERIFIED** until hosted checks pass.

Full compiler/global-write alias proof, production exporter integration and its
shared-object/failure matrix remain **PLANNED**. ADR-0002's production constraint
is unchanged. PR166 (#116/#114) integration retains priority; full #112, #110,
and #109 are still open. See `docs/evidence/original-unwind-precedence.json`.

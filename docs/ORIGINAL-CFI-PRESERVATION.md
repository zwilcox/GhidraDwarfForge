# Preserving original compiler unwind information

**CONFIRMED locally; hosted acceptance pending.** This is a prerequisite for
#112, not synthetic-CFI generation. The matched writer now keeps original
`.debug_frame` and GNU `.zdebug_frame` sections active in linked ET_EXEC/ET_DYN
images. It preserves their payload bytes, file offsets, compression flags,
alignment and address metadata. Replacing recovered types, names and source
rows does not invalidate these independent unwind rules.

Previously the writer renamed these sections to `.forge.stale.*`. Loading the
sidecar with `symbol-file` then hid valid compiler CFI. The x86-64 regression
recovered only two valid frames instead of eight even though every DWARF
validator passed. The [original reproduction](evidence/synthetic-cfi-preservation-probe.json)
remains available; its diagnostic rename experiment is now historical.

## Precedence and limits

- A generated `.debug_frame` that collides with either original encoding is
  rejected before publication. Future synthesis must reconcile coverage rather
  than silently overwrite trusted original records.
- ET_REL and other unlinked images retain the prior inactive-frame behavior,
  with an explicit diagnostic. This change does not implement relocation of
  object-file CFI. Linked `--emit-relocs` inputs are tested separately: their
  already resolved frame payloads remain unchanged while inactive relocation
  sections follow the existing writer policy.
- Original `.eh_frame` and sectionless `PT_GNU_EH_FRAME` discovery are unchanged.
  A missing non-loadable `.debug_frame` section table cannot be reconstructed
  by this preservation path. Unsupported or missing CFI remains a limitation.
- Preservation does not certify malformed original frame instructions or repair
  their contents. Independent structural/runtime validation is still required;
  there is no new validator-warning waiver.
- No executable bytes, target mappings, exception tables or runtime behavior
  are changed. No new JNA/native call or unwind synthesis is enabled.

## Tests and interpretation

`existingDebugSidecarSmoke` exercises twelve ELF32/ELF64, little-/big-endian,
plain/gABI/GNU-compressed layouts. It verifies retained metadata, unchanged
inputs, deterministic output, generated-frame collision rejection, all observed
writer cancellation checkpoints and temporary-file cleanup. ET_REL controls
require inactive frame metadata and a diagnostic. Its payloads are intentionally
opaque: these tests prove writer behavior, not DWARF semantics. The preservation
test fails against the prior writer.

The runtime harness runs the real headless exporter twice per case, then GNU,
LLVM, pinned strict libdwarf and GDB. Thirty cases cover x86-64 and AArch64, each
with non-PIE ET_EXEC, static PIE and a genuinely `dlopen`-loaded shared object.
Each role has plain, gABI zlib, GNU zlib, rebased-import and retained-link-relocation
variants. Sixty exports preserve the input hashes and original CFI payloads;
independent JVM reruns at the same publication path produce identical sidecars
and synthetic source. Different source output names are intentionally not a
byte-determinism comparison, because they are DWARF content.

GDB must recover the eight-frame recursive chain, six distinct register
witnesses, `finish`, and every instruction stop through all recursive returns.
Normalized frame/PC/register traces must equal an independent compiler
reference. Shared inputs use a separate source-built driver, `dladdr` load-bias
evidence and explicit `add-symbol-file`; auto-loading remains disabled. The
driver initializes its call-preserved witness so startup/ASLR values cannot
make the comparison nondeterministic. AArch64 uses QEMU user emulation and the
matching sysroot/library search path.

The harness explicitly applies the four source-built fixture function names and
extents as analyst curation before export. It supplies no unwind rules or saved
register locations. This also accounts for Ghidra's observed AArch64
`--emit-relocs` import splitting a compiler function at an interior call; it is
not a claim that automatic function discovery always matches compiler extents.

Six negative controls remove the frame section from a separate test sidecar.
GDB must stop selecting the DWARF unwinder for the exact target frame, even
though the runtime input still contains compiler CFI. The x86-64 chain breaks;
AArch64's prologue fallback still recovers it. Checking only `bt`, or finding
some unrelated driver frame using DWARF, would not prove sidecar CFI was used.

The AArch64 system-DSO string-table warning is reported and must exactly match
the compiler control. Missing sysroot/library warnings are failures, not accepted
exceptions. The [acceptance receipt](evidence/original-cfi-preservation.json)
records the combined final cases, local correction history and retained logs.
Local tests use the isolated production extension with explicit audited native
libraries; the hosted workflow exercises the packaged-native route. That hosted
acceptance, including Windows, remains unverified.

```bash
python3 src/test/integration/original-cfi-preservation.py x86_64 \
    "$GHIDRA_INSTALL_DIR" build/test-results/original-cfi-preservation/x86_64 \
    --dwarfdump "$DWARFDUMP"
python3 src/test/integration/original-cfi-preservation.py aarch64 \
    "$GHIDRA_INSTALL_DIR" build/test-results/original-cfi-preservation/aarch64 \
    --dwarfdump "$DWARFDUMP"
```

Outputs must be new directories. `--roles` and `--variants` allow targeted
rechecks after a harness failure; CI uses the complete matrix. The separate
[synthetic-CFI evidence model](SYNTHETIC-CFI-EVIDENCE.md) still requires ABI audits,
instruction-range recovery, encoding and generated-CFI behavior tests before
#112 can be completed.

# O32 FPXX and FP64A references with the system-emulator register transport

**CONFIRMED locally; hosted acceptance pending.** An unmodified QEMU 8.2.2
64-bit system emulator supplies a positive compiler-DWARF float/double reference
for O32 FPXX and FP64A in both byte orders when the actual processor has FR=1.
This advances the original #69 reference requirement. It does not claim broad
FPXX/FP64A variable locations, FR=0 compatibility, injected calls, Linux runtime
support or completion of the full #68–#71 objective.

## Why the previous reference failed

The inspected QEMU 8.2.2 `target/mips/gdbstub.c` sends FPR values through
`gdb_get_regl`. Its 32-bit user target truncates FR=1 doubles to 32 bits, even
though the program stores the correct full doubles in memory. Upgrading GDB
did not fix that transport. The 64-bit user emulator cannot load the original
O32 ELF; the rejected attempt remains recorded.

The installed `qemu-system-mips64`/`qemu-system-mips64el` binaries can instead
run an O32 program on a real emulated `MIPS64R2-generic` CPU. Their legacy
remote packet retains 64-bit FPR slots. GDB is explicitly configured for that
actual CPU using `set architecture mips:isa64r2`; ELF pointers remain four
bytes. The O32 code uses the MIPS32r2 instruction subset, without relabeling
ELF class, machine, ISA or floating ABI attributes.

The new startup assembly sets CU1, FR=1 and ERL in the target's status register,
then calls the existing `fp_register_aliases.c` fixture. ERL permits direct
low-address RAM access for this bare-metal test. QEMU's generic ELF loader
loads the unchanged stripped original at its declared addresses. No kernel,
guest filesystem, patched emulator, patched debugger, fabricated DWARF or
debugger register repair is used. The real main return must be zero at the
startup's terminal loop; the owned emulator is then explicitly terminated.

The initial kernel-loader experiments failed: one had a register-packet-width
mismatch, another could not reach the high-address breakpoint, and Malta
explicitly rejected a low-address Linux kernel entry. The generic bare-metal
ELF loader resolves that setup problem. Failed attempts remain evidence, not
passing runtime results.

## Maintained exporter and reference contract

`mips-fpr-system.py` builds FPXX (`-mfpxx`) or FP64A
(`-mfp64 -mno-odd-spreg`) for the selected byte order. It retains compiler
DWARF, imports the stripped original, curates the existing scalar fixture,
and performs two read-only exports through the installed production script.

At function entry and the before/after-store markers, both symbol-file variants
must prove actual FR=1, exact PCs, source lookup and independent raw FPR bytes.
Compiler float values 19.25/-7.5 and double values 21.5/-9.25 must be exact.
The program's stores and final zero return provide independent memory/execution
checks. Forge must retain correct floats and leave both double parameters
unavailable at every marker.

That omission is deliberate: the fixture's current Ghidra MIPS32 language
contains 32-bit FPRs and complete `f12_13`/`f14_15` aliases. The existing fixture
curates those aliases as analyst storage, which does not establish a valid
FR=1 64-bit FPR location. The exporter must report exactly those two
`UNMAPPED_REGISTER` omissions. The known process-entry convention, guarded
floating calls and three opaque `undefined` types explain its partial report;
all four functions must still decompile, with no failed or skipped functions.
The test does not replace an unavailable location with an invented pair.

Every case checks GNU ELF/DWARF views, LLVM verification, pinned strict
libdwarf summaries, byte-identical repeated output, unchanged input/package
files and unchanged saved program files except recorded index-backup rotation.
The original and sidecar are loaded explicitly. The same original instructions
run in the compiler and Forge comparisons.

Three copied-input controls are mandatory per case:

- An unchanged compiler copy must pass all observations.
- Changing the first double's DWARF carrier from f12 to f14 remains LLVM/strict
  valid but must fail with the independently expected wrong value -9.25.
- Changing only the startup FR bit must fail the actual-mode assertion. FR=0
  cannot silently be accepted under the FR=1 reference contract.

These controls preserve the baseline artifacts. Existing FP32, N32/N64,
PIE/shared/rebase, sectionless, failure/cancellation and other target lanes
remain required. The new reference does not substitute for them.

## Reproduction and local evidence

```bash
for endian in be le; do
    for profile in fpxx fp64a; do
        python3 src/test/integration/mips-fpr-system.py "$GHIDRA_INSTALL_DIR" \
            --endian "$endian" --profile "$profile"
    done
done
```

Use the existing Java 21, cross-compiler and strict-validator setup. CI adds
Ubuntu's `qemu-system-mips` package to both MIPS lanes and requires both profiles
through the same installed exporter. No local system packages were changed.

The final cases under `build/test-results/mips-fpr-system` in the
`mips-fpr-reference` worktree are `be.fpxx.oayyvwcm`, `be.fp64a.14mui5oh`,
`le.fpxx.rpf6d8kj` and `le.fp64a.ciecsj7r`. All four pass: eight deterministic
exports, 48 compiler/Forge stops, four positive-copy runs and eight exact
negative rejections. Three fixture-inventory/reproducibility checks (both
MIPS orders and x86-64), workflow lint, Python compilation and diff checks pass.

The unchanged production JAR is
`30d90f1c3d754ffba93c750a00703e1792df9cdd15f04964d3528153b8b4a929`;
all 106 production-source hashes match its previously built package. Receipt:
`build/mips-fpr-reference/validation-v3.json`, SHA-256
`0c750b0f6a13a69ac63958a62ec42e54af76885763baf06c5e7598ed650b92b2`.
Earlier standalone research used a separate returning-function fixture; its
results do not replace these maintained shared-fixture/exporter runs.

**Remaining:** hosted exact-head acceptance, protected integration, the full
requirements audit, and any new production FPXX/FP64A storage/call profile.
The old user-mode failures remain reproducible; only this explicit FR=1
system-emulator reference has new positive evidence.

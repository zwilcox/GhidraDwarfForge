# O32 mixed, wide and aggregate argument acceptance

**CONFIRMED locally (2026-11-02):** all ten O32 byte-order/layout cases pass
with the real packaged exporter. Hosted acceptance and protected integration
remain pending. This extends #69; it does not close P2.3a or the combined
P2.3–P2.3c goal.

## Contract

The fixtures use GCC's O32 MIPS32r2 FP32 profile, ELF32, four-byte pointers and
both byte orders. Ten signed 64-bit integers exhaust the four argument words;
a mixed signature combines 64-bit integers, double, int, float, a two-word
structure and stack arguments. Two aggregate functions return 16- and 24-byte
structures through hidden buffers. Original execution produces the source-known
values before any debugger injection.

The test types must have natural alignment. `StructureDataType`'s unpacked
default gave the test aggregates alignment one, placing their first argument
word in `a1` after the hidden return pointer. Enabling natural packing models the
C structures' eight-byte alignment and correctly skips that word. This fixes
the fixture definition; it does not override analyst storage or change production
allocation policy. Saved signatures retain dynamic storage.

The O32 oracle independently reads four-byte argument slots and combines each
pair in target byte order. It checks runtime instruction bytes against the
compiler fixture, decodes the audited straight-line instruction vocabulary,
and derives register-clobber and home-store boundaries. The N32/N64 oracle
retains its separate eight-byte slot contract.

## Reference limitations and exported behavior

- GCC's big-endian DWARF can retain a paired argument after its first word was
  overwritten. The test records only the interval between the two independently
  decoded first writes. Forge must instead show unavailable after the first
  clobber. Little-endian references do not receive that exception.
- GCC can describe an aggregate's stack home before the stores populate it.
  Only that field, before both decoded stores complete, receives a reference
  exception. Raw incoming argument bytes remain checked.
- Forge's existing shared mixed register/stack proof ends at the first possible
  memory write. Both aggregates must be correct before that boundary and
  unavailable afterward. Broader alias-aware mixed-storage lifetime analysis is
  not implemented by this change.
- GDB 15's O32 injected aggregate calls can omit the alignment hole following
  the hidden return pointer. A non-stopping entry probe checks the exact passed
  bytes, actual ABI carriers and result buffer. Incorrect transfer is recorded
  as a compiler-debugger limitation, never a positive call-support result.
- Forge retains its existing guard for those aggregate calls, including calls
  through typed pointers. Rejection must preserve all registers, the inspected
  stack and fixture globals. Ordinary aggregate returns are read from the real
  hidden buffer with the emitted type; automatic return decoding is not claimed.
- Wide integer and mixed scalar calls remain positive tests through both names
  and callbacks. No debugger registers or memory are repaired to make a test pass.

## Acceptance commands

```bash
python3 src/test/integration/mips-o32-arguments-oracle-test.py
python3 src/test/integration/mips-wide-arguments.py "$GHIDRA_INSTALL_DIR" \
    --abi o32 --endian be --role exec --with-controls
```

Run both `be` and `le` for `exec`, `pie`, `pie-rebased`, `shared` and
`shared-rebased`. Each case uses the real packaged exporter, repeated read-only
exports, GNU/LLVM/pinned strict validation, instruction/source/call GDB phases,
input/program preservation, forced decompiler failure and production
cancellation. An unchanged sidecar copy must pass; four structurally valid
wrong-carrier/late-gap sidecars must fail at their specified GDB observation.
N32 big-endian executable and N64 little-endian rebased shared regressions cover
the shared test changes. Existing sectionless MIPS lanes remain required.

## Local evidence

Ten O32 cases pass 40 normal/failure exports, 10 production cancellations,
24,780 instruction-level compiler/Forge parameter observations and 5,620 source-
stepping observations. Forty structurally valid wrong-location/late-gap
artifacts are rejected; ten unchanged copies pass. Every case preserves the
original and saved program and produces identical repeated artifacts.

The N32 big-endian executable and N64 little-endian rebased shared regressions
pass eight additional exports and two cancellations. Both independent oracle
unit suites pass, as do Python compilation, workflow lint and whitespace checks.
All 106 production source files match the tested PR151 package; its exporter
JAR SHA-256 is
`30d90f1c3d754ffba93c750a00703e1792df9cdd15f04964d3528153b8b4a929`.
The local receipt is `build/mips-o32-arguments/validation.json`, SHA-256
`5456c25a5de0aec197354d4449c6bb55569c48c817c57d561d30f420ae6c854e`.

An initial little-endian negative changed a zero high word to another zero and
correctly failed to demonstrate corruption. The corrected controls change the
value-bearing word; all five big-endian controls were rerun with the final
mutation helper against their unchanged accepted artifacts. The retained
initial failure is not counted as a passing result.

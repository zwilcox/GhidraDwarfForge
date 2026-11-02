# ARM exhausted-register and partial aggregate storage

**CONFIRMED local acceptance; hosted integration remains required.** This
component advances P2.3b/#70 within the complete P2.3–P2.3c goal. It retains
Ghidra 12.0.3, Java 21 and libdwarf 2.3.2. The natural C fixture covers fourteen
base/VFP functions: split pairs, aligned structures, packed five-byte and
three-byte objects, integer arrays, mixed float/integer fields and exhausted
floating-register arguments. Conditional comparisons remain in the fixture.

## Production behavior

Shared incoming-value analysis intersects forward conditional p-code paths and
tracks exact physical byte spans through wider register/memory transfers. It
preserves independent copies, byte shifts and joins whose known-zero bits prove
that no carry or overlapping operand can corrupt a piece. Truncation, unknown
aliases, clobbers and frame release still retire affected facts. Architecture
register mappings and physical byte order remain isolated from generic flow.

An audited ARM allocation policy fixes a computed BE8 packed-structure stack
byte at offset three when the compiler passes it at offset zero. It verifies
the selected prototype and full saved signature before correcting the export
model. Explicit custom storage and the saved program remain unchanged. See
[the investigation](research/ARM-STACK-AGGREGATES.md) for the original wrong-value
reproduction, prototype fingerprints and implementation/model evidence.

## Exact availability contract

`arm_stack_aggregate_contract.py` describes independently audited instruction
prefixes. Every opcode, register, immediate and observation boundary must match;
MOVW/MOVT literals must resolve to the actual compiler-symbol global address.
The contract does not read Forge locations or diagnostic strings to decide what
should be available.

All source-known scalar and aggregate values must be exact except at these
explicit full-object proof boundaries, in both base and VFP variants:

| Object | First unavailable PC relative to function entry | Evidence |
| --- | --- | --- |
| Split pair / packed object | 40 | The store at 36 uses an address without a proven relation to the entry stack, retiring saved pieces. |
| Split integer array | 44 | The corresponding unknown-address store follows an additional scalar copy. |
| LE three-byte object | 52 | Earlier stores retired its stack backup; the shift at 48 destroys its last whole-register copy. |
| BE8 three-byte object; aligned, mixed and floating cases | No gap in the checked prefix | Their independently proven carriers survive. |

These gaps express uncertainty in the exporter's proof. In this particular
runtime the original bytes may still exist. Assuming that every global address
is disjoint from the entry stack would weaken the existing unknown-alias safety
contract. Unknown-alias controls continue to require unavailability even when
one particular execution happens to use disjoint addresses.

The original strict **full-availability** research mode remains the default and
still fails at 130 LE / 116 BE8 field observations. The passing mode is explicitly
named `audited-prefix`. An unexpected gap, a numeric value in a required gap or
any wrong numeric value fails it. It is not evidence that every parameter can be
recovered at every instruction.

## Independent runtime and failure checks

The harness rebuilds the source twice, strips the executable completely,
imports/curates it, and exports twice through the installed production extension
from a read-only project. GNU, LLVM and the pinned strict libdwarf validator
check both symbol files. The sidecar retains target identity and original text
bytes; the original ELF, program data and protected sources/package stay intact.

An independent decoder checks parameter types, widths, entry allocation, actual
DWARF 5 location-list bytes, interval bounds and piece widths. At each actual
GDB stop, a separate evaluator reads the named physical registers/stack bytes
and compares decoded values to the C source. GDB's own typed expressions must
agree independently. Raw ABI entries, captured globals, integer returns and
process exit are also checked. Known compiler-reference defects are corroborated
by current physical carriers inside exact instruction windows; the original
compiler defects remain recorded. Forge receives no compiler exception.

Failure controls reject real decompilation of a neighboring startup function,
the packed object, the partial-register object and the exhausted floating case.
Each runs twice deterministically. A failed function retains its symbol and
range, loses formal/type/source attributes and all owned physical location
entries, and exposes no parameter at any checked PC. Other functions retain
their exact values and required gaps. Cancellation occurs during production
copying of a separately imported padded original and preserves an existing
validated output pair without staging residue.

Read-only reopening of the cancellation project can rotate only the documented
`idata/~index.bak` and `idata/~journal.bak` files. Their before/after hashes are
recorded explicitly; the database, metadata and original baseline project must
remain unchanged. The earlier overly strict all-file assertion is retained as
a failed test, not reported as a successful run.

## Local evidence and invocation

Four cases cover LE/BE8 and unchanged/rebased Ghidra projects. All pass with
production JAR SHA-256
`c3eb4886ebb1d82e1d34131e27d323e80132b6e8c44a50ac4909e83e28650ade`:

- 1,012 baseline instruction stops per compiler/Forge symbol-file variant;
  every Forge stop also has independent physical-carrier checks.
- 492 explicitly required unavailable field observations.
- 32 deterministic failure exports; 3,802 neighboring-function instruction
  observations and 246 symbol-only observations.
- Four cancellations, each after 16 MiB of production copying.
- Eight runtime mutation controls reject early/late gap boundaries, a wrong
  physical register and a changed instruction contract in both byte orders.
- Six reference/contract unit tests, workflow lint and Python/whitespace checks.

Receipt: `build/arm-stack-aggregates/contract-controls-v2.review.json`, SHA-256
`09789fbb981a2abea7b458c89aa813b70b776f87ba988df443c6782dabce186f`.
The 103 production source hashes still match the earlier candidate validated
with 22 model suites, 24 ARM storage controls, two default HFA runs and three
x86-64/AArch64 runtime regressions.

```bash
python3 src/test/integration/arm-stack-aggregates-reference-test.py
python3 src/test/integration/arm-stack-aggregates-contract-test.py
python3 src/test/integration/arm-stack-aggregates.py "$GHIDRA_INSTALL_DIR" \
    --order little --role exec-rebased --availability-contract audited-prefix \
    --with-controls --qemu /path/to/qemu-arm \
    --gdb /path/to/gdb-multiarch --gdb-data /path/to/gdb/data-directory
```

Use `--order big`, the documented corrected `qemu-armeb` and BE8 GDB profile for
the other data order. `--role exec` retains the original Ghidra image base.
`ARM32_CC`, `ARM32_OBJCOPY` and `DWARFDUMP` select isolated toolchains/validators.
CI now includes both roles/orders and the genuine failure/cancellation controls.

**PLANNED:** exact-head hosted acceptance, independent artifact review and normal
protected integration. Additional PIE/shared aggregate compositions remain part
of the full ABI work. Both source-built relocation-free PIE experiments execute
successfully under QEMU, but their recovered DWARF/debugger contract is not yet
validated. All original MIPS, ARM and i386 requirements and the AArch64 closure
audit remain in scope; this component does not complete the full goal.

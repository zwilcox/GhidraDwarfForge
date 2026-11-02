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
PIE uses independently audited LDR/ADD pairs and a final literal-pool word;
its exact instruction, pool offset, function extent and data byte order must
resolve to that same global after runtime relocation. BE8 instructions remain
little-endian while the pool word is big-endian.
The contract does not read Forge locations or diagnostic strings to decide what
should be available.

All source-known scalar and aggregate values must be exact except at these
explicit full-object proof boundaries, in both base and VFP variants:

| Object | First unavailable PC relative to function entry | Evidence |
| --- | --- | --- |
| Split pair / packed object | 40 | The store at 36 uses an address without a proven relation to the entry stack, retiring saved pieces. |
| Split integer array | 44 | The corresponding unknown-address store follows an additional scalar copy. |
| LE three-byte object | 52 | Earlier stores retired its stack backup; the shift at 48 destroys its last whole-register copy. |
| BE8 PIE three-byte object | 68 | The shift at 64 overwrites the final whole-object copy in `ip`, after the PIC address has overwritten `r3`. |
| Non-PIE BE8 three-byte object; aligned, mixed and floating cases | No gap in the checked prefix | Their independently proven carriers survive. |

These gaps express uncertainty in the exporter's proof. In this particular
runtime the original bytes may still exist. Assuming that every global address
is disjoint from the entry stack would weaken the existing unknown-alias safety
contract. Unknown-alias controls continue to require unavailability even when
one particular execution happens to use disjoint addresses.

The original strict **full-availability** research mode remains the default and
retains the original non-PIE failures at 130 LE / 116 BE8 field observations. The passing mode is explicitly
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

Eight cases cover LE/BE8, ET_EXEC/PIE and unchanged/rebased Ghidra projects. All pass with
production JAR SHA-256
`c3eb4886ebb1d82e1d34131e27d323e80132b6e8c44a50ac4909e83e28650ade`:

- 2,032 baseline instruction stops per compiler/Forge symbol-file variant;
  every Forge stop also has independent physical-carrier checks.
- 1,020 explicitly required unavailable field observations.
- 64 deterministic failure exports; 7,632 neighboring-function instruction
  observations and 496 symbol-only observations.
- Eight cancellations, each after 16 MiB of production copying.
- Twelve current PIE runtime controls reject wrong load bias, global addresses,
  actual inferior pool bytes, physical carriers and early/late gap boundaries.
  All copied-control failures retain their exact reason; baseline inputs remain
  unchanged. The earlier eight non-PIE mutation controls remain retained.
- Ten reference/contract unit tests, workflow lint and Python/whitespace checks.

Current receipt in the `arm-stack-pie` worktree:
`build/arm-stack-pie/pie-v4.review.json`, SHA-256
`786bfc03157c69a07077d257a03215a5d614e29a19e7d8c73947736bba1ffda0`.
The original non-PIE receipt remains retained in `arm-stack-aggregates`.
The 103 production source hashes still match the earlier candidate validated
with 22 model suites, 24 ARM storage controls, two default HFA runs and three
x86-64/AArch64 runtime regressions.

```bash
python3 src/test/integration/arm-stack-aggregates-reference-test.py
python3 src/test/integration/arm-stack-aggregates-contract-test.py
python3 src/test/integration/arm-stack-aggregates.py "$GHIDRA_INSTALL_DIR" \
    --order little --role pie-rebased --availability-contract audited-prefix \
    --with-controls --qemu /path/to/qemu-arm \
    --gdb /path/to/gdb-multiarch --gdb-data /path/to/gdb/data-directory
```

Use `--order big`, the documented corrected `qemu-armeb` and BE8 GDB profile for
the other data order. `--role exec` retains the original Ghidra image base.
`ARM32_CC`, `ARM32_OBJCOPY` and `DWARFDUMP` select isolated toolchains/validators.
CI includes all four roles in both byte orders, genuine failure/cancellation
controls and the separate PIE corruption suite.

PIE fixtures are freestanding ET_DYN files with `DF_1_PIE`, no interpreter and
no dynamic relocations. The GDB harness derives load bias from the actual QEMU
entry PC and the original ELF entry, then explicitly relocates each symbol
file. It checks named function addresses against independent compiler labels.
Ghidra's initial import base is recorded before applying the optional rebase;
it is not confused with the original ELF base or runtime load bias. Compiler
function sizes include the final data pool, while the independently checked
Ghidra/DWARF function range excludes it.

The new low-address PIE exposes a validator defect: libdwarf 2.3.2 invents
a `0x200` lower address bound after sorting empty section slots. Its seventh
validation-only patch derives the actual nonempty allocated section bounds.
GNU/LLVM and the corrected strict checker accept both unchanged symbol files.
Twenty synthetic positives and 36 negative controls pass in ELF32/64 and both
byte orders; eight old false rejections and eight old false acceptances are
reproduced. Existing checker regressions, 97 evidence controls and the complete
65,536-message diagnostic suite pass. See
[the validator record](../support/validation/README.md#elf-address-bounds).

**PLANNED:** exact-head hosted acceptance, independent artifact review and normal
protected integration. Shared aggregate compositions remain part of the full ABI work.
The PIE behavior above is locally validated; hosted acceptance is pending. All original MIPS, ARM and i386 requirements and the AArch64 closure
audit remain in scope; this component does not complete the full goal.

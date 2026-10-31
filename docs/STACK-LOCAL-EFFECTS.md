# Stack-local mutation and alias runtime evidence

**CONFIRMED locally; hosted acceptance pending:** the saved stack-local proof
retires all old value carriers after partial writes, full unrecorded assignments
and unknown-pointer stores. A proven non-overlapping stack write preserves the
local. This checkpoint adds end-to-end evidence for the existing ordered
instruction engine; it changes no production Java or native ABI.

## Independent oracle and negative cases

`stack-local-effects.c` defines five small functions. Each initializes one local,
loads a copy into an explicit register, performs a store and keeps that old
register copy live until a later observable write. The selected fixture profiles
use R10/X9; those names occur in the target-specific fixture and debugger oracle,
not generic production logic. The source-built compiler artifact supplies the
actual instruction bytes, boundaries, local address and type/value oracle.

The store cases are:

- A one-byte XOR into the original local.
- A full assignment with a different value and no new analyst definition.
- A pointer loaded from a volatile global that aliases the original local.
- The same unknown-pointer mechanism pointing to a different stack object.
- A direct write to a provably distinct stack slot.

For the first three cases, GDB proves that the local's memory has changed while
the register backup still contains the old value. The Forge declaration must be
unavailable after the store; returning the backup would report the wrong value.
The fourth case remains unavailable even though its memory happens to be
unchanged: the instruction proof cannot establish the pointer's destination.
The fifth is a positive control and remains available after the separate write.
The exported proof makes no claim to recover the new value of an unrecorded
assignment. Broader mutable-stack identity remains separate work.

The fixture compiles at 32 and 64 bits with negative values that expose width
and sign errors. It uses no native producer changes, proprietary inputs or
original-source claims. Curation saves one USER_DEFINED local at the complete
initializing STORE, then read-only reopen/export checks its exact symbol ID,
first-use offset, storage, type, bytes and raw p-code.

## Local acceptance

All twelve x86-64/AArch64 width/address-role cases pass on actual JDK 21:
32/64 bits and exec/PIE/rebased PIE, with 24 candidate exports and twelve
preceding-package exports. The 60 exercised functions provide 3,636 compiler,
Forge and previous-package GDB instruction observations and 417 available Forge
values. There are 36 stale-backup controls, twelve unknown-pointer/non-alias
controls and twelve known non-alias positive controls. The previous package
omits all five later-start locals.

An independent raw `.debug_loclists` reader requires complete coverage only
between the compiler-backed initialization and retirement markers. It checks
actual stack/register expressions, signed displacements, attached definition
bytes and the absence of invented lexical blocks or constants. GDB independently
reads each advertised physical location, checks type/width/current value and
every unavailable boundary, compares stopped code bytes, and verifies source
lookup, `next`, `step`, globals and normal exit.

GNU, LLVM and the pinned strict checker pass for each candidate and previous
artifact. Strict frame diagnostics are corroborated against the original,
without blanket suppression. Target identity and build IDs match, the matched
sidecars have no program headers, repeated outputs are byte-identical, and
original binaries, installed modules, harnesses and saved programs are unchanged
apart from the two documented Ghidra index-backup rotations. PIE/rebased
normalized location and compiler-storage receipts agree at both widths.

Runtime receipt SHA-256:
`735279829e7bf0e33aa3ec25ef05d8146ad0d710250f9f65e52dcd7310f18e7a`, at
`build/stack-local-review/effects/runtime-acceptance.json`. The tested JAR is
unchanged from the prior stack-local component:
`929929c7d0328ac93340e8d012d00a604acf8b7f424d110319a768d1679789ec`.
Its twenty actual Java 21 model suites and failure/cancellation results are
separate existing evidence; this test-only checkpoint does not claim fresh runs.
Both required target CI lanes run this harness at both widths and all three
address roles. Hosted acceptance still requires the dependency corrections and
the exact current-head gate. P1.11a and P3.3 remain incomplete: broader
calls/control flow, mixed pieces and scope relationships remain required.

```bash
export DWARFDUMP=/path/to/pinned/dwarfdump
python3 src/test/integration/stack-local-effects-export.py /path/to/private-packaged-ghidra x86_64 --width 32 --role exec
python3 src/test/integration/stack-local-effects-export.py /path/to/private-packaged-ghidra aarch64 --width 64 --role pie-rebased
```

Run every target/width/role combination. `--previous-ghidra` adds the prior
package's negative comparison; CI requires the compiler/Forge comparison.

## Retained setup failures

The first GDB probe treated the disassembler's inclusive end address as exclusive
and included an instruction after the function. It now passes `end - 1` and
requires the exact compiler function extent. The next probe correctly completed
the Forge runtime checks but the diagnostic scanner rejected a numbered `list`
line containing a synthetic `/* WARNING: ... */` source comment. Raw logs remain
intact; a separate diagnostic copy omits only numbered warning lines whose exact
text and line number match the corresponding generated source. The common
warning/error policy is unchanged. The initial audit expected the Java launcher
banner in stdout; the shared runner records it in a separate `.stderr` file.
The corrected audit checks both that banner and the in-process Java property.
None of those failed setup/audit attempts counts as acceptance.

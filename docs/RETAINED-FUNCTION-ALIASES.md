# Retained ELF aliases and curated function identity

**CONFIRMED locally; hosted acceptance pending:** original ELF function symbols
can coexist with curated typed DWARF names on the tested x86-64/AArch64 profiles.
This bounded policy advances [P1.7/#66](https://github.com/zwilcox/GhidraDwarfForge/issues/66),
which remains open. The implementation already preserves these original symbol
tables; this change adds reproducible integration coverage and records its limits.

## Consumer contract

The current curated Ghidra function name remains the DWARF definition's name.
Its return type, formal parameter, function-owned static and synthetic source
belong to that definition. The matched sidecar retains the original ELF
`.symtab` and `.strtab` bytes and section indices. GDB can resolve those original
function names and same-address aliases, associate their addresses with the
typed definition, and enter a frame named by the curated identity.

The fixture contains two mangled C++ function names and a real C alias of one
function. Ghidra applies independent qualified names and explicit integer
signatures. Each function owns a different static integer named `private_count`.
The test checks both original-name and curated-name `ptype` and ordinary
breakpoint resolution; execution enters through curated names and through an
original alias, then reads parameters and owner-qualified statics correctly.

No extra ordinary function DIE is created at the aliased address. No distinct
`DW_AT_linkage_name` is emitted. Prior experiments with these alternatives
failed LLVM overlap validation or hid curated-name lookup in GDB; see
`research/LINKAGE-LOOKUP.md`. This policy does not require choosing a preferred
original identity among multiple real aliases. `SourceType.IMPORTED` is not
proof of original ELF provenance: the preparation script deliberately adds an
unbacked imported-source label, and the exported symbol/DWARF inventories and
GDB must exclude it.

Fully stripped controls have no original static symbol table. Their curated
names, types, parameters, statics and source remain usable, but the missing
original function names and alias must remain absent. This proves the retained
ELF contribution separately from curated DWARF lookup. Analyst-added aliases
for fully stripped or sectionless inputs are still **PLANNED**; this contract
does not reduce the requirement to preserve meaningful curated knowledge.

## Reproduce and validate

CI installs `g++` for x86-64 and `g++-aarch64-linux-gnu` for AArch64. With the
packaged extension installed and existing validator/QEMU dependencies available:

```bash
for target in x86_64 aarch64; do
    for role in exec pie pie-rebased; do
        for symbols in retained stripped; do
            python3 src/test/integration/retained-function-aliases-export.py \
                "$GHIDRA_INSTALL_DIR" "$target" --role "$role" --symbols "$symbols"
        done
    done
done
```

The twelve cases perform 24 read-only exports from saved curated programs and
24 compiler/Forge GDB executions with 96 actual function calls. AArch64 executes
under QEMU with the private UNIX-socket helper. Checks include:

- Byte-identical repeat sidecar/source pairs and unchanged inputs, saved program,
  installed module and test sources; only known Ghidra index/journal backups may
  differ on read-only reopen.
- Matching ELF identity/build ID, preserved section addresses and original symbol
  table bytes, and no sidecar program-header table.
- Raw typed function/parameter/static DIEs, exact compiler-derived addresses,
  function-owned data, source lines, and absence of fabricated linkage/aliases.
- GNU inspection, LLVM verification and strict libdwarf checks for compiler and
  Forge artifacts. Inherited frame diagnostics require corroboration against the
  original under the existing strict-check policy.
- Positive and negative arguments, exact private values/addresses and returns,
  curated frame identity and source listing, `next`, `step`, and normal exit.
- Nonzero runtime PIE load bias and normalized link-time metadata after Ghidra
  rebase. PIE and rebased-PIE input bytes match.

Local independent retained-artifact review passes. Receipt SHA-256:
`7d6d6f43441748aa48a4ea48740aed326855a59901b0f187747eb7ed067a36fd`.
Evidence is retained under `build/alias-review/` and
`build/test-results/retained-function-aliases/` in the implementation worktree.
The matrix uses the accepted PR78 hosted package (production JAR SHA-256
`235cb2a8174d69b934b6f975efa8152a0388e897fd105ec26e36c8005a848017`),
whose 52 embedded production sources match this branch. Headless runs use
Java 25 with Java 21 bytecode; PR78's actual Java 21 packaged suites are separate
runtime evidence. This change adds no production Java/native modifications.
A fresh hosted gate and artifact review are required for this test/policy commit.

## Remaining scope

This is not complete linkage-name or general C++ support. Same-name overloads,
class/lexical DIE semantics, arbitrary secondary Ghidra aliases, addressless
external code, general thunk relationships, shared-object alias interposition,
other target/ABI profiles and debugger-injected ABI calls need separate evidence.
The test curates function-owned statics explicitly; it does not claim that every
compiler static or decompiler guess is recovered automatically. No release is
published by this work.

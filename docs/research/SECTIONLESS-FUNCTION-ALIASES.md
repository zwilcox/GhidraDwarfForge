# Sectionless function aliases: consumer experiment and implementation decision

**CONFIRMED research checkpoint (2026-10-31); production implementation PLANNED.**
The production alias planner still rejects inputs without a section-header table.
This experiment establishes a packaging prerequisite for P1.7/#66. It does not
establish headless extraction, production support, hosted acceptance or release
readiness. Existing sectionless function/DWARF export remains separate from
secondary alias insertion.

## Observations

Removing the section-header references from copies of twelve existing stripped
alias fixtures leaves executable program headers and dynamic metadata intact.
The unchanged installed writer can place two observed local function symbols in
its existing `.forge.load.<program-index>` allocation records. However, doing so
without a dynamic inventory makes existing original function names disappear in
four MIPS PIE/rebased-PIE cases, across both byte orders. LLVM accepts those
artifacts. A structural validator alone therefore cannot establish correctness.

An independent experimental mirror reads `PT_DYNAMIC` through uniquely
file-backed `PT_LOAD` ranges. It preserves every counted dynamic record's name,
binding, visibility, value and size; maps ordinary defined section indexes to
the corresponding synthesized load allocation; and inserts the two new locals
before the mirrored nonlocals. Undefined, absolute and common symbols retain
their distinct index semantics. GNU version definitions supply qualified names.
The original dynamic bytes remain in the preserved input prefix.

Eight cases with an established count pass GNU readelf, LLVM verification,
pinned strict libdwarf, and native/QEMU GDB: MIPS BE/LE exec, PIE and rebased PIE,
and x86-64 PIE/rebased PIE. There are 32 ordinary runtime calls with typed
original/analyst lookup, entry arguments, owned statics, return values, source
navigation and normal exit. Two additional GNU-versioned shared-object cases
pass 16 qualified name/type lookups, source lookup and four native `dlvsym`
calls. Repeated sidecars are byte-identical; protected inputs remain unchanged.
Independent raw review compares all mirrored records and unchanged DWARF with
the original section-based fixtures, rather than trusting the experimental
reader's output alone.

## A complete inventory needs a justified count

**CONFIRMED counterexample:** the x86-64 exec fixture has an empty GNU hash
with `symoffset=1`, but its original `.dynsym` has three records: the null symbol
and two undefined imports. Treating `symoffset` as the count silently drops
imports. The AArch64 fixtures also expose this ambiguity. Inferring an extent
from the next dynamic pointer or the highest relocation reference is not proof
that all original symbols were retained.

A separate 32-fixture source-built matrix covers x86-64/AArch64 GNU, SysV and
combined hash styles, MIPS BE/LE SysV hashes, exported/non-exported symbols and
exec/PIE. Twenty-nine PT_DYNAMIC inventories exactly match the original
compiler section tables. Three empty-GNU-only cases explicitly report that a
complete count is unavailable. In the saved consumer matrix, four cases have
that limitation and remain unsupported by this experiment.

The System V hash `nchain` supplies a count. Nonempty GNU bucket chains supply
a terminal extent in the tested layouts; all available count sources must
agree. The MIPS-specific symbol-count tag is checked only for MIPS and agrees
with its SysV count in these fixtures. An empty GNU hash alone supplies no
complete count. These observations do not authorize guessing through malformed,
ambiguous or untested metadata.

Reference semantics: [System V dynamic entries](https://osr600doc.xinuos.com/en/SDK_cprog/OF_DynSection.html)
and [glibc GNU hash lookup](https://github.com/bminor/glibc/blob/master/elf/dl-lookup.c).
The numeric tags were also checked against the installed `/usr/include/elf.h`.

## Selected implementation direction

**PLANNED**, before enabling production aliases:

1. Introduce a bounded, cancellable, file-backed PT_DYNAMIC inventory reader.
   Share name/version decoding with the existing dynamic mirror. Keep MIPS-only
   count and mode rules in the target policy. Reject conflicting counts,
   unterminated chains, ambiguous file mappings and incomplete inventories.
2. Share the synthesized load-section index calculation between planning and
   writing. Require unique original file-backed executable bytes for every
   alias body range; a segment's zero-filled tail is not code evidence.
3. Preserve the complete dynamic inventory before creating a static table.
   Keep name collisions, extended indexes, symbol modes and GNU versions
   explicit. A defined TLS symbol needs a separate TLS-relative mapping: the
   experiment rejects a real TLS fixture instead of treating its offset as a
   virtual address. Reserved/unsupported symbol semantics remain diagnosed.
4. If no complete inventory can be established, omit alias insertion with a
   precise diagnostic. Preserve ordinary primary DWARF export. Absence of
   PT_DYNAMIC is distinct from an unreadable or incomplete dynamic inventory.
5. Add real sectionless headless fixtures, immutable/rebased reruns, malformed
   metadata and cancellation controls, plus runtime/validator checks on both
   hosts and applicable targets. Run the exact final package through CI before
   accepting the feature. Do not close P1.7 from this packaging checkpoint.

The research Python reader buffers small trusted fixtures and the independent
packager edits only newly created experimental sidecars. Neither is suitable
as a production parser/writer: file-stream resource bounds, cancellation,
atomic publication, complete mode/TLS/extended-index policy and hostile-input
coverage still need implementation. No production source or workflow changes
are made by this checkpoint.

## Reproduce

Use Ghidra 12.0.3 with the range-aware alias package, an actual Java 21 runtime,
the usual cross-compilers/QEMU/GDB tools and pinned strict validator. The first
command builds its own source fixtures. The consumer commands reuse passing
`local-symbol-merge-integration.py` and `versioned-dynamic-symbols.py` artifact
roots; originals and saved Ghidra projects are not edited.

```bash
export JAVA_HOME=/path/to/build-jdk
export FORGE_JAVA21_HOME=/path/to/java-21-runtime
export DWARFDUMP=/path/to/pinned/dwarfdump
python3 src/test/research/sectionless-aliases/inventory-fixtures.py \
    --output build/sectionless-alias-review
python3 src/test/research/sectionless-aliases/run.py \
    --ghidra "$GHIDRA_INSTALL_DIR" \
    --base-root /path/to/local-symbol-merge-results \
    --output build/sectionless-alias-review
python3 src/test/research/sectionless-aliases/versions.py \
    --ghidra "$GHIDRA_INSTALL_DIR" \
    --base-root /path/to/versioned-dynamic-symbols/run.directory \
    --output build/sectionless-alias-review
```

Local evidence is under `build/sectionless-alias-review/`: consumer
`consumer.hovff4gt`, count matrix `inventory.63xfu4i3`, versioned DSOs
`versions.bog92up1`, and independent review `research-acceptance.json`.
Installed JAR SHA-256:
`1230ab163d5c74b9cef1db57fc1a6d591c04875f3b953edf46855484dae9a8c7`.
Independent research receipt SHA-256:
`bb9566e66f5a798f9ffcfc3471049659425e3668e3b1bc3017be43d82bbe3b05`.

Retained initial harness errors: the machine has a Java 21 runtime without
`javac`, so the probe is compiled with the build JDK's `--release 21` and run
on actual Java 21. The initial AArch64 diagnostic comparison used a nonexistent
compiler-log path; the maintained rerun resolves the actual protected compiler
log from the base fixture command record. The inherited QEMU VDSO diagnostic
then matches its compiler control; the ordinary runtime assertions pass. Four
MIPS missing-name failures remain genuine negative controls, not filtered
warnings. Initial logs are retained in the root checkout's
`build/sectionless-alias-research/`.

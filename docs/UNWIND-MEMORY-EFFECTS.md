# Compiler memory effects and instruction profile (#112)

**CONFIRMED locally:** the native adapter now represents direct default-RAM
varnodes as memory operations. An address-bearing p-code varnode denotes memory
contents; it is neither an immediate integer nor a register. This distinction
was missing for the unchanged compiler reference's x86-64 `cfi_sink` accesses.
The previous adapter converted them to opaque effects. AArch64's explicit
LOAD/STORE representation already exposed the same global address.

Direct reads now load into fresh instruction-local temporaries. Direct outputs
compute into a fresh temporary and then store exactly the declared byte width.
Copy, arithmetic, ordinary LOAD/STORE, and unknown pure-result writes preserve
p-code operation ordering. Fresh coordinates are allocated beyond every raw
unique varnode in that instruction, with overflow and cancellation checks.
Unsupported memory spaces and non-byte-addressed direct memory remain rejected.

The alias rule is unchanged: an unresolved absolute write may overlap saved
stack state and therefore clears that memory evidence. A global name or an ELF
data section does not silently authorize a disjoint-stack assumption. The real
compiler reference now reaches the specific unproved-store refusal on both
targets, instead of failing first on unsupported instructions or opaque memory
operands. It emits no recovered plan. This is **not** positive acceptance of
synthetic unwinding for that global-writing reference.

The user has been asked whether the supported storage profile should explicitly
assume ordinary stacks are separate from ELF globals or require explicit stack
region evidence. Until that boundary is settled, the strict alias behavior is
retained. Production recovery and full #112 acceptance remain **PLANNED**.

## Instruction audit

The unchanged reference also exposed missing integer-profile entries:

- `ENDBR64` changes CET branch-tracking state, without changing the integer
  register/stack-memory facts used by this model. Ghidra 12.0.3 emits empty p-code
  for it. Its inclusion follows the instruction audit, not a rule that all empty
  p-code is harmless. Hidden AArch64 PAC controls still reject recovery.
- AArch64 `CSET` writes the selected general register based on condition flags.
  Both 32-bit and 64-bit forms are tested; the 32-bit form writes the full mapped
  register with zero-extension. The flow drops the destination's incoming
  identity rather than inventing a predicate result.
- x86 `SETNZ` writes a byte destination. Register writes invalidate overlapping
  incoming register facts; the memory form emits a byte store and retains the
  conservative alias behavior.

The audit uses [Intel SDM Volume 2, ENDBR64 and SETcc](https://cdrdv2-public.intel.com/782156/325383-sdm-vol-2abcd.pdf)
and [Arm Instruction Set Reference Guide 100076_0100_00_en, CSET](https://documentation-service.arm.com/static/6245c734b059dc5ff9a8bdab),
plus the installed Ghidra 12.0.3 `cet.sinc` and `AARCH64base.sinc`. Source hashes
and the extracted text are retained in the evidence archive. This does not claim
support for arbitrary CET/shadow-stack or authenticated-return mechanisms.

## Validation

The initial `endbr64`/`cset`/`setnz` refusals and opaque global accesses are retained.
New native cases check global loads, full/byte stores, read-modify-write temporary
separation, loss of potentially aliased saved values, and all cancellation polls.
The profile suite also verifies unchanged return/stack/preserved-register rules
and loss of conditional-set destination identities.

Passing local results:

- 751 profile, 1849 instruction-adapter, 4470 closed-callee, 102 flow, 182 call
  contract and 158 encoder component checks; extension build and workflow guards.
- Four observation/refusal probes of the unchanged compiler source, covering
  x86-64/AArch64 at original and rebased Ghidra addresses. GNU symbols independently
  identify `cfi_sink`; the captured store resolves to its exact address and width.
  Unknown aliases still refuse synthesis and leave no plan output.
- Extended assembly runtime fixtures exercise global reads and the newly audited
  instructions. All four recovered-frame non-PIE/PIE cases pass GNU/LLVM/pinned
  strict checks and GDB comparisons across eight plain/compressed sidecars and
  sixteen debugger sessions. The encoder's independent artifact/runtime suite
  also passes after the fixture additions.

The original `synthetic-cfi.c` global increment remains unchanged. The observation
harness is a negative acceptance control, not a replacement for the required
positive compiler-reference recovery. Full storage separation, shared/compiler
coverage, production integration and failure/cancellation acceptance remain open.
New hosted coverage is **PRESENT, UNVERIFIED** until its exact head passes CI.

Separately, PR167's original-frame preservation passed all hosted target/Windows
checks and required-validation. An independent artifact review verifies thirty
cases, sixty packaged exports, thirty raw strict reports and six removed-frame
controls. It is ready but remains behind PR166's integration priority. See
`docs/evidence/original-cfi-hosted-review.json` and the memory-effect receipt.

# Independently migrating incoming pieces

**PRESENT, UNVERIFIED for full runtime acceptance:** the incoming composite
proof now tracks each register or stack piece independently through the shared
ordered value-flow engine. It validates the complete attached Ghidra parameter,
formal/storage sizes, exact register slices, stack-space identity, join order
and nonoverlapping carriers before seeding any fact. It does not manufacture
detached scalar parameters to bypass those checks.

Ghidra's significance-ordered join becomes DWARF memory-ordered pieces according
to the program's byte order. The composition intersects each piece's proven
instruction intervals. Every piece must be available; a surviving half never
becomes a location for the whole object. Body holes remain absent. An existing
valid prefix is retained and only its unavailable intervals are refined.

The shared engine now interprets exact affine stack-pointer changes in p-code
order for incoming values. Allocating stack space does not discard a caller's
still-valid incoming slot. Releasing space retires overlapping slots according
to `CompilerSpec.stackGrowsNegative()`; unknown or partial pointer writes retire
memory facts. Local identity retains its previous conservative frame-change
policy. Calls still invalidate memory unless a separate proof establishes it.
No native ABI change is involved.

## Confirmed evidence

**CONFIRMED model acceptance:** `CompositeValueFlowSmoke` passes 1,032 checks on
actual Java 21 against the built production JAR. The x86-64/AArch64 models cover
32/64-bit pieces, register/register and explicit register/stack storage, spills,
loads, delayed incoming loads after allocation, partial overwrites, unknown and
known nonalias stores, released slots, surviving memory backups and lost halves.
Public type extraction, detached-identity rejection, missing instructions and
cancellation are checked. ARM32 little- and big-endian decoder models check
piece order with a terminal self-loop. These models do not establish a new
supported runtime profile. All 24 related Java 21 suites pass, with source
hashes and loaded class origins recorded.

**CONFIRMED narrow runtime acceptance:** the existing compiler-copy fixture
passes on x86-64 and QEMU AArch64, with computed and saved custom storage. Eight
real exports and 48 compiler/candidate GDB instruction observations establish
both field values after the incoming register is overwritten: the first field
survives in the compiler's actual full-width backup and the second retains its
original carrier. Independent raw DWARF decoding requires the original pair
and copied pair at their exact boundaries. GNU/LLVM and pinned strict validators,
types/source lookup, normal exit, deterministic repeated artifacts and original/
module/program observation preservation pass. The strict check corroborates
inherited compiler-frame diagnostics against the original artifact.
Both targets' existing dynamic composite-storage regressions also pass their
computed/custom export, validator and GDB checks; their logs are retained as
`dynamic-x86_64.log` and `dynamic-aarch64.log`.

The existing composite-prefix regression now requires these available values
instead of its previous unavailable tail. Its physical-copy and exact raw
location assertions remain mandatory. The old prefix-only API still has its
original direct tests; the public exporter composes the stronger proof.

Evidence is under `build/composite-value-review` in the mixed-piece worktree:

- `java21/acceptance.json`: all 24 packaged-production model suites.
- `prefix-runtime-acceptance.json`: SHA-256
  `f0a5f62549417ea2934a8d640dc3a5a3ec2bbf401d72ba40d083e2a28fbbbf75`.
- `prefix-x86.log`, `prefix-aarch64.log`, and their referenced result directories.
- `architecture.log` and `architecture-controls.log`: unchanged guard and seven
  negative controls.

## Remaining acceptance and retained failures

**PLANNED:** dedicated compiler-oracle migration fixtures for independent
register/stack pieces, all required address roles, unavailable transitions,
control-flow/call boundaries, raw interval checks and actual values at each
executed instruction. Recheck failure/cancellation and broader runtime regressions
after the shared stack-pointer refinement. Require exact final package and
hosted target/host gates before integration. P1.11a and every remaining P3.3 row
in `LIFETIMES-AND-SCOPES-PLAN.md` remain open.

Initial failures are retained. `late-load-initial.log` demonstrates the previous
loss on stack allocation. `models.log` records the old public-prefix assertion
rejecting newly available copied fields. `models-2.log` demonstrates that the
original lost-second test still had a valid incoming memory backup; the fixture
now separately tests that positive case and explicitly overwrites the backup
for its negative case. The ARM `bx lr` experiment fails the existing ordered
control proof; its logs are retained, and no acceptance is claimed for that
form. The byte-order model instead ends with a real decoded self-loop. Initial
Gradle model runs use Java 25 and are separate from actual Java 21 acceptance.

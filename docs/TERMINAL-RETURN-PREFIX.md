# Incoming register lifetimes at an ordinary terminal return

**CONFIRMED locally; hosted acceptance pending (2026-10-25).** ARM's decoded
`BX LR` includes a `CALLOTHER` mode-change operation before its final `RETURN`.
The whole-function stable-register proof already recognizes this ordinary
terminal boundary. The incoming-prefix proof previously rejected it, losing
otherwise provable integer, floating and register-composite arguments before
their first overwrite.

The prefix proof now reuses the existing ordinary-terminal-return predicate.
The return must be the final, fully decoded instruction, with no length or
fall-through override, conditional/computed jump, delay slot, competing control
flow, or malformed return operand. Every user operation must have a constant
selector. `UNIMPLEMENTED` and nonterminal user operations still reject the
whole proof, including hazards after an earlier register overwrite.

Locations describe state before a machine instruction. The returned invocation
has no subsequent instruction at which a terminal user operation's effects
could be observed. This permits no user-operation purity assumption, syscall
whitelist or architecture-specific opcode exception. Existing first-write,
complete-body, entry-reference, register-map, piece-order and backup checks
still apply. A composite's whole value becomes unavailable after its earliest
piece overwrite; no surviving-piece or stack-copy location is inferred.

## Validation contract

`OpaqueRegisterEffectsSmoke` uses actual ARM MOV/NOP/BX decoding to exercise
scalar and composite incoming prefixes. Twenty-four controlled negative shapes
cover malformed/competing p-code, opaque middle instructions, metadata, delay
slots, return lengths and fall-through. The existing real AArch64 syscall and
cancellation checks remain. `DynamicCompositeOrderSmoke` checks a complete
computed ARM pair until its first write and an unavailable tail, with object
order unchanged. Existing coverage, register-copy, direct-call, composite-prefix,
dynamic-parameter and type/name models remain required.

The real floating harness checks ARM32, x86-64 and AArch64 exec/PIE inputs,
rebases, deterministic repeats, compiler values, exact overwrite boundaries,
stored globals, source lookup, stepping and normal exit. ARM's `fp_clobbered`
now retains `13.75` at entry and immediately before its overwrite, and becomes
unavailable afterward. Its omission report must start at `fp_clobber_after`.

The dedicated ARM `terminal-composite` fixture checks a computed eight-byte
pair with fields `{-19, 37}` at entry, after the prologue and at the overwrite.
Afterward GDB must report the entire pair unavailable while machine `r0` is
zero and the stored globals remain correct. The pipeline runs both exec and
PIE, rebased imports and deterministic repeats. Its checker corroborates raw
DWARF `r0/r1` 32-bit pieces, normalized location endpoints, Ghidra's recorded
image-base translation, actual installed JAR origin and unchanged protected
inputs. GNU, LLVM and pinned strict libdwarf validation are required.

GCC's aggregate stack-home location is wrong before its prologue stores
execute. The compiler-entry result is retained explicitly as unvalidated;
entry machine arguments are checked separately. Compiler field comparisons
are strict after the prologue and before the overwrite. This distinction is
also required by the earlier mixed register/stack investigation.

## Local evidence and retained failures

The isolated local package JAR is
`c129db523d509d0db67f21b1fccd567ca58d0a39e2088ef3f01fc283aba96c75`.
Ten freshly compiled test suites pass on actual Java 21, with class-load
origins bound to that packaged JAR. Local headless Ghidra uses Java 25.0.4.1;
hosted Java 21 results remain a separate acceptance requirement.

The floating run `run.ltPEJj0x` passes eighteen exports across three targets.
ARM's existing computed/custom/reopened aggregate regression
`arm32.LjR4Qt87` passes four exports. The initial complete terminal-pair runtime
matrix `run.qoM8xdUs` passes six exports, validators and GDB; a subsequent final
harness run `run.QjnHMSJp` also passes recorded image-base metadata and protected
source checks. Its receipt SHA-256 is
`9fc8a499f838d4cb4a2595a78b627fcf8074c5e481b3f3c9cad00cb1515cd3f0`.
The actual Java 21 receipt is
`da47c449b805cc59c3cbfad75d8df06622502ea5085bae5a3becdd8336f0176f`.
All six dedicated composite exports report zero strict validator errors. The
floating AArch64 cases retain seven independently corroborated inherited frame
diagnostics each; there are zero unexplained diagnostics. They are not reported
as strict-zero artifacts.

Failures are retained under `build/terminal-review`:

- `baseline-model.log` reproduces the empty incoming prefix with old production
  code. The first modified-model run incorrectly assumed the same omission
  precedence for both composite piece orders; the corrected negative fixture
  places the overwritten piece first to exercise the full prefix proof.
- The existing dynamic-composite test expected the old ARM omission. Its
  assertion now checks the exact complete prefix, piece order and whole-value
  unavailable tail, rather than merely accepting a nonempty list.
- `run.sQir1Hxw` stopped on a driver assertion expecting an omission message;
  a bounded prefix emits a lifetime-limitation diagnostic instead. The corrected
  driver also checks the report's exact unavailable interval.
- `run.fhqhSvSR` failed the compiler aggregate location at raw entry. Its real
  machine arguments were correct. The corrected oracle explicitly separates
  that observation from compiler fields after prologue execution.
- The first terminal-composite checker omitted Ghidra's initial PIE mapping
  offset. It failed against otherwise passing runtime artifacts. The final
  script records the actual current and original bases and checks their
  difference, separately from the requested additional rebase.
- Hosted run `40234561115` rejected the new C file because the shared fixture
  reproducibility harness's explicit source inventory was not updated. Package
  and actual Java 21 checks passed, but target build gates stopped before their
  exporter cases. The inventory now includes `terminal-composite.c`; all five
  source-built target inventories and deterministic fixture checks are rerun
  before restarting the complete gate. This is a harness omission, not accepted
  hosted runtime evidence.

No new native binding, ABI, mixed register/memory support, automatic backup,
later-local inference, Thumb claim or release publication is part of this work.

## Hosted regression correction

Run `40235383982` at `8527d28` failed the ARM extended-section step: its old
scalar oracle still required complete omission of `recovered_add::left`.
The emitted register prefix was correct. The shared-object oracle also retained
that obsolete expectation for both parameters. These checks now require the
bounded-lifetime diagnostic and GDB values `left=19, right=23` at the initial
breakpoint. Later whole-value unavailability remains covered by the dedicated
scalar floating and register-pair fixtures.

The unchanged tested production JAR passes the corrected extended-section
exec/PIE/repeat suite (`run.i8pTH80U`) and a shared-library export plus runtime
GDB. Pinned strict libdwarf reports zero errors for all four artifacts; GNU,
LLVM, GDB and input preservation checks pass. An earlier local attempt
(`run.Q9lvCuAC`) used the system dwarfdump instead of the pinned validator and
failed its completion check; it is retained and is not acceptance. The hosted
failure remains recorded, and a fresh combined gate is required before merging.

## Remaining ARM oracle corrections

PR58 run `40237292953` and the initial combined PR59 run `40239553691`
failed the ARM/Thumb finish checker: it still required `left` to be unavailable
throughout the function. The captured GDB transcript instead reads the correct
incoming values at the source breakpoint. Its raw location list ends exactly
at the fallthrough of the Thumb `mov r0,r3` return-value write. These runs are
not accepted; successful packages and other lanes do not override that failure.

A local audit of the later ARM tests found the same obsolete whole-function
omission requirement for the `vfp_sum` parameters in the mixed base/VFP-PCS
fixture. Both parameters now have a bounded prefix; writing `s0` invalidates
the shared physical `d0` base conservatively, including the `s1` slice. No
surviving-piece recovery is inferred.

The corrected oracles require exact values before the real write and unavailable
Forge parameters immediately afterward. Compiler DWARF retains its stack values;
raw return registers independently hold the computed sum. The finish checkers
also compare the precise emitted register/bit-piece expressions, exclusive
prefix end and unavailable report tail against the decoded machine boundary.
No production or fixture bytes change for these corrections.

Fresh saved-program runs `arm-thumb-mode/run.U2mad1LN` and
`arm-dynamic-pcs/run.AHNtzPIt` pass four total exports, deterministic repeats,
GNU/LLVM/strict validation, QEMU/GDB and input/module preservation. All strict
checks report zero errors. A first local Thumb attempt placed its boundary
breakpoint after source stepping could already pass the write; the retained
`run.FeGtGUbQ` failure led to placing that guard before `next`. The original
mixed-PCS failure is retained as `run.vOLFLVSh`. The corrected complete hosted
gate remains required before integration.

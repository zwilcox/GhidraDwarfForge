# Ordinary unwind profiles (#112)

**CONFIRMED locally:** metadata selection and guarded native instruction capture
for the two initial integer profiles. **PLANNED:** verified call summaries,
frame-rule projection, original-byte agreement and production synthesis.
This component does not enable exporter CFI or complete #112.

## Selection and entry evidence

The isolated `targets/UnwindAbiProfile` uses the pinned sources in
[the ABI audit](UNWIND-ABI-AUDIT.md). It selects ELF64 little-endian linked images
with zero target flags, ABI version zero, and System V or Linux OS ABI. Selection
requires exact Ghidra language/compiler/convention identities, the expected
compiler stack register and eight-byte physical registers. External/thunk
functions, custom storage, call fixups, unexpected purge and process-entry
functions are excluded. Process-entry comparison uses the original ELF address
domain after normalizing an explicit rebase delta.

| Profile | Ghidra compiler/convention | Entry evidence |
| --- | --- | --- |
| x86-64 SysV integer | gcc / `__stdcall` | CFA = entry RSP + 8; return address at entry RSP |
| AArch64 AAPCS64 integer | default / `__cdecl` | CFA = entry SP; return address in X30 |

These convention names describe the inspected Ghidra 12.0.3 specifications.
The x86 language's default compiler is Windows, so selecting the language default
would be incorrect for the SysV profile. Windows and Golang compiler fixtures
are rejected. An unknown function convention uses the verified compiler default;
an explicit different convention does not.

Entry general-register identities, the caller return address and current program
counter are distinct. X30 is not assumed preserved across a call despite Ghidra's
unaffected list. The component supplies callee-saved candidates; it does not
prove that a particular callee obeys them. Register maps and mnemonic policies
remain inside this audited target file, which is explicitly named by the
architecture-neutrality guard.

## Hidden instruction semantics

Ghidra 12.0.3's AArch64 processor specification defaults `ShowPAC` to zero.
`AARCH64_base_PACoptions.sinc` makes `paciasp` produce **empty p-code** under that
setting. Therefore absence of p-code is not proof of no machine effect.
The native regression observes exactly that empty result, observes the visible
user operation with `ShowPAC=1`, and rejects both from the ordinary profile.
A later hidden `paciasp` after a valid NOP also rejects capture.

Every capture now requires an explicit instruction policy; there is no overload
that silently assumes ordinary instructions. The profile applies a positive
mnemonic set and restricts physical register effects to its integer registers
and flags. Thus a scalar-looking `str` of D8 is rejected. The x86 profile also
requires a known long-mode context. Empty-p-code NOP remains valid under the
selected policy. Unknown operations handled by the generic lowerer still make
the instruction opaque; a recognized mnemonic alone does not prove all effects.
The raw decoder suite deliberately supplies a named raw-only policy so it can
continue observing unsupported instructions without claiming ABI acceptance.

PAC, MTE, SVE, SME, SIMD preservation, APX, exception/signal transitions and
alternate calling conventions are outside these initial profiles. The explicit
allowlist is a bounded recovery policy, not a claim that every ordinary compiler
instruction is covered. Future additions require native evidence and full
exporter/runtime acceptance. No function-name heuristic recognizes special
frames; metadata selection alone is not proof that arbitrary machine code obeys
an ABI. Callee effects and every used recovery state still need verification.

## Validation

```bash
./gradlew unwindAbiProfileSmoke ghidraUnwindInstructionsSmoke unwindFlowSmoke callFrameEncoderSmoke buildExtension
src/test/integration/architecture-neutrality.sh
actionlint
```

The profile suite passes 235 checks across 11 native fixtures. Controls include
compiler/convention selection, ELF class/order/type/machine/flags/OS ABI,
process entry before/after rebasing, custom storage, call fixups, stack purge,
hidden/visible/later PAC, SIMD, wrong execution mode, every observed selection
and guarded-capture cancellation poll, and a clean retry. Ordinary save/restore
fixtures pass through selection, guarded capture and flow analysis, recovering
the return target, post-return stack and all selected callee-saved identities.
A linked shared-image metadata control is not a shared-library runtime test.

The existing raw decoder suite now passes 653 checks (the additional mandatory
policy cancellation polls increase its count), the flow suite passes 75, and
the encoder suite passes 158. Extension build, architecture guard and workflow
lint pass. CI includes the profile suite; hosted execution remains
**PRESENT, UNVERIFIED**. These are actual ProgramDB/Sleigh component tests,
not GDB validation of newly emitted CFI. No emitted DWARF behavior changes here.
See [the receipt](evidence/unwind-profiles.json) for hashes and retained evidence.

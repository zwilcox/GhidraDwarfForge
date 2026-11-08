# Initial unwind ABI audit (#112)

**CONFIRMED:** the pinned source and Ghidra-resource observations below.
**CONFIRMED locally:** isolated [profile selection](UNWIND-PROFILES.md) and native
flow components. **PLANNED:** production recovery and all new support claims.
The [receipt](evidence/unwind-abi-audit.json) binds source revisions, resource
hashes and a retained local archive. No native/JNA interface changes are needed.

## Source baselines

- AMD64 psABI `e1ce098331da5dbd66e1ffc74162380bcc213236`,
  [register use, stack frame and DWARF mapping](https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/e1ce098331da5dbd66e1ffc74162380bcc213236/x86-64-ABI/low-level-sys-info.tex).
- Arm 2025Q4 `daa7a94ca55973736c0e434a67a6e4bbcd35d7fa`,
  [AAPCS64](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/aapcs64/aapcs64.rst),
  [AADWARF64](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/aadwarf64/aadwarf64.rst), and
  [AAELF64](https://github.com/ARM-software/abi-aa/blob/daa7a94ca55973736c0e434a67a6e4bbcd35d7fa/aaelf64/aaelf64.rst).
  This retains the project's existing Arm baseline instead of silently adopting
  the newer upstream branch examined during initial encoder research.
- Installed Ghidra 12.0.3 compiler specifications and DWARF maps, separately
  hashed in the receipt. Their data informs selection and corroboration, but
  does not replace the ABI or decoded instruction effects.

## Ordinary entry and call rules to implement

| Profile | Entry CFA and return address | General registers preserved by an ordinary call |
| --- | --- | --- |
| x86-64 SysV LP64 | CFA = entry RSP + 8; return address at entry RSP; DWARF return column 16 | RBX, RBP, R12–R15; post-return RSP restored |
| AArch64 AAPCS64 LP64 | CFA = entry SP; return address initially in X30; DWARF return column 30 | X19–X29 and SP |

AMD64 DWARF column16 is a return-address column even though the current machine
RIP is not that saved caller address. Its 128-byte red zone cannot be treated as
preserved caller storage across another ordinary call. AArch64's V8–V15 call
preservation applies only to their low64 bits. X18 is platform-sensitive; the
initial profile must not assume it is preserved. These observations rule out
naively copying a variable register map into an unwinding model.

AADWARF64 defines PC32 separately from LR30 and specifies CIE initialization
obligations, including a defined initial rule for used callee-saved registers.
Its consumer defaults are not evidence for arbitrary caller values. The encoder
must accept explicit CIE rules from the profile; blanket undefined CIE rules
followed by FDE overrides are insufficient for that contract. The existing
assembler-reference fixture uses a same-value CIE rule for X19. Its earlier
PC-undefined failure also shows why a working return column alone is not enough
to claim complete consumer behavior.

## Ghidra disagreements and inference boundaries

The installed `AARCH64.cspec` lists X30 as unaffected. **Inference:** that entry
must not authorize preserving an incoming LR identity through a decoded call;
actual call semantics replace LR with the return target. The analysis needs a
separate return-address identity, explicit call effects and post-return state.
Similarly, an instruction's current PC is not the saved caller PC. These will
be independently tested against native p-code and debugger observations before
any production rule uses them.

Selection must validate ELF class/endianness/machine and the selected language,
compiler specification and function convention. Initial candidates are
`x86:LE:64:default` with gcc and `AARCH64:LE:64:v8A` with default AAPCS64;
Windows/Golang, MSABI, syscall and process-entry conventions need separate
semantics. A matching processor string alone is insufficient. The entry-point
startup function cannot automatically be treated as an ordinarily called frame.

The profile must also positively delimit ordinary instructions and reject
unmodeled authentication, interrupt/exception transitions, stack switching and
unknown mode changes. ELF GNU properties can provide evidence, but absence of
a property is not proof that every instruction is ordinary. No PAC, MTE, SVE,
SME, APX or asynchronous-frame support is claimed by these observations.

The recovery model must track entry-register identities, return address and
affine entry-SP addresses through complete instruction effects. Full-width saves
and restores require exact memory identity; overlapping or uncertain writes end
the corresponding proof. Calls and stack release must invalidate affected slots.
A join keeps only rules proved identically by every reachable predecessor.
Unsupported regions require explicit omission, never extension of an earlier
row through an unknown interval. See [the full evidence model](SYNTHETIC-CFI-EVIDENCE.md)
for remaining tests, including split/shrink-wrapped prologues and cancellation.

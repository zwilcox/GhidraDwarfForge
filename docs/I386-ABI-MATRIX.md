# Selected i386 libc, SSE, vector and convention matrix

**CONFIRMED locally; hosted acceptance and protected integration pending.**
This component advances the original #71 requirements. The full #68–#71 scope
in `TARGET-ABI-COMPLETION-PLAN.md` remains binding; this does not close an issue
or establish every i386 or host-specific target ABI.

The existing i386 register table omitted XMM registers. Explicitly curated
vector and SSE parameters therefore had unavailable locations even when their
hardware values were independently readable. The isolated i386 map now includes
XMM0–XMM7 as DWARF registers 21–28, matching Ghidra 12.0.3's
`Processors/x86/data/languages/x86.dwarf`. ST0, XMM8 and YMM0 remain outside this
location profile. Generic location/lifetime algorithms are unchanged.
Real Ghidra register hierarchy tests cover all eight registers at 4/8/16-byte
widths; actual runtime coverage uses XMM0–XMM2, not all eight registers.

## Fixture and debugger contract

The source-built fixture uses actual malloc/free/memcpy/memset and eleven
non-inlined functions under the selected Linux i386 GCC ELF profile. The harness
imports a stripped original, curates the saved Ghidra program, and exports twice
through the installed production entry point. Original/package/program files
are hashed; only documented Ghidra filesystem index backups may rotate.

| Functions | Contract |
| --- | --- |
| float, double, long double | Exact stack arguments and automatic typed x87 return values |
| vector addition | Two complete XMM arguments, raw XMM return and exact destructive-write gap |
| Pair and Mixed structures | Aggregate/stack arguments, raw backing bytes and typed aggregate returns |
| SSE register parameters | Three doubles in XMM0–2, raw XMM return and exact destructive-write gap |
| regparm(3), stdcall, fastcall, thiscall | Explicit signature/storage, independently read register/stack arguments and raw integer returns |

The fixture installs analyst compiler-spec extensions for the three conventions
missing from the pinned GCC compiler spec: sseregparm, stdcall and fastcall.
These are saved fixture knowledge, not new product compiler specifications.
Existing regparm(3) uses Ghidra's computed model. Vector/SSE/stdcall/fastcall/
thiscall parameters use explicit analyst storage; thiscall's ECX pointer is
checked against actual inferior memory. The vector is an explicitly named
four-float analyst array, not a fabricated native compiler vector type.

All six custom/nondefault signatures retain the existing debugger call guard.
Named injected calls must fail before PC/SP/GPR/XMM state changes; automatic
return decoding must remain unavailable. Independently read hardware return
values must match the fixture. No new injected-call ABI support is claimed.

The untouched compiler reference has two documented GDB consumer limits:
its Mixed argument may be optimized out at function entry, and automatic
vector/sseregparm return values can be wrong. Raw argument memory/registers and
raw returns must still be exact, and those discrepancies are retained explicitly
in `referenceLimits`. Forge's entry argument values receive no such exception.
The five ordinary return signatures require correct automatic typed results.
Earlier GDB 17.1 research also reproduced the vector/SSE automatic-return issue;
this component does not silently convert that issue into a passing return claim.

## Failure and negative controls

A one-instruction native decompiler limit forces `vector_add` to fail. Repeated
exports must emit one diagnostic source comment and a symbol-only function DIE,
without formal children, invented source line or return type. Its name/address
and raw execution/return remain correct; all ten neighboring ABI functions must
retain their original checks. The shared failure helper now selects the same
parameter-allocation policy as the production source pass. AArch64 vector and
failure/cancellation regression tests cover that helper change.

Each layout also imports a separate 128-MiB padded ELF, preserving production
identity verification, then cancels the real installed exporter during bounded
file copying. The existing sidecar/source pair and saved program must remain
unchanged, with no temporary publication files left behind.

Four isolated corruptions per layout change either the XMM carrier or the
incoming-value lifetime end for vector/SSE arguments. GNU, LLVM and the pinned
strict checker accept these structurally valid files. GDB must reject the wrong
entry value or the incorrect value after the exact clobber instruction. An
unchanged positive copy must pass all eleven functions. Original artifacts
remain unchanged. CI requires all four layouts, controls and retained logs.

## Local evidence

Final installed JAR:
`b1754a51b09ba93a99e3afc17fe2d9e7d70d0ffcfdbe707ad2a071e3e80e87ca`.
Assembled package ZIP:
`ef7f1d875b14f82a1cf1eefe3fe8010a01e13021399f4ddb87e41c611d564c19`.
All 106 recorded production-source hashes still match the tested package.
The strict checker is PR149's pinned eight-correction validation-only bundle.

| Layout | Case under `build/test-results/i386-abi-matrix` | Failure/cancellation | Corruptions |
| --- | --- | --- | --- |
| non-PIE | `exec.nxzhe1y9` | `controls.ue8zxvmm` | `negative.1o311__5` |
| sectionless | `sectionless.7r4gc94v` | `controls.fu4gg1qz` | `negative.qhobifp7` |
| PIE | `pie.dayb1r8l` | `controls.3ryq6qen` | `negative.i7neyfqq` |
| rebased PIE | `pie-rebased.36v08sgl` | `controls.bs0u2bv_` | `negative.gfm4liwh` |

Every full harness exits zero: eight normal and eight failure exports are
pairwise deterministic; four production cancellations and sixteen structurally
valid wrong-location rejections pass. GNU/LLVM/strict structural checks,
compiler/Forge debugger values, source lookup and normal runtime exit pass.
The compiler reference limits above remain explicitly recorded.

AArch64 regression `build/test-results/aarch64-vector/exec.rpg771l_`, including
`controls.beq30rie`, passes with the same package. BuildExtension,
VariableStorageSmoke and RegisterAliasSmoke pass. Fixture inventory and thirteen
x86-64 byte-identical fixture rebuilds pass; workflow lint, Python compilation
and diff checks pass.

The `i386-abi-matrix` worktree receipt is
`build/i386-abi-matrix/complete-matrix-v6.json`, SHA-256
`580c22e9d1173f8ceb6b6110cbe846c63114979e2b4985dc7042aecc5b5fb192`.
Retained failed experiments include initially unknown fixture conventions,
a signed ECX-pointer conversion, the separate GNU-vector validator false
rejection, a collector Path error and an ARM-only parser incorrectly reused
by the first negative harness. None is counted as passing evidence.

Hosted Linux/Windows acceptance, independent artifact review, protected
integration, additional target-ABI classification and the full original scope
audit remain required. The existing i386 shared/dynamic-symbol/alias lanes stay
in CI and must pass on the final integrated head.

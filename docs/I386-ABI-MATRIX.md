# Selected i386 libc, SSE, vector and convention matrix

**CONFIRMED locally; hosted acceptance and protected integration pending.**
This component advances the original #71 requirements. The full #68–#71 scope
in `TARGET-ABI-ACCEPTANCE.md` remains binding; this does not close an issue
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

### Hosted compiler-vector diagnostic correction

**CONFIRMED:** PR150 run `41469749960`, x86-64 job `125365045287`,
stopped before importing/exporting the new matrix. GDB 15.1 reported
`Cannot access memory at address 0x1` while its Python finish breakpoint tried
to decode the compiler's vector return. Its JSON otherwise recorded all eleven
functions as passing, with the vector automatic return unavailable and the raw
XMM0 return correct. The strict stderr check correctly rejected that run.
Artifact `13157115518` retains the original compiler executable and logs.

The consumer failure is reproducible with the unchanged four-byte vector body
(`addps xmm1,xmm0; ret`). GDB's i386 array-return path reads through EAX;
the function returns its real vector in XMM0. An incidental readable EAX
produces a wrong automatic value, while EAX=1 produces the observed exception.
This extends the already recorded compiler automatic-return limitation; it is
not a newly validated typed vector return. The locally inspected GDB 17.1
`gdb/i386-tdep.c` `i386_return_value` and
`gdb/python/py-finishbreakpoint.c` agree with the runtime reproduction.

The oracle now captures only the compiler-vector finish operation. An exact,
single `gdb.MemoryError` is recorded in `finishDiagnostic` only when its address
equals unchanged EAX, inferior memory at that address is independently
unreadable, the automatic return is unavailable, the real return PC matches,
and all four XMM0 values are correct. The breakpoint's routine stop message is
silent so GDB 15.1 and 17.1 expose the same diagnostic boundary. Forge, all other
functions and unrelated warnings/errors retain their strict gates. Source
lookup and every existing argument/return/clobber check remain required.

Each layout adds two owned compiler-reference controls: EAX=1 reproduces the
known consumer failure while actual execution and all eleven functions pass;
changing a vector argument must still fail the raw-value check. These controls
verify the exact instruction bytes, alter registers only in their separate
reference processes, and preserve executable bytes. Twelve parser controls
reject other functions, Forge, wrong values/addresses, additional diagnostics
and missing independent evidence. The old oracle reproduces the failing stderr
gate; both GDB 15.1 and 17.1 pass the corrected controls.

The final local full-matrix cases are `exec.0s4ggs5y`,
`sectionless.v2su5qzf`, `pie.wifw3nsf` and `pie-rebased.4f21j2dj` under
`build/test-results/i386-abi-matrix` in the `i386-reference-diagnostics`
worktree. All sixteen normal/failure exports, four cancellations, sixteen
wrong-location rejections and eight new reference controls pass. GNU, LLVM,
pinned strict validation, original/program preservation and deterministic
reruns pass. Workflow lint, Python compilation and diagnostic controls pass.
The unchanged PR151 package has JAR SHA-256
`30d90f1c3d754ffba93c750a00703e1792df9cdd15f04964d3528153b8b4a929`;
all 106 production-source hashes match that tested package. Receipt:
`build/i386-reference-diagnostics/validation.json`, SHA-256
`88acadcc655eb2cc51622ab89c338360b639081b6d4e4bdab5ac0ac4a4e07342`.

Retained failed setup attempts include the hook's initially late-bound
`__file__`, a GDB 17.1 invocation missing its data directory, and its different
routine breakpoint display before the silent-stop correction. Only the final
cases above count as acceptance. Hosted validation, protected integration and
the full original ABI requirements remain open.

### Earlier matrix checkpoint

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

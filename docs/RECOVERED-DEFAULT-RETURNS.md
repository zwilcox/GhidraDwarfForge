# Recovering default scalar returns

**CONFIRMED locally; full hosted acceptance pending:** when an analyzed
function still has a DEFAULT undefined listing return, the preceding exporter
emits an unspecified type that GDB displays as `void`. SQLite profiling exposed
this independently of the corrected formal/effective aggregate-return bug.
The decompiler may already know a concrete scalar return that appears in the
synthetic C but is absent from the listing signature.

## Policy and implementation

The existing successful source-generation pass captures its HighFunction
prototype return alongside the source model. Only concrete integer, boolean
or floating types are eligible. Both listing signature and return provenance
must be DEFAULT, the saved formal return must be undefined, and custom storage
must be absent. The type extractor rechecks these conditions before using the
evidence. Addresses use the same normalized ELF coordinates as selected
functions. No second production decompilation pass, program mutation, variable
location or native producer API is introduced.

USER_DEFINED, IMPORTED and ANALYSIS information keeps precedence. Curated
pointer/void and formal aggregate signatures remain intact. Missing, failed,
undefined, pointer, aggregate, typedef and void inference does not add a return
fallback in this bounded implementation. A failed function keeps the existing
symbol-only policy; cancellation still unwinds the decompiler interface.
The pass returns an immutable evidence map.

A diagnostic identifies each accepted return as decompiler-recovered. The
listing signature provenance remains DEFAULT; no inferred return is labeled
an original compiler fact. This is recovery of Ghidra's current inference,
not proof of exact original C types. In the unchanged regression fixture,
Ghidra recovers `ulong` for an optimized unsigned division whose original
compiler return is `unsigned int`. The test deliberately preserves this
64-bit/32-bit discrepancy and checks both independent observations. GDB
correctly observes the ordinary call's value 41 with the recovered type;
this positive observation does not establish equality of all original type
semantics. Analyst curation remains the way to supply a stronger type.

## Local acceptance (2026-10-25)

`recoveredReturnSmoke` passes 645 checks using real ProgramDB instances for
x86-64, AArch64, ARM32 and both MIPS32 byte orders: accepted/rejected scalar
candidates, provenance precedence, address normalization, no invented variable
locations, determinism, cancellation, and immutable saved-database reopen.
The formal-return 312 checks, type-graph smoke and extension build also pass.
Actual packaged Java 21 inventory/type-graph/formal-return/recovered-return
checks pass in `packaged.nkrij2ck`, result SHA-256
`9066746f9e97bf70f69b97b5966a12b4711b6fb4fb38ac2caa96927b3195e66f`.
Source Gradle/headless checks used Java 25 and must not be mislabeled Java 21.

Installed JAR SHA-256
`319d27c32e0c5b2007394cb64d45cb20832070dcaf5335d4b545b3037deae6bd`
passes the actual x86-64 import/export/validator/GDB harness in
`build/test-results/recovered-default-returns/x86_64.zorw21nh` in the
`recovered-default-returns` worktree. Result SHA-256:
`c9139cb3be8f028f42bb5608e2bf9956e011d198eaec1567a0f6025c32c7b511`.
The previous package reports all three tested returns as void. Corrected
and compiler sidecars expose the independently expected types; ordinary calls
return -41, 41 and 1.75. GDB source lookup, next/step and normal exit pass.
Curated pointer/void returns keep their analyst provenance. All seven inherited
frame findings are independently corroborated; strict unexplained errors are
zero and LLVM reports no errors. Repeated corrected sidecar/source bytes match.
Input, installed module, harness and program data are unchanged; only Ghidra's
observed index/journal backup rotations are reported separately.

The real decompiler pass controls attempt each selected function once, inject
one function failure without losing the other source/return results, reject
mutation of the evidence map, and honor cancellation initiated inside the
operation. These controls run separately from normal production export.
They do not substitute for the existing emitted symbol-only failure regression.

Retained development failures are `x86_64.7vzd1rni` (validator-only stderr rule
mistakenly applied to normal Java launcher messages), `x86_64.9sk4sufq`
(incorrect expectation that inference exactly matches original unsigned width),
and `x86_64.b_pssbsg` (GDB lookup tried only global scope, while Forge's full
DWARF function was in static scope). The corrected oracle accepts either full
DWARF scope, never an inherited minimal ELF symbol. A retained-artifact GDB
replay confirmed the lookup fix before the final full harness run. No
production or fixture change was needed for those harness corrections.

## Reproduction and remaining scope

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC \
    ./gradlew recoveredReturnSmoke formalFunctionReturnSmoke typeGraphSmoke buildExtension
DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 src/test/integration/recovered-default-returns-export.py /path/to/installed/ghidra
```

The optional `--previous-ghidra` runs the same saved program through a preceding
package and requires the old void-return observation; it is a negative
comparison, not supported behavior. CI runs the model checks on Linux/Windows
and the installed return regression in the x86-64 lane. The complete existing
five-target matrix remains mandatory. Other inferred return shapes, parameter
recovery, linkage/scopes and changing variable locations remain separate TODOs.

### Retained SQLite replay

**CONFIRMED locally:** one fresh semantic export of the retained 1,539-function
SQLite program passes strict validation (828 independently corroborated frame
findings, zero unexplained errors), LLVM and GDB. Checkpoint/SQLite step/exec
returns have the separately observed signed/unsigned 32-bit inferred types.
The ordinary checkpoint call returns 5150 in GDB and the SQL workload exits
normally. The original executable, preceding artifacts, installed JAR and all
project bytes remain unchanged in this replay. Receipt SHA-256:
`174a02c1fc01daaaaef671d0dcdd5e0c8612313883dffcdcd7470cb91f539a44`,
under `build/recovered-return-review/sqlite-replay`. This is correctness
validation of the discovered gap, not a new benchmark timing or speedup claim.

### Final local candidate

A final source-pass review moves the eligibility check before appending the
successful source record, so a policy exception cannot leave both a successful
and failed source entry for the same function. Normal inferred-return behavior
is unchanged. The rebuilt installed JAR
`f333584802dd22ec91fcb8607035f7fadaf468077d1b631a3543604c73b26d8a`
passes fresh actual Java 21 inventory/type-graph/formal-return/recovered-return
checks in `packaged.m71e2643` (receipt
`68b2261432c987aba47fab45f50c051a9821178bc19c501031804acfe0b93c92`).
Fresh full installed regression `x86_64.632kxk18` passes the same previous,
compiler and Forge GDB behavior, isolation/cancellation, validator,
determinism and preservation checks (receipt
`a50119da1c95e6929164d83d3e2e913028a7b158de12b9d54c401c348960764a`).
The earlier SQLite observation retains its original tested package identity;
it is not relabeled as a run of this final package. Workflow lint, architecture
isolation, Python syntax and the 32-source/13-artifact fixture reproducibility
check pass. Full hosted acceptance remains pending.

# Recovered parameter names and types

**CONFIRMED locally; hosted acceptance pending:** a successful decompiler pass
can recover parameter names and types even when the saved listing has no
parameters. The exporter now retains a bounded subset of that information
without asserting a variable location or changing the saved program.

## Evidence and precedence

Recovery requires a DEFAULT signature with no listing parameters, custom
storage or known variadic signature. The existing source-generation pass reads
the HighFunction prototype once; no additional production decompilation is
introduced. The extractor rechecks eligibility before using that evidence.

The first supported list contains only concrete positive-width integer,
boolean, floating or pointer types, with unique nonblank names. Every parameter
must qualify. Missing parameters, hidden return/this parameters, inferred
variadic signatures, undefined scalar types, aggregates and conflicting names
omit the entire inferred list with a diagnostic. A pointer may retain an
unknown pointee through the existing type graph. A later supported parameter
never moves into an earlier unsupported parameter's position.

USER_DEFINED, IMPORTED and ANALYSIS signatures, existing listing parameters,
custom storage and analyst locals retain precedence. Recovery does not promote
DEFAULT provenance or set `DW_AT_prototyped`. Inferred names and types are
Ghidra's current interpretation, not a claim about original compiler source.

HighFunction storage does not establish a variable lifetime. Each accepted
parameter therefore gets explicit DECOMPILER evidence and an UNKNOWN_LIFETIME
omission in the location model. Its DIE has a type and name, without
`DW_AT_location`, `DW_AT_const_value` or a fabricated artificial-parameter flag.
The export report explains the omission and remains PARTIAL. GDB can display
the signature while reporting the argument as unavailable.

## Local validation (2026-10-25)

`recoveredParameterSmoke` passes 550 checks against real ProgramDB instances
for x86-64, AArch64, ARM32 and both MIPS32 byte orders. It covers ordered lists,
type identity/size, stronger provenance, existing parameters, local-name
conflicts, whole-list rejection, normalized addresses, explicit unavailable
storage, deterministic extraction, cancellation and immutable saved-database
reopen. The existing 645 return, 312 formal-return and type-graph checks pass.

Five focused checks also pass against the installed package on actual Java 21
in `build/recovered-parameter-review/packaged.s_93nen1`, receipt SHA-256
`5a962f9166a2d1b2ae76de33d97aa8a873d2fd62fa93873323acc3657f9ee683`.
The tested JAR SHA-256 is
`5299b00be591544b604068e2464165c91b01eb8ee0a4c97045915f8adc180e89`.
Source Gradle and headless tests use Java 25.0.4.1 locally; those are distinct
from the actual Java 21 packaged checks.

The x86-64 fixture is compiled with independent compiler DWARF, then copied
with debug sections removed while retaining ELF symbol names. Its uncurated
listing has zero parameters. The HighFunction recovers `int`, `int *` and
`double` for three functions. A fourth function has an unresolved scalar plus
a pointer and must retain zero exported parameters. A fifth has an explicit
analyst name/type and the target's default calling convention.

Full installed regression `x86_64.rbr4_s4d` passes in the parameter worktree,
receipt SHA-256
`9428785f690b2391286151365c679dd08be22ea766481488adfa9e57457e3b61`.
The previous package lacks the three parameter lists. The new package exposes
their types but GDB reports `param_1 = <optimized out>`. Compiler DWARF observes
the real argument values; ordinary calls return -41, 41 and 1.75 through both
compiler and Forge symbols. Source lookup, next/step and normal exit pass.
GNU/LLVM validators pass; all eight inherited frame findings are corroborated
against the original, with zero unexplained strict errors.

Repeated sidecar/source bytes match. The executable, installed module, harness
and saved program data remain unchanged; only the two explicitly reported
Ghidra project backup files rotate. Actual decompiler controls attempt each
selected function once, isolate one injected function failure, retain the
other evidence, reject evidence-map mutation and honor in-flight cancellation.

The retained first run `x86_64.3te4wzm_` failed the import/reopen source-equality
assertion because the test's newly curated signature used an unknown calling
convention. Ghidra removed its transient warning after reopening. The fixture
curator now explicitly selects the actual target compiler's default convention;
the source-equality assertion remains intact. No production change was needed.

The final harness additionally verifies the actual installed class origin and
raw PARTIAL report's UNKNOWN_LIFETIME omissions. Fresh full run
`x86_64.vtbi9fog` passes with unchanged production JAR; receipt SHA-256:
`64dbfdfa77fc5af34911164dc21b57db9fdb27db4233d21090e74b2f29469270`. Workflow lint,
architecture isolation and the 33-file/13-artifact reproducibility inventory
also pass locally.

## Reproduction and limits

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.3_PUBLIC \
    ./gradlew recoveredParameterSmoke recoveredReturnSmoke formalFunctionReturnSmoke typeGraphSmoke buildExtension
DWARFDUMP=/path/to/pinned/dwarfdump \
    python3 src/test/integration/recovered-parameter-types-export.py /path/to/installed/ghidra
```

The optional `--previous-ghidra` checks the preceding package against the same
saved program. CI runs the model on Linux and Windows and the installed
compiler/export/GDB regression on x86-64, alongside the mandatory existing
five-target matrix. Local ARM32 model checks do not claim a local ARM32 runtime
test; that compiler is unavailable on the development host.

This does not complete all function-signature or variable-location work.
Partial inferred lists, inferred varargs, implicit parameters, aggregates,
additional type shapes and recovered location/lifetime evidence remain separate
work. Existing proven listing-storage policies are unchanged.

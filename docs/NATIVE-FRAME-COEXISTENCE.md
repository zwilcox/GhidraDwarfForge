# Original records and recovered frames through real native export

**CONFIRMED locally; hosted acceptance unverified:** the native-export harness now
tests original/generated `.debug_frame` coexistence with actual ELF import,
decompilation, native DIE production and staged publication. It does not enable
standard CLI/GUI synthesis or complete #112.

## Positive fixture contract

Both independent assembler families have three functions: a leaf checkpoint,
a recursive function, and an outer startup boundary. The owned input fixture
retains the assembler CIE and the leaf and outer-boundary FDEs, removing only
the recursive FDE. The original code, allocated section geometry/payloads and
program-header table must remain identical. The original frame bytes are encoded
plain, gABI zlib or GNU zlib; output is plain or gABI zlib.

The real collector must recover exactly one recursive-function frame and omit
both original-covered ranges. Every composed artifact must contain one active
`.debug_frame`; the original decoded records must remain its exact prefix.
The original stored section must remain byte-identical at the same file offset,
under its inactive name. Appended FDE CIE references are checked independently
before the generated suffix is decoded and compared with the separately proved
recursive rows. This tests preservation and generated coverage separately.

The runtime oracle requires the complete fixture chain and caller-register
witnesses to match the independent assembler reference. It checks selected DWARF
unwinders at actual relocated instruction addresses. The inherited-only control
has no generated recursive CFI and must select original DWARF only for the leaf
within the inspected call group. Disabling DWARF must remove that selection too.
These controls do not assume that every fallback unwinder necessarily fails.

The existing real-export controls remain mandatory: deterministic reruns at each
database base, original-image CFI equivalence after rebasing, staged cancellation
and exception preservation, retry, unchanged inputs, independent GNU/LLVM/strict
validation, and separate GDB source lookup/next/step sessions. The positive matrix
covers both x86-64 and AArch64, ordinary and shrink-wrapped frames, executables,
PIE and loaded shared libraries, and all three original encodings.

All thirty-six positive cases pass: 324 successful exports, 72 cancellation or
exception controls, 144 GNU/LLVM/pinned-strict sidecars and 324 GDB sessions.
Four no-original-CFI shared-library regressions also pass across both targets
and fixture families (36 exports, eight failure controls, sixteen sidecars and
36 GDB sessions). The inherited-unavailable control adds one real export and
two independently compared debugger sessions. Workflow lint, Python syntax,
architecture neutrality and diff checks pass. Production Java/native code and
the previously tested installed package are unchanged; no extension rebuild was
needed. Commands, raw outcomes and hashes are in
`docs/evidence/native-frame-coexistence.json`.

## Inherited unavailable-register control

The independent assembler leaf deliberately marks several registers unavailable,
including AArch64 x29. Removing the explicit outer-boundary record as well as
the recursive record exposes a real consumer limitation. After generating the
recursive records, GDB may still need x29 to speculate beyond the proved group.
It cannot recover a value that the original leaf declared unavailable.

An independent assembler-only artifact with the same nonterminal coverage stops
at exactly the same four frames, PCs and x19 witnesses as Forge, with
`Register 29 was not saved`. `unwind-incomplete-original.py` preserves this
negative case and compares the actual GDB observations. Both binaries must exit
normally. The shortened chain is explicitly **not** full-chain acceptance.
No original record is rewritten and no generated rule invents the missing value.
The assembler-only controls have no compilation units, so their strict summaries
use the checker's existing original-input mode and explicit frame printing.
The exported artifact still must pass the ordinary nonzero-compilation-unit
strict contract. No checker policy was changed.

The full-chain positive fixture therefore retains the assembler's explicit
outer boundary. This is part of its input contract, not a generated fallback or
a claim that arbitrary incomplete original metadata can provide complete stacks.
The earlier missing-boundary run and independent reproduction remain archived.
The archive also retains initial harness failures: an expected-frame filename
collision, a shadowed prefix variable and applying the generated-output checker
contract to a compilation-unit-free assembler input. None is counted as passed.

The shared-library oracle also previously issued an unbounded `bt` even though
its frame/PC comparison intentionally ends at the unsupported fixture startup.
The command now uses the same captured frame count. Errors are not suppressed;
every positive case still requires the complete expected fixture chain, witnesses,
instruction trace and finish/return behavior. This does not establish unwinding
from arbitrary shared-library frames through their host callers.

## Reproduction and remaining work

After installing the tested extension and generating the independent recovery
results, run:

```bash
python3 src/test/integration/unwind-export.py "$GHIDRA_INSTALL_DIR" \
    build/test-results/unwind-frame-recovery/aarch64 \
    build/test-results/native-coexistence/plain/unwind-frame-recovery/aarch64 \
    --target aarch64 --original-encoding plain --dwarfdump "$DWARFDUMP"
python3 src/test/integration/unwind-incomplete-original.py "$GHIDRA_INSTALL_DIR" \
    build/test-results/unwind-frame-recovery/aarch64 \
    build/test-results/native-inherited-unavailable/aarch64 --dwarfdump "$DWARFDUMP"
```

Repeat the positive harness for both targets/families and `gabi`/`gnu` original
encodings. Local isolated installs may specify both native-library paths.
CI includes these controls; hosted execution is **PRESENT, UNVERIFIED**.

User-facing synthesis/provenance, the unchanged global-writing compiler-C
storage policy, broader original-metadata combinations and hosted acceptance
remain open. Existing strict storage-alias refusals remain unchanged. PR166
integration retains priority, followed by full #112, #110 and #109.

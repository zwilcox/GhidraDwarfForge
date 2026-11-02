# GNU vector validation-only correction

**CONFIRMED locally; hosted acceptance pending.** This unblocks independent
compiler-reference validation for the original #71 i386 vector/ABI requirement.
It does not complete #71 or any of #68–#70.

The pinned libdwarf 2.3.2 standalone checker recognizes `DW_AT_GNU_vector`,
but its allowed form-class list is empty. GCC 13.3.0 emits the array attribute
using `add_AT_flag`; the exact primary source and patch contract are linked in
[`support/validation/README.md`](../support/validation/README.md#gnu-vector-flag-form-class).
The correction adds one extension-table row and its generator source entry.
It accepts the flag class only. Shipped consumer/producer sources, register maps
and Ghidra production code are unchanged.

The build helper pins the patch, records it in build metadata and corresponding
source, and includes it in the bundle manifest. The evidence profile now requires
all eight patches. CI runs the new independent metadata harness and retains its
logs, while every existing checker category remains enabled.

The final local bundle is `build/i386-vector-validator/validator-final` in the
`i386-vector-validator` worktree. Its executable SHA-256 is
`d984bd10cb9899b4c8773f92c686bcd27aeb290b07b14e516dc0a5ac2fea13c9`.
The downloaded GCC 13.3.0 source SHA-256 is
`fc1f2c61443c7bbb44ec5bdf75cc12c24287c56bbced005f3118f81a06e8f9be`.

| Check | Result |
| --- | --- |
| GNU vector metadata, DWARF4/5, ELF32/64 LE/BE | 16 corrected positives, 48 corrected rejections |
| Previous checker comparison | 16 false rejections reproduced; 48 invalid fixtures rejected |
| GNU readelf and LLVM | All 16 positive fixtures accepted |
| Existing subroutine conventions | 32 cases pass |
| Existing GNU location views | 24 cases pass |
| Existing ELF address bounds | 56 cases pass |
| Frame terminators and malformed prefixes | PASS |
| Relocated configuration | PASS |
| Evidence capture/validation | 97 controls pass |
| Strict-checker parser and inherited-frame controls | PASS |
| Workflow lint, Python compile, shell syntax, diff checks | PASS |

Exact result/log hashes are in `build/i386-vector-validator/validation.json`,
SHA-256 `0d3ab174caaa148fb38d7623234a78863a1ee5abca9cc0314b3cff2848a439aa`.
The first test attempt is retained: its diagnostic-substring assertion omitted
one word, while the actual positive/old-reader results already matched the
contract. The corrected full test and final-bundle rerun both pass 128 observations.
No test failure is counted as successful acceptance.

Separately, the uncommitted i386 ABI matrix passes eleven-function non-PIE,
sectionless, PIE and rebased-PIE runtime comparisons with this correction.
Those exporter results require their own failure/cancellation controls, CI,
source review and package evidence before integration. They are not validator
unit tests and do not establish broad vector or additional-convention support.
Normal protected integration and a fresh hosted gate remain mandatory.

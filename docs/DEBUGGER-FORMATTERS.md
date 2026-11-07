# Optional debugger formatters (#111)

Explicit selections produce a generation-bound Python companion with independent
GDB and LLDB adapters. Default exports remain unchanged. The acceptance evidence
below describes the tested profiles; [PR188](https://github.com/zwilcox/GhidraDwarfForge/pull/188)
tracks protected integration and the required final-revision checks.

An analyst selects `flags` only for an enum they have identified as a bitmask,
or `structure` for an aggregate. Names do not imply either policy. Selection uses
canonical keys from the export coverage report, not a global type-name regex:

```json
{"schema":1,"types":[{"key":"uid:example","mode":"flags"}]}
```

The `--formatters=<selection.json>` option emits `forge_formatters_<hash>.py`
in the same recoverable publication transaction as the ELF and synthetic source.
The filename hash is SHA-256 of the sidecar basename's UTF-8 bytes; the export
prints the complete companion path. This Python-compatible basename also works
when the ELF filename contains dots, spaces, quotes or Unicode: LLDB 18 rejects
extra dots in an imported script's module name.
An enabled export adds explicitly named synthetic typedef witnesses referencing the
selected canonical DIEs and any same-named candidates. They do not replace actual
program types, variable locations, or source mappings. The companion records the
original and sidecar hashes, selections and enum bit patterns as encoded JSON.
Only the fixed packaged runtime becomes executable Python. No analyst expression
is evaluated, and no debugger command is assembled from analyst names.
The helpers do not use `DW_AT_artificial`: the pinned strict checker correctly
rejects that attribute on `DW_TAG_typedef`, even though LLVM accepts it. The
reserved `__forge_formatter_` name and manifest record their synthetic origin.

GDB's type equality is insufficient on its own: a compiler fixture with two
separate CUs and identical `struct Same` definitions compares equal even through
distinct typedefs. Consumers must check the exact symbol module and refuse a
selection if its type is indistinguishable from a different same-named canonical
type. Refusal leaves normal debugger display available. Distinct layouts and
distinct modules require separate positive/negative runtime tests.

Flags retain raw signed/unsigned values, width, aliases, zero names and unknown
bits. Aggregate summaries retain native child access, bound summary depth/node
counts and do not follow pointers or infer container layouts. Explicit metadata
is presentation intent, not proof that arbitrary target memory is safe to read.
MMIO access policies remain #118; these formatters do not traverse device memory
through pointers or establish read-clear/access-width guarantees.

## Loading and disabling

Export the saved Ghidra program using the normal headless wrapper plus
`--formatters=/path/to/selection.json` (PowerShell: `-Formatters <path>`). Find the
canonical keys in the JSON export report's `coverage.typeNodes` array. A normal
export with formatters disabled supplies these keys. For example, list eligible
emitted enums and aggregates from a saved report:

```bash
jq '.coverage.typeNodes[] | select(.emitted == "YES" and
    (.definitionKind == "EnumType" or .definitionKind == "AggregateType")) |
    {key, name, definitionKind, byteSize}' export.report.json
```

Copy the chosen node's `key` into the selection JSON. Use `flags` for an enum
only when you intend bitmask interpretation, or `structure` for an aggregate.
Names alone are insufficient to identify a type. A missing key or an incompatible
mode is a failed export; the previous artifact generation is preserved.

Load the original executable and its matching sidecar before loading formatters:

```gdb
file /path/to/original
set auto-solib-add off
symbol-file /path/to/original.dbg
source /path/to/forge_formatters_<hash>.py
forge-formatters list
forge-formatters unload
```

Use the exact path printed by the exporter. GDB's `source` command takes the
remaining filename literally, including spaces; do not wrap that path in quote
characters. Its `file` and `symbol-file` commands use GDB's usual path quoting.

```text
target create /path/to/original
target symbols add --shlib /path/to/original /path/to/original.dbg
command script import /path/to/forge_formatters_<hash>.py
forge-formatters list
forge-formatters unload
```

LLDB paths containing spaces need normal LLDB command quoting. Reimporting a
companion replaces its own registration. `forge-formatters unload` removes all
Forge formatter registrations in the current debugger; it leaves other providers
and native type/field inspection intact. Summaries do not supply synthetic LLDB
children: expand the real fields as usual. GDB exposes each real aggregate field
through its child interface. Summary truncation never removes those fields.

The original and sidecar bytes must match the hashes captured at export. A
changed artifact disables formatting and is rejected on reload. LLDB summaries
are explicitly uncached so a stopped process cannot keep displaying an old
summary after a file change. Exporting again with formatters disabled preserves
the normal output pair and does not delete an earlier Python companion; that
earlier companion will reject a different sidecar generation.

The formatter companion can move with its matching original ELF and sidecar.
Keep their filenames and place all three together. At the original export
location it retains the recorded input path, allowing `--output` in another
directory. After relocation it binds only the co-located original and sidecar;
both must still match the recorded hashes. Missing files or different bytes are
rejected even if the old export remains available elsewhere. This also permits
a Windows-produced companion to be consumed by Linux GDB/LLDB. Source-file
search paths and the separate `.gdb.py` loading companion retain their own
documented contracts; this does not rewrite DWARF or an executable. To list the
synthetic source in GDB after moving it, also copy `<sidecar>.c` and run
`directory /new/bundle/directory` before starting the program. The transported
tests verify source listing in both GDB CLI and MI, including Windows paths
recorded in DWARF consumed on Linux.

## Acceptance evidence

**CONFIRMED:** the formatter stages in [run 42390876041](https://github.com/zwilcox/GhidraDwarfForge/actions/runs/42390876041)
at `ef876bee49e2f1165626e9766b33ea4b5bd9b668` pass production exports and GDB
CLI/MI for x86-64, AArch64, ARM32 hard-float, MIPS32 big-endian and MIPS32
little-endian. Each target tests non-PIE with plain DWARF and PIE with zlib
compression. LLDB 18.1.3 summaries and native children pass separately on
x86-64 and AArch64; this does not claim LLDB support for the other profiles.
Two relocated x86-64 generations also pass GDB/LLDB controls with byte-identical
companions and ELFs. The [Linux evidence record](evidence/formatter-linux-acceptance.json)
binds reviewed raw transcripts, validator reports and artifacts to the actual
release package. These formatter-stage results do not establish a passing
whole-run gate or native Windows formatter acceptance.

The tests use a fully stripped input, curate and save its Ghidra model, and then
invoke the packaged exporter on that saved program. Compiler reference DWARF
is a separate oracle. The harness retains commands, full debugger transcripts,
strict-validator reports and artifact hashes. Early `formatter-evidence-*`
artifacts contain PAX archives so quoted and Unicode filenames survive upload.

| Original #111 requirement | Implementation and behavioral evidence |
| --- | --- |
| Analyst metadata, canonical identity, same-named types and stale sidecars | `FormatterSelection` and `FormatterPlan` bind explicit canonical keys to typedef witnesses. `formatter_checks.py` tests distinct same-named layouts, refuses indistinguishable canonical peers and foreign modules, and changes artifact bytes to prove stale summaries stop and reload fails. |
| Complete flags semantics and raw values | Real GDB/LLDB values cover 8/16/32/64-bit signed and unsigned enums, zero, aliases, composites, high bits and unknown bits. Summaries include decimal and full-width hexadecimal raw values. |
| Bounded nested/recursive structures and native fields | `formatter_checks.py` checks recursive and null pointers, unreadable memory and an explicitly unlocated variable. GDB CLI/MI and LLDB independently retain all five node fields and the array element beyond summary truncation. The summaries never dereference pointers. |
| Data-only analyst text, module scope, load/unload | Hostile labels include quotes, a backslash, newline, Unicode, escape and Python-looking text. Actual debugger assertions check escaped display, foreign-module refusal, repeat registration and unload. The manifest is JSON data; only the packaged runtime is executable. |
| Separate GDB CLI/MI and LLDB behavior, including endianness | `formatter-export.py` runs all five GDB profiles and both LLDB profiles. MIPS big-endian and the little-endian profiles must display bitfields `a=5`, `b=17`; separate CLI/MI child and LLDB summary/child assertions inspect the actual target values. |
| Default preservation, determinism, failure/cancellation and original preservation | `formatter-export.py` compares default-before/default-after and repeated enabled artifact hashes, retains original/selection hashes, rejects missing keys and wrong modes, and checks preparation/render cancellation followed by retry. `CompanionArtifactPublisher` smoke checks exercise rollback/cancellation with four/five outputs. `formatter-portable.py` validates relocated copies and refuses missing/mismatched originals and sidecars. |

The known QEMU ARM vDSO string-table warning is accepted only when the independent
compiler-reference session reports the same warning; all other warnings fail.
Some fixtures retain compiler-generated `.eh_frame` diagnostics from the original
ELF. The strict checker accepts those only when the original and sidecar frame
bytes, section hash and diagnostic text match; unexplained diagnostics fail.
The selected formatter names remain separate from Ghidra's recovered type facts.

**CONFIRMED native Windows producer:** the same run's `windows-host` job passes
non-PIE and PIE five-companion generation, default/enabled determinism,
cancellation/retry and invalid-selection checks. Raw review verifies both ELF
identities, exact packaged runtime/wrapper hashes, original-input hashes and
GNU/LLVM output. These are native Windows exports, not Linux PowerShell tests.

**CONFIRMED corrected local consumers:** the unchanged Windows artifacts pass
Linux GDB CLI/MI, LLDB summaries/native children, strict libdwarf validation and
missing/mismatched-file controls. The initial hosted consumer run failed because
GDB could not find the source recorded under the Windows build directory, even
though formatter assertions passed. The harness now supplies the transported
source directory and requires actual source listing; it retains the warning
check and never rewrites the artifacts. See
[Windows production and consumer evidence](evidence/formatter-windows-acceptance.json).

This evidence checkpoint does not claim a passing whole-run gate. The corrected
hosted consumer and complete final-revision `required-validation` check must pass
before protected integration and closure of #111. Use PR188's checks for that
integration result. #187 remains last in the queue.

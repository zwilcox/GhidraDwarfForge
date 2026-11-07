# Optional debugger formatters (#111)

**PRESENT, UNVERIFIED as a complete feature:** explicit selections produce a generation-bound Python
companion with independent GDB and LLDB adapters. Default exports remain unchanged.
Implementation and end-to-end acceptance are in progress; this is not a support claim.

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
canonical keys in the JSON export report's `coverage.types` array. Names alone
are insufficient to identify a type. A missing key or an incompatible mode is a
failed export; the previous artifact generation is preserved.

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
documented contracts; this does not rewrite DWARF or an executable.

## Local validation checkpoint

**CONFIRMED:** local production fixtures exercise GDB CLI/MI on x86-64,
AArch64 and MIPS32, plus LLDB 18.1.3 on x86-64/AArch64. The expanded x86-64 and
AArch64 PIE/zlib cases pass structural checks, real debugger summaries/children,
same-named canonical-type controls, escaped analyst text, stale generation
refusal, repeat registration, formatter-stage cancellation and retry. This is
not the final five-target/native-Windows gate. The harness retains commands,
full debugger transcripts, strict-validator reports and artifact hashes.

The known QEMU ARM vDSO string-table warning is accepted only when the independent
compiler-reference session reports the same warning; all other warnings fail.
The selected formatter names remain separate from Ghidra's recovered type facts.

Acceptance remains all six original #111 requirements: selection/identity and
stale bindings; full flag semantics; bounded structures and unavailable values;
data-only text and module-scoped load/unload; real GDB CLI/MI plus LLDB children
and endian controls; deterministic/default-preserving publication and cancellation.
The current GDB/LLDB profile, production exporter, native Windows packaging and
required cross-target gate remain mandatory. #187 remains last in the queue.

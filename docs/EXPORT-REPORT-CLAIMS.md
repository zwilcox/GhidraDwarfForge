# Read-only export report claims

**CONFIRMED:** PR #33 head `67785a4`, exact hosted run `40094712284`, passes
all twelve jobs. Independent package, all-five-target reader artifact and both
GUI reviews are clear, including fifteen native Windows focused checks. Normal
merge `464caf7` preserves the tested tree. See exact evidence in `VALIDATION.md`.

The result contains reported schema/status, target text, artifact path/hash
strings, counts, native version and validation status. It is an immutable set
of claims from the supplied report. It does not open the named executable,
sidecar or source, recompute their hashes, validate ELF/DWARF, establish identity,
or authorize debuglink attachment. `NOT_RUN` remains a reported validation
status; successful parsing is not an independent validator result. Ordinary
export and its report writer remain unchanged.

Artifact paths are opaque strings from the exporting host. Preserve their
spelling, Unicode, relative components and uppercase/lowercase hash text. A
Windows path read on Linux does not become a Linux `Path`. The reader opens
only the supplied report path using actual filesystem semantics, without
lexically normalizing it first. Reading the report is not a stable snapshot.

## Supported shape

Accept the current schema version 1 with exact known fields and types, in any
object-field order. Reject duplicate decoded keys, unknown/missing fields,
numeric coercions, invalid nullability, trailing input and unsupported versions.
Completed `SUCCESS`/`PARTIAL` reports require target, artifact and count objects,
a nonblank reported native version, and no failure. Each of the five diagnostic
inventory counts must match its array; `SUCCESS` requires all five inventories
empty, while `PARTIAL` requires at least one entry. The lightweight `read()`
methods validate inventories incrementally and discard them rather than retaining
them in the returned claims.

Validate `CANCELLED`/`FATAL` report shape before rejecting it explicitly as having
no completed artifact claims. An arbitrary parser error must not be converted
to a successful empty report. There is no inference that exported functions,
signatures, decompilations or variable locations form stronger count equalities
than the current writer actually establishes.

Historical version-1 reports lack `functionStaticVariables`; that field was
added without a schema increment. This reader deliberately accepts only the
documented current shape and rejects that historical shape explicitly. It does
not supply a guessed zero. Even field presence does not establish which exporter
revision produced the report or which historical static-count semantics were
used. The returned number is only the reported count. A future schema-evolution
policy is separate work.

## Strict JSON and resource limits

Use Ghidra 12.0.3's provided Gson 2.9.0, without bundling another copy. Its
`JsonReader.setLenient(false)` alone accepts several nonstandard string/literal
forms and does not bound token allocation. A small schema-specific lexical
reader checks UTF-8, strings/escapes/surrogates and this schema's integer/null
alphabet before Gson handles object/array grammar and string decoding. The
schema visitor checks exact token types and key sets instead of coercing values
or skipping unknown objects.

Supported-reader bounds are 64 MiB of report bytes, 65,536 UTF-16 units per
decoded string, nesting depth eight, 1,000,000 visited values and 250,000 entries
per array. These are explicit reader limits, not limits already imposed by the
writer. Bound strings before Gson can grow an unbounded token. Reject malformed
UTF-8, a leading BOM, raw string controls, invalid escapes and unpaired
surrogates. Legal escaped controls and supplementary characters remain valid.

Cancellation is checked before opening, around bounded I/O, during traversal
and after EOF. The reader owns and closes its stream on success, failure and
cancellation, preserving primary/suppressed failures. Cancellation cannot
interrupt a filesystem operation already blocked in the operating system.

## Opt-in diagnostic inventories

**CONFIRMED locally; full hosted gate pending:** `readDetailed()` returns
`Detailed(claims, inventories)` from the same strict parse. The five immutable
lists retain failed functions, skipped functions, omitted locations, unsupported
constructs and general diagnostics. Preserve their order and decoded text,
including unknown reasons, empty general diagnostics and Unicode. Canonical
hexadecimal addresses round-trip through the existing immutable report records.
Neither counts nor `PARTIAL` classify an entry's severity or decide whether an
artifact is useful. `NOT_RUN` remains unchanged.

Detailed reads additionally limit the combined inventories to 16,384 entries and
1,048,576 UTF-16 units across their retained string fields. These are separate
retention bounds; numeric addresses are not retained strings. Check before adding
each completed entry and reject overflow explicitly, without truncation. The
existing input, per-string, nesting, value and array limits also apply. Lightweight
reads keep their current limits and discard behavior.

No detailed result is returned before complete EOF, cardinality and status
validation and successful stream closure. The result constructors defensively
copy the lists and require consistency with the associated claims. A detailed
read adds neither report authentication nor an artifact-validation result.

Source `1d80348` passes 432 focused checks on actual Java 21 with a 64 MiB heap,
including both default retention caps reached together and independent over-cap
rejections. Existing lightweight reader/binder checks still pass. The installed
connected workflow preserves all five inventories for nine retained real reports
across x86-64, AArch64 and MIPS32 big-endian, including unknown/Unicode diagnostics
in controlled reports. This local replay remains retained-export evidence. PR #40 head `13e706e5`
subsequently passes all twelve jobs in `40119714272`, all five fresh installed
target artifact reviews, both GUI hosts and 22 native Windows checks. Windows
observes all 432 detailed assertions and the combined retention boundary.
Normal merge `25845418` preserves the tested tree.

## Validation

Focused tests use real writer-generated examples for all four statuses and
exercise each field's type/nullability, all object key sets, five cardinalities,
historical shape, bounds, Unicode and stream/cancellation behavior. All 429
malformed controls pass locally, including exact/over default resource bounds
under a 64 MiB heap. Four focused checks pass locally on actual Java 21; the
hosted Linux and native Windows checks also pass.

The installed-JAR oracle compares returned claims with independently parsed
real exporter reports. It checks both dependency origins, actual Java 21, a
64 MiB heap, exact
path/hash/count text, repeated reads and unchanged report/artifact bytes/mtimes.
Opaque foreign/missing/FIFO paths must parse without any access to the named
artifacts. Malformed and terminal controls must return no completed claims.
Run this oracle beside the other read-only checks directly after primary
exports. Retain its consumed transcripts, extracted JSON and fixture byte
copies in its own result directory. Before/after preservation assertions apply
to this invocation; later regression steps may deliberately reuse the original
fixture or log paths. Their reuse must not replace the earlier evidence.
Explicit use of retained reports is recorded separately from fresh exporter
execution. The full exporter regression pipeline remains required for merge;
this parser does not introduce new GDB behavior or an attachment command.

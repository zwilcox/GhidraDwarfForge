# Curated external function declarations

**PRESENT, UNVERIFIED in hosted CI:** Forge can retain curated external
signatures as addressless `DW_TAG_subprogram` declarations. Local acceptance is
recorded in `VALIDATION.md`; this does not complete linkage, thunk/alias,
class, namespace or external-code debugging support.

The ordinary function iterator excludes external functions. Extraction now
uses the separate external iterator for declarations with a non-default
signature source. Imported or analyst-chosen names alone are not sufficient:
a `DEFAULT` prototype stays omitted. Return and parameter types are the formal
Ghidra types, including the corrected distinction between an aggregate return
and its ABI carrier.

Declarations have their own model list and persistent identity key. Their full
Ghidra display names retain library and nested scope identity as flat names;
these are not original-language namespace DIEs. Same-display-name functions
remain distinct through their persistent IDs. External-space placeholders,
possible external-location addresses and memory thunks never become declaration
code addresses or parameter locations.

The producer emits the name, type, declaration/external/prototyped flags,
recognized conventional calling convention, no-return/variadic state and typed
formal parameters. Real auto parameters keep their artificial flag. It emits
no code ranges, entry address, frame base, local variables, parameter locations,
linkage name or fabricated source line for a declaration. Unknown vendor
calling conventions remain absent, as for definitions. The same canonical type
graph validates declaration and definition references.

External functions remain omitted from the current image's definition inventory
and can still make the export report PARTIAL. Existing `functionsExported` and
`functionSignatures` counters count definitions; declaration types are included
in the type graph. No report schema or attachment-receipt contract changes.

## Debugger limitation and acceptance

An independent GCC DWARF 5 executable calling a separate library contains the
correct unlocated declaration, yet GDB ignores it when resolving the imported
function's prototype. It reports an unknown-return-type PLT symbol. Forge does
not assign an invented address to work around this behavior. Declaration
metadata preserves curated knowledge for DWARF consumers; it does not promise
`ptype` of a library function without that library's debug information.

The regression builds a normal x86-64 caller and library, strips the caller,
curates the actual imported signature and an unreferenced variadic/no-return
signature, and retains an unknown-prototype negative. The real exporter is run
twice, with a read-only reopen. The checker compares typed declaration DIEs to
the compiler oracle, rejects all location/address attributes, verifies model and
artifact determinism, and requires structural validators. GDB must retain real
definition lookup, source navigation and successful normal library execution
while ignoring the unlocated declarations in both compiler and Forge artifacts.
Input caller/library files remain unchanged.

The five-language inventory smoke additionally checks duplicate display names,
distinct library/nested identities, default-prototype omission, thunk separation,
unchanged definition/location selection and cancellation. Native-free graph
controls reject duplicate keys and dangling return types. These model tests do
not imply five-architecture runtime acceptance for this new declaration path.

### Initial hosted inventory-oracle failure

**CONFIRMED:** run `40208416888` at `ff9776a` is not accepted. All five
lanes stopped after their first extended-section export because the older
external-inventory checker still required the superseded diagnostic
`declaration/linkage policy is not implemented yet`. The captured x86-64
transcript shows successful production export followed by this exact checker
assertion. The updated assertion requires the new exact diagnostic; external
names, multiplicities, reasons, counts and PARTIAL status checks are unchanged.
Replaying that retained transcript passes; missing and stale diagnostic negative
controls still fail. The exact hosted package/source/manifests and fresh
packaged Java 21 inventory/type-graph/formal-return checks passed independently.
They do not substitute for the corrected full workflow, which remains pending.

# LLDB automatic discovery checkpoint (#110)

**CONFIRMED locally; hosted acceptance pending.** LLDB 18.1.3 discovers the
selected x86-64 and AArch64 exec/PIE/shared sidecars from a configured private
build-ID tree. These tests arrange owned fixture copies; they do not implement
the production installer, provenance, refresh or removal policy requested by
#109. The original executables and source sidecars remain unchanged.

## Fresh-session discovery and behavior

`automatic-discovery-lldb.py` consumes the real scalar floating-point export
fixtures. Each target/layout has six fresh debugger processes: compiler and
Forge symbols, each with an unconfigured root, a mismatched build-ID file and
a correctly configured matching file. None issues `target symbols add` or
`target modules add`.

Before launch the harness checks the module's identity, actual selected symbol
path, compile units and function entry address. Unconfigured/mismatched cases
must have no recovered function or compile unit, and the original must still
exit normally. Matching cases must load precisely the prepared `.build-id`
file, list the source, hit named and address breakpoints, and pass all ten
scalar-value/lifetime observations from the explicit-loading harness. This
includes the clobbered argument becoming unavailable, expected global values
and normal exit. Every original and installed fixture copy is rehashed.

`shared-object-lldb.py --discovery` copies both the stripped executable and its
`$ORIGIN`-relative library into an owned directory. The compiler driver symbols
and selected compiler/Forge library symbols occupy separate matching build-ID
paths. Both are discovered automatically. At the library's actual relocated
addresses, the existing oracle verifies the selected symbol file, recursive
type, arguments, global, register and changing-SP stack values, honest missing
local, source stepping and normal exit. Both targets pass both producers.

The configured search root is a prerequisite, not proof that an arbitrary
installation directory is already searched. Tests disable external lookup and
use fresh LLDB processes to keep system paths and prior process caches from
masking a missing association. The pinned
[default locator](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/lldb/source/Plugins/SymbolLocator/Default/SymbolLocatorDefault.cpp)
searches configured directories for a UUID-derived build-ID path and compares
the candidate module identity. Runtime tests, rather than this source reading,
establish the compatibility claims above.

## Sectionless limitation and working alternative

**CONFIRMED limitation:** both original ELF files retain a build ID in their
program-header notes, independently read by `readelf -n`, and their prepared
compiler/Forge sidecars have that same ID. Nevertheless, LLDB 18.1.3 exposes
no module UUID for either sectionless original. Automatic discovery yields no
compile unit or recovered name; the named breakpoint has zero locations and
zero hits, and the original exits normally. Both producers reproduce this on
both targets. A mismatch or malformed fixture is not accepted as this control.

This is consistent with the pinned
[`ObjectFileELF::GetUUID`](https://github.com/llvm/llvm-project/blob/llvmorg-18.1.3/lldb/source/Plugins/ObjectFile/ELF/ObjectFileELF.cpp#L798):
it returns an invalid UUID if section-header parsing fails for a non-core file.
No newer consumer version is established here.

`sectionless-lldb.py --loading automatic` requires that exact limitation and
writes `CONFIRMED_LLDB_SECTIONLESS_DISCOVERY_LIMITATION`, not a successful
source-debugging status. The normal `--loading module` path separately passes
original code-byte, source-step and exit checks on both targets. Its explicit
module/zero-slide workflow is limited to the tested ET_EXEC inputs; see
[the ELF layout contract](LLDB-ELF-LAYOUTS.md). Neither test rewrites the target
or fabricates missing recovered functions.

## Pipeline and evidence

The floating export driver runs discovery after both exec/PIE fixture roles
exist, retaining mismatched controls in the same target lane. CI also runs
shared discovery and the sectionless limitation check beside their existing
explicit-loading checks. The debugger packages remain pinned to Ubuntu
`1:18.1.3-1ubuntu1`; the AArch64 runtime uses the recorded QEMU 8.2.2 transport.
The scalar cases select Cortex-A53 for the already documented Neon limitation.

The [receipt](evidence/lldb-discovery.json) binds current source, raw logs,
selected symbol paths, original hashes and retained production/validator
artifacts. Local results cover 24 exec/PIE discovery sessions, four shared
sessions, four sectionless automatic-discovery controls and four explicit
sectionless alternative sessions. Discovery of debuglink-only inputs,
production installation/refresh/removal, perf and other consumers remain
outside this checkpoint. #109 must independently validate its own policy and
full requested matrix.

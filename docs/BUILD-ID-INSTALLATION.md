# Install a Forge export by build ID

**Development status:** the Linux command has local end-to-end validation,
and Windows native installation/recovery plus hosted downstream GDB checks pass
at `0f74abd`. The complete five-target gate, final artifact review and protected
integration remain outstanding. See the
[current Windows receipt](evidence/windows-build-id-current-acceptance.json)
and [Linux command receipt](evidence/build-id-command-linux.json).

Installation associates an export with the original ELF's existing build ID.
It leaves the executable unchanged, retains the source and export report, and
publishes a validated sidecar under an explicitly selected debug root. GDB must
be configured to search that root. Ordinary export never installs automatically.

## Linux invocation

Use Java 21 or later, Ghidra 12.0.3 and the installed Forge extension. The initial
Linux host supports Intel LP64 with the selected files and debug root on ext4.
Create the debug root yourself with the access permissions you want.

Save an absolute-path request as UTF-8 JSON:

```json
{
    "schema": "forge-build-id-request-v1",
    "action": "install",
    "root": "/home/me/debug-symbols",
    "files": {
        "original": "/home/me/program",
        "sidecar": "/home/me/program.dbg",
        "source": "/home/me/program.dbg.c",
        "report": "/home/me/export.json"
    },
    "tools": {
        "helper": "/path/to/GhidraDwarfForge/os/linux_x86_64/forge-validator-supervisor",
        "readelf": "/usr/bin/readelf",
        "llvm": "/usr/bin/llvm-dwarfdump",
        "strict": "/path/to/dwarfdump-linux-validation/libexec/dwarfdump",
        "configuration": "/path/to/dwarfdump-linux-validation/share/dwarfdump/dwarfdump.conf"
    }
}
```

Use the completed export's original report, with hashes matching all three
selected files. The strict checker and configuration must be the pinned
libdwarf 2.3.2 validation bundle used by Forge. A report saying validation passed
does not bypass the command's fresh GNU, LLVM and strict checks. Tool paths are
your explicit selections; paths mentioned in an export report are not executed.

Select the saved request, compute its SHA-256, then run:

```bash
request_path=/absolute/request.json
request_sha=$(sha256sum -- "$request_path")
request_sha=${request_sha%% *}
/path/to/GhidraDwarfForge/support/ghidra-dwarf-forge-build-id \
    --ghidra-dir=/path/to/ghidra_12.0.3_PUBLIC \
    --request="$request_path" \
    --request-sha256="$request_sha"
```

The launcher prints one preview JSON object and then one execution result.
`--preview` prints selections without installing or executing validators. No
target-change confirmation or elevation is required by the command. Permission
failures are reported without retrying with greater privilege.

The request is bounded to 1 MiB. Unknown or duplicate fields, unknown actions,
relative paths and mismatching request hashes are errors. After editing a request,
compute its new hash. An installation root cannot contain the host search-path
separator, a line break or leading/trailing whitespace. Spaces and Unicode are
supported by the tested Linux command and its GDB setup.

## GDB setup and source retention

A successful result includes `registration`, `source`, `state` and
`gdbSetupCommand`. Apply that command **before** loading the original in a fresh
GDB session, for example:

```gdb
set debug-file-directory /home/me/debug-symbols
file /home/me/program
break recovered_function
list recovered_function
```

`set debug-file-directory` replaces GDB's current search-path setting. Include
other desired search roots yourself if needed. Installation does not modify
GDB configuration or populate perf's separate cache. Installation-specific
LLDB and offline perf lookup now pass locally for x86-64/AArch64 exec and PIE;
see [consumer setup, cache rules and limitations](BUILD-ID-CONSUMERS.md).
Hosted acceptance remains pending. Separate native x86-64 recordings with
compiler controls confirm that the tested perf sample reports do not recover
Forge function names; offline source lookup does not imply sample-name support.

The installed DWARF points at a retained source generation within the root.
The original export directory can disappear without losing that source. Keep
the root at its installed path. Moving it leaves stale DWARF references and
causes update/recovery to refuse; use the retained exported sidecar, source and
report to install into a fresh root instead. Generations are not pruned.

For section-header-free ELF inputs, installation and source retention do not imply
automatic GDB discovery. Matching compiler controls and Forge tests on GDB 15.1
show this limitation on all five target lanes. The command reports it on install/
update. Explicit loading of the returned `registration` path is validated for
the tested non-PIE ET_EXEC fixtures; relocated images need the appropriate runtime
load bias. See [shared/sectionless acceptance](BUILD-ID-LAYOUTS.md) for the exact
commands, controls and limits.

## Update, removal and recovery

For a new analyst export of the same original, select the new sidecar/source/
report and change the request action to `update`. A different export will not
silently replace an installed one through `install`. An unchanged export is an
idempotent no-op. A build-ID match with different original executable bytes is
refused; equal IDs alone do not establish file identity.

Removal and recovery use the build ID printed by installation:

```json
{
    "schema": "forge-build-id-request-v1",
    "action": "remove",
    "root": "/home/me/debug-symbols",
    "buildId": "<existing-lowercase-build-id>"
}
```

Removal unregisters only the verified managed sidecar and retains old source
generations. To reconcile an interrupted operation, use action `recover` with
the same root and ID. It commits an observed completed publication or aborts an
unpublished preparation. It never guesses ownership or automatically publishes
a cancelled preparation. Keep all state and diagnostics if it refuses.

`--cancel-file=/absolute/empty-file` observes a fresh empty file owned by the
caller. Changing or removing it requests cancellation. `--cancel-on-stdin`
requests cancellation on any input byte or EOF; keep that stream open while
the operation runs. Cancellation is cooperative. Once publication begins, the
transaction finishes synchronization and readback before returning. Exit 130
means cancellation was observed; exit 1 means failure. State records remain
authoritative if a process exits or result output is lost.

## Windows launcher and validation

`support/ghidra-dwarf-forge-build-id.ps1` accepts `-RequestFile`,
`-RequestSha256`, `-GhidraDirectory`, optional `-ExtensionDirectory`,
`-JavaExecutable`, `-CancellationFile` and `-Preview`. It transports request
paths as UTF-8 base64 and never invokes a shell or requests elevation.
The Windows host requires the existing local NTFS/raw-security metadata
contract. `-EnableSecurityPrivilege` explicitly enables an already assigned
token privilege for that host and restores it afterward; it does not obtain
an administrator token.

**CONFIRMED scoped native validation:** host job `128276867134` passes actual
headless and saved-analyst-refresh exports followed by the packaged installer.
Raw review verifies 73 command checks, 14 interrupted lifecycle boundaries,
metadata comparisons for both generations, and 22 protected-input bindings.
Controls cover explicit null-SACL refusal, locking, cancellation, foreign
registrations, junctions, hard links and alternate streams. Native raw metadata
and command observations are not a local replay of Windows filesystem behavior.
Independent review also verifies all 25 retained generations: 1,050 manifest
files, 175 supervised validator executions and 50 strict original/sidecar
reports, with original frame bytes and retained source checked. The latest
combined gate remains required; see the [acceptance map](BUILD-ID-ACCEPTANCE.md).

The earlier DACL-fixture and second-handle lock failures are resolved in this
native run. Their reproductions and corrections remain recorded in the
[SACL fixture receipt](evidence/windows-build-id-sacl-fixture.json) and
[lock audit](evidence/build-id-locking.json). Production admission still rejects
unsupported security metadata and retains whole-file exclusion.

### GNU validator path requirement

The tested Windows setup uses `<MSYS2>/usr/bin/readelf.exe` from the `binutils`
package, alongside MinGW LLVM and the pinned strict checker. The MinGW build of
GNU readelf loses Unicode characters in the selected debug root. Independent
controls compare the same compiler ELF on ASCII, Unicode and 388-character paths,
under both an unset locale and the production supervisor C locale. MSYS2 reports
match exactly and malformed input is rejected; the MinGW Unicode control fails.
The actual supervised installation/recovery workflow also passes with MSYS2.
Arbitrary GNU readelf builds do not establish Unicode/long-path compatibility.
See the [retained path failure and test contract](evidence/windows-build-id-validator-paths.json).

### Transferred artifacts and source lookup

The downstream consumer uses the exact native Windows-installed initial and
curated generations, verifies recorded hashes, reruns GNU/LLVM/pinned-strict
validation, and tests fresh GDB build-ID discovery, addresses, names, types,
arguments and normal exit. Transferred DWARF still records its Windows source
directory, so Linux GDB requires explicit source substitution. Empty/removed
registrations and unmapped source paths are separate negative controls.

The first hosted consumer failed because the new unmapped-source oracle searched
only global symbols. Exact-artifact reproduction resolves the expected file-local
function at the correct address. The corrected test and stale-name controls use
both global and static lookup. Local replay and current hosted consumer job
`128283282420` pass two runtime sessions and four controls; the compressed-GUI
and unwind consumers also pass. This does not claim native Windows execution
of the Linux ELF. The five-target gate and protected integration remain
outstanding. See the [current native artifact and consumer receipt](evidence/windows-build-id-current-acceptance.json).

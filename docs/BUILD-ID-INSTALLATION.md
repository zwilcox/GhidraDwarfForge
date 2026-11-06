# Install a Forge export by build ID

**Development status:** the Linux command has local end-to-end validation.
Windows command code is **PRESENT, UNVERIFIED** for this installer. Full #109
consumer acceptance and protected integration remain outstanding. See the
[transaction checkpoint](BUILD-ID-TRANSACTION.md) and
[Linux command receipt](evidence/build-id-command-linux.json) for the tested scope.

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
Hosted acceptance remains pending, and perf event/report symbolization has not
been established by those offline tests.

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

## Windows launcher status

`support/ghidra-dwarf-forge-build-id.ps1` accepts `-RequestFile`,
`-RequestSha256`, `-GhidraDirectory`, optional `-ExtensionDirectory`,
`-JavaExecutable`, `-CancellationFile` and `-Preview`. It transports request
paths as UTF-8 base64 and never invokes a shell or requests elevation.
The Windows host requires the existing local NTFS/raw-security metadata
contract. `-EnableSecurityPrivilege` explicitly enables an already assigned
token privilege for that host and restores it afterward; it does not obtain
an administrator token. Installer-specific Windows acceptance is still required.

The native Windows CI harness now consumes the existing Windows headless export
and separately saved analyst-refresh export. It exercises the packaged PowerShell
launcher, protected DACL preservation, explicit null-SACL refusal, 14 interrupted lifecycle boundaries,
recovery, locking, cancellation, foreign registrations, junctions, hard links and
alternate-stream refusals. It retains raw commands, results, native metadata
snapshots and independent copies of both installed generations. **PRESENT,
UNVERIFIED:** the native run must pass before these checks establish Windows
installer acceptance. This harness does not claim Windows GDB runtime/discovery;
consumer acceptance is separate.

The first native installer run refused unsupported SACL metadata after the test's
high-level `Get-Acl`/`Set-Acl` DACL setup. The corrected fixture reuses the existing
native DACL-only helper and checks unchanged absent-SACL state; it does not relax
production metadata admission. The corrected fixture now passes its native
DACL/SACL controls; the following installation exposed a separate lock readback
defect. Native acceptance of the lock correction remains pending. See
[the retained failure and correction](evidence/windows-build-id-sacl-fixture.json).

The old whole-file lock implementation had two independently observed defects:
Windows rejected its second-handle byte read, and Linux silently released its
process-scoped lock when that second handle closed. The corrected implementation
uses the actual locking channel for Windows reads and an audited Linux Intel
LP64 open-file-description lock for Linux. Metadata inspection and content
checks retain the original contract. Isolated Linux tests prove that independent
metadata/data reads and same-JVM contenders do not release exclusion; production
transaction and command regressions pass. An early native Windows smoke and the
full native lifecycle/downstream tests are still required. See the
[lock reproduction, ABI audit and validation receipt](evidence/build-id-locking.json).

The downstream Linux job now runs `windows-build-id-gdb.py` on those exact
retained initial and curated installed generations. It verifies their recorded
hashes and Windows host contract, reruns GNU/LLVM/pinned-strict validation, and
requires GDB build-ID discovery, exact function addresses, analyst names/types,
arguments and normal exit. Empty/removed registrations and unmapped Windows
source paths are separate negative controls. Source substitution is explicit:
the transferred DWARF is unchanged and still records its Windows installation
directory. **PRESENT, UNVERIFIED:** this downstream installer harness awaits
actual native Windows artifacts. An independent compiler fixture confirms GDB's
Windows-path substitution behavior with Unicode, spaces, quotes and a dollar
sign; that control is not Windows installer acceptance.

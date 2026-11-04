# Windows attachment authorization

**PRESENT, UNVERIFIED complete public execution:** the PowerShell7 launcher previews the
selected request without native privilege adjustment. `-ConfirmTargetChange`
allows execution; `-Authorize` additionally requests the Windows `runas` verb
for the separate Java helper. With no authorization option it uses its existing
token and does not retry elevation. Preview ignores modification/authorization
options. Ghidra is never relaunched or elevated by this code.

The new launcher requires PowerShell7 for .NET's `ProcessStartInfo.ArgumentList`,
which performs argument escaping without assembling a shell command. The script
uses this API for both ordinary and `UseShellExecute`/`runas` launches. It does not
use `cmd.exe`, PowerShell `-Command`, `Invoke-Expression`, or a command file.
Installation paths containing a semicolon are rejected because Windows Java
classpaths use that separator; selected target/request paths remain literal
arguments. See Microsoft's [ArgumentList contract](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo.argumentlist)
and [RunAs example](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/start-process#example-5-start-powershell-as-an-administrator).

The confirmed modifying invocation also passes the explicit helper option
`--enable-security-privilege`. It enables only SeSecurityPrivilege already
present in the helper's own process token, as needed to inspect/preserve the
strict native security metadata contract. It cannot add a missing privilege.
UAC denial, missing privilege, native inspection failure and restoration failure
are errors, with no readable-only fallback. In particular, TRUE plus
ERROR_NOT_ALL_ASSIGNED from AdjustTokenPrivileges is failure. The scope restores
the original enabled state and verifies readback before closing its owned token
handle, including when helper host creation or an operation fails. Already-enabled
state is preserved. It neither removes privileges nor opens another process.
See [AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges).

The host adapter itself still never enables privileges. The scope is opened only
by the standalone helper after complete request/path admission and explicit
confirmation. A preview with the privilege option remains read-only. If scope
cleanup fails after a committed transaction, the helper reports COMMITTED with
an error/nonzero exit; it does not claim the executable stayed unchanged.

## Native mapping audit

No libdwarf producer binding or pin changes. These Windows APIs were checked
against Microsoft Learn and the installed MinGW-w64 headers. The compile-only
`support/validation/windows-token-layout.c` asserts the Windows x64 scalar,
structure, constant and function-pointer contracts; CI compiles it with its
actual MinGW64 toolchain. The Java adapter also rejects other hosts.

| Native value | JNA representation |
| --- | --- |
| BOOL, DWORD, TOKEN_INFORMATION_CLASS | 32-bit Java int |
| HANDLE, buffer addresses | Pointer; an output HANDLE uses PointerByReference |
| LPCWSTR privilege name | WString; null system selects the local system |
| LUID | 8-byte opaque value in owned Memory |
| LUID_AND_ATTRIBUTES | 12 bytes; attributes at offset8 |
| TOKEN_PRIVILEGES with one entry | 16 bytes; count at0, LUID at4, attributes at12 |

`GetCurrentProcess` returns an unowned pseudo-handle. Only the token obtained
from [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
is closed. Requested rights are TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES (0x28).
[LookupPrivilegeValueW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew)
looks up only the local SeSecurityPrivilege LUID.

[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
first establishes a bounded required size with ERROR_INSUFFICIENT_BUFFER; a
second call must return valid bytes/count within that allocation. The query
rejects a missing or duplicate selected LUID. Every native allocation is scoped.
The layouts follow [TOKEN_PRIVILEGES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)
and [LUID_AND_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-luid_and_attributes).

## Evidence and remaining work

**CONFIRMED scoped real-ELF execution:** run41866768900/job126708313285 passes
independent review of current-permission and explicit RunAs initial commits,
plus rollback. Retained target/backup/pair bytes, native identity/metadata claims,
receipt binding, debuglink CRCs and 105 validator log hashes were checked; see
[the evidence](evidence/windows-attachment-operation-41866768900.json). The runner
already owns the required privilege. This does not establish standard-user UAC
prompt/decline, saved-curation refresh or full Windows GUI/cancellation acceptance.
Those remain in [the completion ledger](DEBUG-LOADING-COMPLETION-PLAN.md).

**CONFIRMED isolated native token scope:** job126079085292 in run41680805435
passes independent review of archive13253386157, all143 packaged production
sources and the retained test/dependency provenance. Actual Windows Java21
confirms precise own-token enable/readback, nested already-enabled preservation,
exceptional restoration, idempotent close and128 measured cycles without handle
growth or diagnostics. See
[evidence](evidence/windows-attachment-privilege-41680805435.json). This proves
the unchanged token-scope implementation, not standard-user UAC interaction,
Windows real-ELF/GUI attachment, the corrected cancellation identity, or the
current-head required gate. Earlier pending-token notes below are historical.

**CONFIRMED locally:** Windows x64 cross-compilation of all ABI assertions;
actual Java21 compilation/helper115 checks and extension build; PowerShell parser
checks; Python AST and workflow lint; release assembly with both launchers.
Cross-compilation and parsing are not native Windows execution.

**Historical hosted coverage definition:** a standalone probe uses an independent
test token reader to check disabled-to-enabled and already-enabled nesting,
restoration after an injected operation failure, idempotent close and128 cycles
without handle growth. The real Windows initial attachment now invokes the
packaged launcher, first checks preview and no-consent refusal, then requests
RunAs and verifies actual durable receipts, saved recovery selections, metadata,
validator logs and ELF bytes. The later GDB consumer still checks automatic
discovery, runtime values and CRC rejection. The runner already owns the required
privilege; this does not prove an interactive standard-user UAC prompt/decline.

ShellExecute/UAC does not redirect the elevated console. The launcher reports its
observed process exit; retained transaction receipts are authoritative if the
console is closed or output is lost. Actual interactive authorization/cancellation
and the full Windows Ghidra GUI journey remain incomplete. Local Linux checks
request no OS authorization. Native Windows claims are restricted to the scoped
hosted artifact reviews above.

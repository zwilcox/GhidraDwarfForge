# Attachment host observations

**CONFIRMED locally:** the Linux inspection probe passes on actual Java
21.0.12.1 with a 64 MiB heap. **PRESENT, UNVERIFIED:** the Windows provisioner
and native inspector have source/static review; native Windows execution is
**NOT_RUN**. This research starts from accepted main `fdebe18` and changes no
production exporter, native binding, default behavior or public option.

The next [ADR-0004](../ADR-0004-DEBUGLINK-ATTACHMENT.md) prerequisite is a
supported host identity/metadata contract before an initial-association
transaction on owned test targets. These probes only inspect new private
fixtures. They do not replace an executable, preserve metadata on a new file,
create a backup/transaction receipt, or prove atomicity or durability.
Commands and the bounded manifest/result protocol are in the
[probe README](../../src/test/integration/attachment-host-observations/README.md).

## Exact local evidence

`build/attachment-host-review/linux.au9qj2nt/result.json` records ten owned
entries, four identity pairs and eight rejected malformed manifests. Independent
native `fstat` distinguishes two handles to one file from an equal-byte distinct
copy, confirms hardlink count two and inspects a symlink without following it.
Real default-ACL inheritance produces mode `0640`, versus `0600` for the same
create mode/umask under the control parent. The inherited ACL is visible natively
while Java's user-attribute map is empty. Six selected byte copies and three
source copies are retained; a separate duplicated-PAIR observation is rejected.

The runtime is Java 21; compilation used `javac 25 --release 21` because the
local Java 21 installation has no compiler. Executable source hashes are:

| Source | SHA-256 |
| --- | --- |
| `HostFacts.java` | `e8b0d1a089863aeb2317a2fbb1d31c9af47cda01a6480ba68f7acddc94940096` |
| `linux-host-observations.py` | `616310b39638911b85203d1b822adbe3faf09498a2c0555a798bf25349987670` |

`build/attachment-host-review/source-acceptance.json` binds this run and the
retained failures. Earlier successful `linux.q4icm83n` and `linux.2o_zhvf2` runs
precede evidence-retention or exact-pair-oracle changes; they are not proof of
the final provisioner bytes. No new ELF/Ghidra/GDB execution is claimed.

The failures remain available:

- `linux.36t7gpyk`: the initially selected Java 21 compiler did not exist.
- `linux.b9de1yz2`: Java 21 DOS metadata inspection blocked on an owned FIFO in
  `LinuxDosFileAttributeView.readAttributes` → `UnixPath.openForAttributeAccess`
  → native `open0`. The direct test child timed out and was killed/reaped; its
  thread dump, compiled class and input evidence remain. The final probe excludes
  known nonregular/nondirectory entries from optional DOS/ACL/user queries.
- `linux.2sijds0y`: the independent oracle initially still expected a user view
  on that now-excluded FIFO; the expectation was corrected explicitly.

## Windows status and limits

The test-only C# inspector uses inspected Windows header contracts, recorded in
`windows-api-contract.json`. Portable PowerShell 7.6.8 on Linux passes syntax,
C# compilation and managed-layout assertions only; no Windows API was invoked.
Evidence is under `build/attachment-host-observations/windows-static/` and
`windows-source-review-corrected.json`. Native identity/link/reparse/ADS/ACL/sharing behavior
still requires the separate native Windows run, with no skipped minimum controls.

The root's retained `windows-static/typed-parameter-control.{ps1,stdout,stderr}`
exposes a failure missed by those early static checks: PowerShell treats typed
parameter `$Java` and local `$java` as the same variable. Assigning the process
result converts it to a string, so `.stdout` fails. Earlier syntax/managed-layout
success did not catch this provisioner error; those checks are not evidence of a
complete native run. The failed control remains separate from corrected-source
evidence and from native Windows or production attachment acceptance.
The corrected provisioner uses `$factsProcess`; an actual portable PowerShell
control executes the three corrected source lines and preserves the typed
parameter and structured stdout/stderr. It passes alongside refreshed static
checks. The corrected PowerShell SHA-256 is
`389da16c9bbff5472201567247f9932952706440b2522ba4416cd9f8ac875237`.

Both probes distinguish path observations from opened-handle identity. Java's
public opened-channel identity remains `UNKNOWN`. Exact bytes and observed
identity/link counts, modes, ACL/xattrs and modification/change times remain
unchanged locally; access times changed and are recorded separately. Successful
[Linux xattr enumeration](https://man7.org/linux/man-pages/man2/listxattr.2.html)
can omit inaccessible names, so metadata-namespace completeness remains unknown.
Windows attribute queries do not prove content/delete access, and `$DATA` stream
enumeration does not cover all security, EA or reparse metadata.

Known-kind checks do not solve concurrent replacement or general blocking
filesystem calls. No immutable snapshot, adversarial race defense or production
cancellation guarantee follows. ADR-0004 still requires native Linux **and**
Windows metadata application/readback, independent retained backups, file and
namespace durability, atomic replacement, conditional recovery and refresh
acceptance before public attachment. Report `PARTIAL`/`NOT_RUN`, source correlation
and unsigned validator-evidence limits are unchanged. P2.8 remains incomplete.

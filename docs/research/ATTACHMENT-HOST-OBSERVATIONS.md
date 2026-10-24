# Attachment host observations

**CONFIRMED within the inspection scope:** Linux and native Windows probes pass
manual run `40129632540`, attempt 1, with independent artifact review. Both use
actual Java 21.0.12.1 and a 64 MiB heap. Research sources `8e9809f` start from
accepted main `fdebe18`; normal merge `9cd3cd9` incorporates accepted main
`0d2cbc5` without changing the tested executable sources. No production exporter,
production native binding, default behavior or public option changes.

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

## Windows source checks and retained failure

The test-only C# inspector uses inspected Windows header contracts, recorded in
`windows-api-contract.json`. Portable PowerShell 7.6.8 on Linux passes syntax,
C# compilation and managed-layout assertions only; no Windows API was invoked.
Evidence is under `build/attachment-host-observations/windows-static/` and
`windows-source-review-corrected.json`. These portable checks precede and are
separate from the native Windows run below; none substitutes for it.

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

## Independent two-host trial acceptance

The separate never-merge trial branch used exact head
`ed5d8bef4d7f7f9940b75d3fada2bea880cc58df` and source commit `8e9809f`.
Manual run `40129632540` has exactly two successful jobs, `linux-observations`
and `windows-observations`. Its temporary `ci.yml` override exists only on the
trial branch. The integration branch retains production CI and adds the same
manual workflow bytes as `attachment-host-observations.yml`.

| Host | Artifact | SHA-256 |
| --- | --- | --- |
| Linux | `12573907987` | `74af52117df8eb9b001171985d917015c1b34212d962b1a692b66dc0b8c0c262` |
| Windows | `12574917382` | `5a5300e0abd8dbdc6fb895d22551e3d2745050cc65d9f85c4cc36e6f0463e84f` |

Linux run `linux.q9ar8ix3` retains 72 regular evidence files, six selected-byte
copies, ten entries, four identity pairs and eight manifest rejections. Independent
review checks all retained file/source hashes, exact runtime outputs and the ACL
inheritance contrast. Six access-time changes are explicitly recorded. The first
audit compared a raw JDK launcher path with its resolved spelling; that failed
audit and correction against the exact job `JAVA_HOME` remain retained.

Native Windows run `run.windows.5c5ab27e2d7f43eeb651f59e40db6b38` retains 38
regular evidence files, twelve entries, six pairs and nine selected-byte copies.
Actual PowerShell is 7.6.7 on Windows Server 2025. Native structures have observed
sizes 52/8/24/600 bytes. Every minimum fixture is created; none is skipped.
The artifact independently proves:

- Hardlinks share an opened 128-bit file identity and have link count two;
  equal-byte copies have distinct identities. Symlinks and junctions expose their
  no-follow reparse tags, and a dangling link is separate from its missing target.
- An alternate `$DATA` stream shares the base file identity but has different
  bytes. Java rejects its colon path while its user-attribute view observes the
  named stream. Identity alone does not identify selected stream content.
- An attribute-only open succeeds while an exclusive sharing lock rejects native
  `GENERIC_READ` with error 32 and rejects Java content reads.
- Explicit deny-WriteData and inherited DACL entries, plus a read-only attribute,
  are observed. Independent raw ACE decoding agrees. All three native snapshots
  agree on the checked metadata, excluding separately observed access time.

All four Windows retained source files are rehashed in their actual checked-out
form. Their only difference from the pinned Git blobs is LF-to-CRLF conversion;
raw checkout hashes are preserved instead of claiming cross-host byte equality.
Launcher before/after records agree, but uploaded evidence does not authenticate
unretained tool binaries or dependencies.

Evidence is retained under `build/attachment-host-trial-audit/run-40129632540/`:
`gui-linux-review.json` SHA-256
`f20a21f99795263710c6638e5c1b732044aa6b3d5f12fea1d5c059a845947526` and
`independent-windows-review.json` SHA-256
`a8f3646d870c49c695cb331dd8d7bfb7007bd4c783861dc2e3c1c6e0bc836590`.
These are independent reviews of recorded execution, not additional host runs.
The strengthened `independent-windows-review-archive-bound.json` also compares
all 38 extracted members with the digest-verified archive. Combined acceptance
`independent-two-host-review.json` has SHA-256
`0cddb5efb802ee1ae49f4fa8708c197d20484b3deb37aacea17d75e383f5af3a` and
binds both host reviews, current executable sources and both workflow scopes.
The root's first source-review directory enumeration included ignored
`__pycache__` and failed before writing its receipt; a corrected review of the
nine committed paths is separately recorded. No executable-source hash failed,
and that audit failure is not reported as a passing command.

## Remaining transaction boundaries

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

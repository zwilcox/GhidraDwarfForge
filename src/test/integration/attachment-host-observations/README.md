# Attachment host observations — research only

These standalone tests inspect new owned fixtures. They do not implement an
attachment operation, approve a target, preserve metadata on a replacement,
test atomic replacement, or establish backup/receipt durability. No production
extension class, native binding, public option or baseline changes.

`HostFacts.java` uses Java 21 public APIs and no additional dependency. It reads
the explicitly selected manifest, queries paths, opens selected regular files
read-only, and writes one JSON document to stdout. It never creates, replaces,
deletes or changes attributes of a selected file. Reads can change access times.
All facts are sequential observations of trusted fixtures, not a snapshot or a
defense against concurrent replacement. Java public channel APIs expose no
opened-channel file identity here; path `fileKey` observations are not substituted.

## Manifest and output

The ASCII manifest starts with `FORGE_HOST_FACTS<TAB>1<LF>`. Subsequent records:

```text
FILE<TAB>id<TAB>base64(UTF-8 absolute path spelling)<TAB>READ|METADATA<LF>
PAIR<TAB>left-id<TAB>right-id<LF>
```

IDs match `[a-z][a-z0-9_-]{0,63}`. A manifest contains at least one and at most
64 unique file IDs and 128 pairs, within 65,536 bytes. Duplicate paths under
different IDs/policies are allowed; unknown pair IDs, invalid UTF-8/base64,
duplicates and malformed records fail before any fixture inspection. Paths are
not normalized. Provider path-construction failures (including a Windows ADS
spelling rejected by Java) become per-file unavailable facts, preserving the
other records. Invalid UTF-8/NUL path text is a manifest error.

Output `schemaVersion: 1`, `scope: INSPECTION_ONLY` contains exact manifest SHA,
host/JDK/provider facts, `files` keyed by ID, and explicit `pairs`. Every query
returns `{status: OBSERVED, value: ...}` or `{status: UNAVAILABLE, exception,
message}`. READ results include two simultaneously opened read-only channels'
SHA/count observations, with `openedChannelIdentity: UNKNOWN_PUBLIC_JAVA_API`.
METADATA results are `NOT_REQUESTED` for content reads. Basic follow/nofollow,
POSIX/unix/DOS/ACL/user views remain separate; absent/null `fileKey` is not equality.
Pair `isSameFile` is another path observation, not an opened-handle assertion.

Content reads are capped at 16 MiB each; attribute values at 64 KiB each/1 MiB
per view/64 names; ACL output at 256 entries. Provider enumeration allocations
precede these research output bounds, so this is not a universal metadata-memory
or bounded-duration contract. The manifest is bounded before parsing. No general
blocking-call or cancellation guarantee is inferred from the test timeout.

Known nonregular/nondirectory entries are excluded from optional DOS/ACL/user
queries. On actual Java 21/Linux, requesting DOS metadata for an owned FIFO
blocked in `LinuxDosFileAttributeView.readAttributes` →
`UnixPath.openForAttributeAccess` → native `open0`; even a metadata operation can
open a data descriptor. Basic/unix/POSIX facts still record those entries. This
precheck does not solve a concurrent path replacement or remote-filesystem stall.

## Linux provisioner and independent oracle

Run in a new owned directory below an existing explicit output parent:

```sh
python3 src/test/integration/attachment-host-observations/linux-host-observations.py \
    --java /path/to/java21/bin/java --javac /path/to/jdk/bin/javac \
    --output-parent build/attachment-host-review
```

The compiler uses `--release 21`; the actual runtime must report Java 21 and a
64 MiB maximum heap. `getfacl`/`setfacl` are explicit research tools, with paths,
versions and hashes retained; they are not product runtime dependencies. The
provisioner never uses an existing caller file as a fixture. Python's independent
native `open`/`fstat`/`lstat` and xattr calls compare two handles to one inode,
an equal-byte distinct copy, hardlinks, no-follow `O_PATH` symlink identity,
dangling links and FIFO metadata. A user xattr and real named default ACL prove
the metadata contrast: identical create mode/umask yields an inherited ACL child
at mode 0640 versus the noninherited control at 0600. The parent user xattr is
not inherited. Java's user view is not a POSIX ACL inventory.

All selected bytes, observed identities/link counts, modification/change times,
modes and observed xattrs/ACLs must remain unchanged. Access times are retained
before/after separately and may change. Successful xattr enumeration can omit
inaccessible names: native and Java lists, including empty lists, never prove
complete security-namespace absence. Visibility stays `UNKNOWN`.

Retained fixture FIFOs and symlinks are evidence objects, not ordinary artifact
files. Any future upload must select regular evidence files explicitly instead
of following links or reading the FIFO. The JSON/native snapshots retain their
facts. Windows provisioner/oracle evidence is separate; local Linux success does
not establish any Windows result.

## Native Windows provisioner

Run from PowerShell 7 on native Windows, with an existing owned workspace parent:

```powershell
& ./src/test/integration/attachment-host-observations/windows-host-observations.ps1 `
    -WorkspaceParent C:\owned\host-observations `
    -Java C:\jdk21\bin\java.exe -Javac C:\jdk21\bin\javac.exe
```

The script creates a unique fixture directory, holds the sharing-lock control
while Java runs, and retains native/Java observations and bounded byte copies.
`NativeWindowsHostFacts.cs` uses read-only, OPEN_EXISTING native calls inspected
against the pinned headers in `windows-api-contract.json`. Source/static checks
alone do not establish native Windows behavior. Unavailable required fixtures
fail the research run; they are not silently skipped. Upload explicit evidence
files, not live junctions/symlinks. See the
[current research record](../../../../docs/research/ATTACHMENT-HOST-OBSERVATIONS.md)
for exact local and independently reviewed native Linux/Windows evidence.

## Primary API basis and limits

- [Java 21 Files](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Files.html)
  delegates to the filesystem provider; path facts do not imply open-handle identity.
- [Linux open](https://man7.org/linux/man-pages/man2/open.2.html) documents
  `O_PATH | O_NOFOLLOW` and descriptor-based inspection of a symlink itself.
- [Linux ACL](https://man7.org/linux/man-pages/man5/acl.5.html) distinguishes
  access/default ACLs and creation inheritance.
- [Linux listxattr](https://man7.org/linux/man-pages/man2/listxattr.2.html)
  permits inaccessible names to be omitted even on success.
- [Python 3.12 os](https://docs.python.org/3.12/library/os.html) supplies the
  independent native calls; no new ABI mapping is introduced.
- [Windows CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
  distinguishes requested rights and sharing; attribute queries can succeed when
  content/delete access is unavailable. Identity query success is not eligibility.
- [Windows FindFirstStreamW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw)
  enumerates `$DATA` streams only, not all security/EA/reparse metadata.

Before any transaction implementation, these observations must support a defined
host metadata envelope, independent backup, file/namespace flush policy, atomic
replacement and conditional recovery tests on both native Linux and Windows.
Unknown facts remain blockers for that future policy. Current ordinary export is
unchanged; no live target has been selected for attachment.


## Manual two-host workflow

The separate `attachment-host-observations.yml` workflow uses explicit Linux and
native Windows runners with actual Java 21. It has only a manual trigger and
read-only repository permission. Its artifact upload selects regular evidence
files; live FIFO, symlink and junction fixture entries are excluded. It does not
replace or relax the production `required-validation` workflow.

```sh
gh workflow run attachment-host-observations.yml --ref <reviewed-ref>
```

Before this workflow exists on the default branch, the identical workflow was
manually dispatched through the registered `ci.yml` path on the separate
`research/attachment-host-trial` branch. That trial branch must never be merged;
only the research sources and this separately named workflow belong in the
integration branch. Exact source/run/artifact acceptance is recorded in
`docs/research/ATTACHMENT-HOST-OBSERVATIONS.md`.

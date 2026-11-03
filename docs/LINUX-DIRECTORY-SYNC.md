# Linux directory identity and flush

**CONFIRMED locally:** `LinuxDirectorySync` supplies native opened-directory
identity, mount/filesystem observations and explicit directory `fsync` for the
Linux Intel LP64 release host. It is not a complete attachment host or a claim
of power-loss testing. Full filesystem admission and storage assumptions must
still be selected and recorded before enabling #72 publicly.

The ABI is checked by `src/test/native/linux-directory-contract.c`: libc
`open`, `statx`, `fstatfs`, `fsync`, `close`; fixed-width scalar types; the
256-byte statx and 120-byte LP64 statfs layouts; field offsets and flags.
Headers were inspected before mapping. No libdwarf producer declaration changes.

The operation opens a directory without following its leaf link, with
O_DIRECTORY/O_NOFOLLOW/O_CLOEXEC/O_NONBLOCK. It retains the native descriptor
while checking device/inode/mount ID and filesystem identity/type/flags/name
bound. The selected path is checked against the opened object before and after
the operation. Missing identity/mount fields, changed selections and native
errors are refusals, with no global-sync or unavailable-field fallback. Free
space, directory timestamps and entry counts are deliberately not stable
identity fields. Ancestor traversal follows the already selected path; this
primitive does not normalize symlink/`..` traversal or claim adversarial race
resistance.

`sync` requires an expected directory observation. It invokes `fsync` on that
same opened descriptor, propagates errors and closes it on success, failure or
cancellation. Cancellation is checked around native calls; it cannot interrupt
a blocked kernel operation. The transaction must finish post-publication flush
and reconciliation even if user cancellation arrives. This primitive does not
select a supported filesystem merely because `fsync` returned success.

[Linux fsync documentation](https://man7.org/linux/man-pages/man2/fsync.2.html)
requires a separate directory flush for namespace persistence in addition to
file data/metadata flushes. [statfs](https://man7.org/linux/man-pages/man2/statfs.2.html)
provides filesystem observations, while
[statx](https://man7.org/linux/man-pages/man2/statx.2.html) provides opened-file
identity/mount fields. Hardware and filesystem guarantees remain part of the
complete host contract, not properties inferred from an identity record.

## Validation

```sh
GHIDRA_INSTALL_DIR=/home/ziggy/ghidra_12.0.3_PUBLIC ./gradlew compileTestJava buildExtension
JAVA=/usr/lib/jvm/java-21-openjdk-amd64/bin/java \
    python3 -B src/test/integration/linux-directory-sync.py \
    --jar build/libs/GhidraDwarfForge.jar \
    --ghidra /home/ziggy/ghidra_12.0.3_PUBLIC \
    --results build/test-results/linux-directory-sync/harness-final
```

The standalone Java 21 test passes 494 assertions on the local `0xef53`
filesystem. An independent compiled C observer uses fstat/fstatfs and mount-ID
observation to compare every emitted field. Cases include Unicode/spaces,
entry changes without identity changes, read-only directory permissions,
wrong-directory and symlink/non-directory rejection, a path replacement while
the descriptor is open, and actual procfs `fsync` failure. The latter changes
no procfs entries. After warmup, 128 success/cancellation/failure cycles show
no native descriptor growth. Raw commands, exact JAR/dependencies/sources and
hashes are retained by the harness. The extension CI runs that harness; hosted
acceptance of the new primitive is **PRESENT, UNVERIFIED** until its new run.

Receipt, backup, target replacement, transaction and operation tests now use
these production identity/flush calls alongside the production native rename.
Actual Java 21 suites pass 101/75/63/525/72 controls, including abrupt process
exit, backup retention, rollback and refresh. A real x86-64 executable replay
passes the live GNU/LLVM/pinned-strict validator and GDB discovery/runtime/CRC
and rollback controls. Evidence is under `build/test-results/linux-directory-sync/`.
These test hosts still use deliberately limited metadata adapters; the results
do not complete Linux/Windows host admission or public attachment controls.

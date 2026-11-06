# Original-frame composition in the matched ELF writer (#112)

**CONFIRMED locally:** `MatchedElfSidecarWriter.writeWithFrames` packages an
explicit frame plan only after checking original unwind coverage and the selected
loader-write profile. The supplied plan's address width and byte order must
match the input ELF. Generated ranges cannot overlap original EH/debug-frame
coverage or runtime relocation writes. Unknown metadata remains a refusal.

The writer obtains the original debug-frame bytes from its own verified source
inventory. Fresh file identity, stored-content and decoded-content hashes bind
that read to the original inspection. Plain, gABI zlib and GNU zlib inputs use
the same bounded decoder. Original decoded records become an exact prefix of
the composed section; generated FDEs refer to the appended CIE's actual offset.

The original stored encoding remains byte-for-byte in the copied ELF prefix,
under an inactive `.forge.stale.debug_frame` or `.forge.stale.zdebug_frame`
section name. One active `.debug_frame` contains the combined records and obeys
the selected output compression policy. Original EH metadata is preserved.
Output uses the existing temporary-file/atomic-publication path; the target is
never modified. An empty generated plan retains ordinary preservation behavior.

This is an explicit writer API, not automatic rule recovery. The ordinary writer
still rejects caller-supplied frame bytes that collide with original debug-frame
metadata. The new API also refuses a plan accompanied by caller-supplied frame
bytes. Its scope is packaging and original-metadata qualification; the caller
must still prove instruction bytes, CFA/register rules and supported ABI/frame
conditions. The production exporter does not yet enable synthesis, and
ADR-0002's acceptance condition remains in force.

## Validation

Twelve cases use original ELF inputs containing a complete, unchanged compiler
CIE/FDE prefix: x86-64 and AArch64, non-PIE and PIE, and three original storage
encodings. Explicit generated plans cover only the other functions. Twenty-four
plain/compressed output sidecars pass GNU, LLVM and pinned strict validation.
Independent inspection verifies both the active decoded bytes and the inactive
original section's exact stored bytes, offsets and flags. Twenty-four native/QEMU
GDB sessions match the independent compiler backtrace/register/finish/stepping
reference. These are packaging tests with explicit plans, not positive acceptance
of recovered compiler-frame evidence.

Each writer run tests cancellation at every observed poll, including decoding,
composition and publication preparation. Cancellation preserves an existing
destination, leaves no staging file, and permits a byte-identical successful
retry. Original-coverage overlaps and ordinary-writer frame collisions reject
without replacing the destination. Plan/raw-byte conflicts, target-layout
mismatches and a non-directory output parent also fail without publication.
Empty plans preserve original frame storage exactly. The twenty-four first
serializations exercise 8,213 cancellation polls; deterministic reruns repeat
those controls. Source, input and output hashes establish
deterministic behavior and unchanged originals. The known AArch64 QEMU VDSO
warning matches the independent compiler control.

The existing four native recovered-frame non-PIE/PIE cases now use this same
writer API for their no-original-CFI targets. Eight sidecars and sixteen GDB
sessions pass with original/rebased plan agreement and GNU/LLVM/strict checks.
Their plans come from the native instruction/callee proof, while their importer
and minimal CU remain test-only; this is not production exporter acceptance.

The initial test compilation tried a package-private ELF path accessor; the test
now receives its own input path. The failed build is retained in the evidence.
See `docs/evidence/qualified-frame-writer.json` for commands, results and archives.
Hosted additions are **PRESENT, UNVERIFIED** until the exact head passes.

**PLANNED:** production recovered-plan orchestration, global-write storage
evidence, the complete compiler/shared/split/shrink-wrap matrix and full export
failure/cancellation acceptance. This does not complete #112, #110 or #109.

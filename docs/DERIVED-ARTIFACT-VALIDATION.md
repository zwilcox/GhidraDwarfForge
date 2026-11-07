# Validation evidence for a source-relocated artifact

**CONFIRMED component contract:** a
relocated sidecar has different bytes from the reported export. Its original
report remains provenance for the export, not a certificate for the new bytes.
`ArtifactValidationBinding` preserves that distinction before the existing
GNU/LLVM/pinned-libdwarf policy executes.

This document records the component checkpoint. Subsequent production Linux
and native Windows installer results, including current hosted consumption of
Windows-installed files, are tracked in the [acceptance map](BUILD-ID-ACCEPTANCE.md).
The complete target gate and protected integration remain pending there.

The original four selected files first pass `AttachmentExportBinding`: report
hash agreement, ELF prefix/allocation/build identity/target agreement and host
identity observations. A derivative additionally requires distinct non-link,
single-link selections, exact source content and the original DWARF basename.
The current source-relocation plan then compares the entire candidate against
its expected bytes through bounded read-only file operations. This includes
unchanged prefixes, header patches, appended payloads and alignment padding.
An otherwise valid sidecar naming a different directory does not pass this proof.
These observations detect ordinary changes; callers still need stable owned
snapshots and must not claim protection from adversarial change-and-restore races.

The combined validator and strict checker use the derived original/sidecar pair
for validation and inherited-frame corroboration. Both export and derived
snapshots are rechecked around validation and evidence publication. Ordinary
export validation retains schema version 2. Derived validation uses version 3,
adds `artifactRelationship: exact-synthetic-source-relocation-v1`, and records
`reportedExportInputs` separately from the actual validated `inputs`.
`exportStatus` and `exportValidationStatus` retain their original meanings; they
are not upgraded when the derived artifact validates. No original report is
edited or regenerated to substitute the new hash.

The [local receipt](evidence/build-id-derived-validation.json) binds the current
JAR and 213 production source files. Twenty retained real artifacts span
exec/PIE, plain/zlib and x86-64, AArch64, ARM32 and both MIPS32 byte orders. Forty
fresh combined-policy runs pass: one original and one derivative per case.
Controls cover 220 refusals and 140 **sampled** cancellation boundaries, including
wrong source directories/basenames, aliases and same-length modifications with
restored timestamps. Independent copies of the exported quartet prove that
opaque report paths are not used to locate files. Original selected bytes stay
unchanged, and old/new evidence schemas keep the hashes and claims distinct.

The probe uses the explicitly test-only Linux metadata adapter already used by
the attachment validator probes. This validates production binding/policy code
and actual external checker processes; it does not establish the installer's
production Linux/Windows metadata, permissions, locking, publication, recovery
or consumer-configuration contract. The fixture archive referenced by the
receipt contains the earlier source-absent GDB/LLDB/perf behavior evidence; this
checkpoint does not claim new producer or debugger runs. The pipeline invokes
this validation after each plain/zlib relocation case.

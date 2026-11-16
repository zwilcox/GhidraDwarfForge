#!/usr/bin/env python3
"""Compile bounded, explicit mutants outside the checkout and require behavioral failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[3]
REPAIR = "ghidradwarfforge/dwarf/Dwarf32InfoRepair.java"
RELOCATE = "ghidradwarfforge/dwarf/SyntheticSourceRelocation.java"
PUBLISH = "ghidradwarfforge/output/CompanionArtifactPublisher.java"
REPAIR_TEST = "ghidradwarfforge.dwarf.Dwarf32InfoRepairBoundarySmoke"
RELOCATE_TEST = "ghidradwarfforge.dwarf.SyntheticSourceRelocationBoundarySmoke"
PUBLISH_TEST = "ghidradwarfforge.output.CompanionPublicationFailureSmoke"
PROTECT = "ghidradwarfforge/GhidraProjectOutputProtection.java"
PROTECT_TEST = "ghidradwarfforge.GhidraProjectOutputProtectionSmoke"
FIRMWARE = "ghidradwarfforge/firmware/FirmwareExportImage.java"
FIRMWARE_TEST = "ghidradwarfforge.firmware.FirmwareImageLifecycleSmoke"
INHERITANCE = "ghidradwarfforge/dwarf/DwarfInheritanceExpression.java"
INHERITANCE_TEST = "ghidradwarfforge.dwarf.DwarfInheritanceExpressionSmoke"
RECORDS = "ghidradwarfforge/output/BuildIdRecords.java"
RECORDS_TEST = "ghidradwarfforge.output.BuildIdRecordsSmoke"
UNWIND_REPORT = "ghidradwarfforge/output/UnwindEvidenceJson.java"
UNWIND_REPORT_TEST = "ghidradwarfforge.output.UnwindEvidenceJsonBoundarySmoke"
MMIO = "ghidradwarfforge/output/MmioSelection.java"
MMIO_TEST = "ghidradwarfforge.output.MmioSelectionBoundarySmoke"
CXX_SELECTION = "ghidradwarfforge/output/CxxSelection.java"
CXX_SELECTION_TEST = "ghidradwarfforge.output.CxxSelectionBoundarySmoke"
PROGRAM_TYPES = "ghidradwarfforge/types/ProgramTypeModel.java"
PROGRAM_TYPES_TEST = "ghidradwarfforge.types.ProgramTypeModelBoundarySmoke"
SECTIONLESS = "ghidradwarfforge/elf/SectionlessDynamicSymbols.java"
SECTIONLESS_TEST = "ghidradwarfforge.elf.SectionlessDynamicSymbolsSmoke"
DYNAMIC = "ghidradwarfforge/elf/DynamicSymbolMirror.java"
DYNAMIC_TEST = "ghidradwarfforge.elf.DynamicSymbolMirrorSmoke"
RECEIPT = "ghidradwarfforge/output/AttachmentReceipt.java"
RECEIPT_TEST = "ghidradwarfforge.output.AttachmentProtocolSmoke"
RECEIPT_STORE = "ghidradwarfforge/output/AttachmentReceiptStore.java"
RECEIPT_STORE_TEST = "ghidradwarfforge.output.AttachmentReceiptStoreSmoke"
OPERATION = "ghidradwarfforge/output/AttachmentOperation.java"
OPERATION_TEST = "ghidradwarfforge.output.AttachmentOperationSmoke"
SOURCE_FILES = "ghidradwarfforge/output/SourceBundleFiles.java"
SOURCE_FILES_TEST = "ghidradwarfforge.output.SourceBundleFilesSmoke"
SOURCE_BUNDLE = "ghidradwarfforge/output/SourceBundle.java"
SOURCE_BUNDLE_TEST = "ghidradwarfforge.output.SourceBundleSmoke"
REPORT_CLAIMS = "ghidradwarfforge/output/CoverageReportClaims.java"
REPORT_CLAIMS_TEST = "ghidradwarfforge.output.CoverageReportClaimsBoundarySmoke"
TYPE_CLAIMS_TEST = "ghidradwarfforge.output.CoverageTypeEvidenceSmoke"
TRANSACTION = "ghidradwarfforge/output/AttachmentTransaction.java"
TRANSACTION_TEST = "ghidradwarfforge.output.AttachmentTransactionSmoke"
MIPS_ALLOCATION = "ghidradwarfforge/targets/MipsWideParameterAllocation.java"
MIPS_ALLOCATION_TEST = "ghidradwarfforge.MipsN32ParameterAllocationSmoke"
STACK_FLOW = "ghidradwarfforge/StackValueFlow.java"
STACK_FLOW_TEST = "ghidradwarfforge.RegisterByteSliceFlowSmoke"
STACK_CARRIER_TEST = "ghidradwarfforge.StackValueFlowSmoke"
VTABLE_BINDINGS = "ghidradwarfforge/GhidraVtableBindings.java"
VTABLE_BINDINGS_TEST = "ghidradwarfforge.VtableBindingEvidenceSmoke"
STATIC_RECOVERY = "ghidradwarfforge/GhidraStaticRecovery.java"
STATIC_RECOVERY_TEST = "ghidradwarfforge.StaticRecoverySmoke"
BOUNDED_SWITCH = "ghidradwarfforge/calls/GhidraBoundedSwitch.java"
BOUNDED_SWITCH_TEST = "ghidradwarfforge.calls.BoundedSwitchProofSmoke"
ARM_MODE_INVENTORY = "ghidradwarfforge/elf/Arm32FunctionAliasSymbols.java"
ARM_MODE_INVENTORY_TEST = "ghidradwarfforge.elf.Arm32FunctionAliasSymbolsSmoke"
CURATED_TYPES = "ghidradwarfforge/GhidraTypeGraph.java"
CURATED_TYPES_TEST = "ghidradwarfforge.FloatingTypeLayoutSmoke"
CALL_MEMORY = "ghidradwarfforge/CallMemoryEffects.java"
CALL_MEMORY_TEST = "ghidradwarfforge.CallMemoryEffectsSmoke"

CXX_PROFILE = "ghidradwarfforge/GhidraCxxProfile.java"
CXX_PROFILE_TEST = "ghidradwarfforge.CxxProfileSmoke"
CALL_VALUE = "ghidradwarfforge/calls/CallValue.java"
CALL_VALUE_TEST = "ghidradwarfforge.calls.CallValueSmoke"
CALL_VALUE_ORACLE = REPO / "src/test/integration/check-call-values.py"
VALIDATOR_STATUS = "ghidradwarfforge/output/ValidatorSupervisor.java"
VALIDATOR_STATUS_TEST = "ghidradwarfforge.output.ValidatorStatusBoundarySmoke"
STRICT_REPORT = "ghidradwarfforge/output/StrictDwarfReport.java"
STRICT_REPORT_TEST = "ghidradwarfforge.output.StrictDwarfReportSmoke"
STRICT_REPORT_MUTANTS = [
    ("strict-report-accepts-duplicate-category", STRICT_REPORT, STRICT_REPORT_TEST,
     "rows.put(row.group(1), counts) == null", "rows.put(row.group(1), counts) == null || true"),
    ("strict-report-accepts-zero-checks", STRICT_REPORT, STRICT_REPORT_TEST,
     "checks > 0 && checks ==", "checks >= 0 && checks =="),
    ("strict-report-accepts-trailing-record", STRICT_REPORT, STRICT_REPORT_TEST,
     "tail.substring(lastEnd).isBlank()", "true"),
    ("strict-report-accepts-duplicate-tag-report", STRICT_REPORT, STRICT_REPORT_TEST,
     'require(tagStart == -1, "duplicate final tag report")',
     'require(true, "duplicate final tag report")'),
]
I386_ALLOCATION = "ghidradwarfforge/targets/I386ParameterAllocation.java"
I386_ALLOCATION_TEST = "ghidradwarfforge.I386ParameterAllocationSmoke"

MERGED_LIFETIME = "ghidradwarfforge/MergedLocalLifetime.java"
MERGED_LIFETIME_TEST = "ghidradwarfforge.MergedLocalLifetimeSmoke"
REGISTER_PROFILE = "ghidradwarfforge/GhidraVariableStorage.java"
REGISTER_PROFILE_TEST = "ghidradwarfforge.RegisterAliasSmoke"
REGISTER_MAP = "ghidradwarfforge/locations/TargetRegisterMap.java"
REGISTER_MAP_TEST = "ghidradwarfforge.locations.VariableStorageSmoke"
RUNTIME_RELOCATIONS = "ghidradwarfforge/elf/ElfRuntimeRelocations.java"
RUNTIME_RELOCATIONS_TEST = "ghidradwarfforge.elf.ElfRuntimeRelocationsSmoke"
ELF_READER = "ghidradwarfforge/elf/ElfImage.java"
ELF_READER_TEST = "ghidradwarfforge.elf.ElfImageReaderSmoke"
ALLOCATIONS = "ghidradwarfforge/elf/MatchedElfAllocations.java"
ALLOCATIONS_TEST = "ghidradwarfforge.elf.MatchedElfAllocationsSmoke"
ALLOCATION_BOUNDARY_MUTANTS = [
    ("allocation-ignores-load-write-permission", ALLOCATIONS, ALLOCATIONS_TEST,
     '((segment.flags & 2) != 0 ? 1 : 0)', '0'),
    ("allocation-invents-load-execute-permission", ALLOCATIONS, ALLOCATIONS_TEST,
     '((segment.flags & 1) != 0 ? 4 : 0)', '4'),
    ("allocation-ignores-replaced-relocation-name", ALLOCATIONS, ALLOCATIONS_TEST,
     '(!relocation || section.name.startsWith(".debug_"))', '!relocation'),
    ("allocation-retains-expired-nonallocated-note", ALLOCATIONS, ALLOCATIONS_TEST,
     'nonallocated--;', ''),
    ("allocation-shrinks-merged-note-coverage", ALLOCATIONS, ALLOCATIONS_TEST,
     'end = Math.max(end, next.getValue());', 'end = Math.min(end, next.getValue());'),
]
ELF_READER_MUTANTS = [
    ("elf-reader-ignores-magic-byte", ELF_READER, ELF_READER_TEST,
     "ident[2] != 'L'", 'false'),
    ("elf-reader-allows-header-overlap", ELF_READER, ELF_READER_TEST,
     'sectionOffset < encodedHeaderSize', 'false'),
    ("elf-reader-allows-dangling-name-index", ELF_READER, ELF_READER_TEST,
     'encodedCount != 0 || encodedNameIndex != 0', 'encodedCount != 0'),
]
RUNTIME_RELOCATION_MUTANTS = [
    ("runtime-dynamic-allows-trailing-byte", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'dynamic.fileSize % size == 0', 'dynamic.fileSize % size <= 1'),
    ("runtime-relocation-ignores-standalone-entry-size", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'require(tags.get(entry) == reader.entrySize(format), "wrong standalone relocation entry size");',
     'require(true, "wrong standalone relocation entry size");'),
    ("runtime-relocation-treats-plt-rel-as-rela", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'format == 7 ? Format.RELA : Format.REL', 'Format.RELA'),
    ("runtime-relocation-discards-empty-general-table", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'tables.add(reader.table(role, format, tags.get(pointer), tags.get(size)));',
     'if (tags.get(size) != 0) tables.add(reader.table(role, format, tags.get(pointer), tags.get(size)));'),
    ("runtime-relocation-fabricates-empty-file-offset", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'long offset = size == 0 ? 0 : locate(address, size);',
     'long offset = size == 0 ? address : locate(address, size);'),
    ("runtime-relocation-ignores-first-overlap-framing", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     '(start - a.offset()) % a.entrySize() == 0', 'true'),
    ("runtime-relocation-ignores-second-overlap-framing", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     '(start - b.offset()) % b.entrySize() == 0', 'true'),
    ("runtime-relocation-accepts-negative-rel-target", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'require(value >= 0, "relocation target exceeds signed address domain");',
     'require(true, "relocation target exceeds signed address domain");'),
    ("runtime-relocation-accepts-negative-relr-target", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'require(value >= 0, "RELR target exceeds signed address domain");',
     'require(true, "RELR target exceeds signed address domain");'),
    ("runtime-relocation-overflows-elf32-bitmap", RUNTIME_RELOCATIONS, RUNTIME_RELOCATIONS_TEST,
     'width == 8 || target <= 0x1_0000_0000L - width', 'true'),
]
REGISTER_MAP_MUTANTS = [
    ("register-slice-overflows-physical-extent", REGISTER_MAP, REGISTER_MAP_TEST,
     '(long) byteOffset * 8 + bitSize', 'byteOffset * 8 + bitSize'),
    ("register-slice-overflows-logical-extent", REGISTER_MAP, REGISTER_MAP_TEST,
     '(long) valueBitOffset + bitSize', 'valueBitOffset + bitSize'),
    ("register-pair-allows-overlap-or-gap", REGISTER_MAP, REGISTER_MAP_TEST,
     'high.baseBitOffset() != low.bitSize()', 'false'),
    ("register-pair-allows-duplicate-child", REGISTER_MAP, REGISTER_MAP_TEST,
     'pieces.get(0).registerName().equals(pieces.get(1).registerName())', 'false'),
    ("register-pair-allows-unmapped-child", REGISTER_MAP, REGISTER_MAP_TEST,
     'pieces.stream().anyMatch(piece -> !sorted.containsKey(piece.registerName()))', 'false'),
    ("register-slice-allows-unmapped-parent", REGISTER_MAP, REGISTER_MAP_TEST,
     '!dwarfNumbers.containsKey(entry.getValue().parent())', 'false'),
    ("register-pair-sorts-away-object-order", REGISTER_MAP, REGISTER_MAP_TEST,
     'pairs.put(entry.getKey(), pieces);', 'pairs.put(entry.getKey(), List.of(low, high));'),
    ("register-pair-retains-caller-list", REGISTER_MAP, REGISTER_MAP_TEST,
     'var pieces = List.copyOf(entry.getValue());', 'var pieces = entry.getValue();'),
]
MIXED_PREFIX_TEST = "ghidradwarfforge.MixedParameterPrefixSmoke"
MIXED_PREFIX_MUTANTS = [
    ("mixed-prefix-admits-foreign-storage", REGISTER_PROFILE, MIXED_PREFIX_TEST,
     "function.getProgram() != program || storage.getProgramArchitecture() != program ||",
     "function.getProgram() != program ||"),
    ("mixed-prefix-admits-detached-parameter", REGISTER_PROFILE, MIXED_PREFIX_TEST,
     "parameter.getFunction() != function ||\n                parameter.getOrdinal() < 0 || function.getParameter(parameter.getOrdinal()) != parameter ||",
     ""),
    ("mixed-prefix-forgets-indirection", REGISTER_PROFILE, MIXED_PREFIX_TEST,
     "storage.isForcedIndirect() || storage.isUnassignedStorage() ||", "storage.isUnassignedStorage() ||"),
    ("mixed-prefix-inverts-stack-depth", REGISTER_PROFILE, MIXED_PREFIX_TEST,
     "Math.subtractExact(stack.byteOffset(), (long) interval.depth()))\n                        : piece.storage();",
     "Math.addExact(stack.byteOffset(), (long) interval.depth()))\n                        : piece.storage();"),
]
FRAME_REREAD = "ghidradwarfforge/elf/OriginalFrameSources.java"
FRAME_REREAD_TEST = "ghidradwarfforge.elf.OriginalFrameSourcesSmoke"
BACKUP_READBACK = "ghidradwarfforge/output/AttachmentFileStore.java"
BACKUP_READBACK_TEST = "ghidradwarfforge.output.AttachmentFileStoreSmoke"
BACKUP_READBACK_MUTANTS = [
    ("backup-ignores-final-content-change", BACKUP_READBACK, BACKUP_READBACK_TEST,
     "!source.digest().equals(copy.digest()) ||", ""),
    ("backup-ignores-observation-change", BACKUP_READBACK, BACKUP_READBACK_TEST,
     "if (!before.equals(after)) {", "if (false) {"),
    ("backup-ignores-copied-stage-change", BACKUP_READBACK, BACKUP_READBACK_TEST,
     "if (!stageIdentity.equals(copied.fingerprint().identity()) || !source.digest().equals(copied.digest())) {",
     "if (false) {"),
    ("backup-ignores-metadata-stage-replacement", BACKUP_READBACK, BACKUP_READBACK_TEST,
     "if (!stageIdentity.equals(staged.fingerprint().identity())) {", "if (false) {"),
    ("backup-ignores-published-replacement", BACKUP_READBACK, BACKUP_READBACK_TEST,
     "if (!stageIdentity.equals(installed.fingerprint().identity())) {", "if (false) {"),
]
LINUX_METADATA = "ghidradwarfforge/output/LinuxFileMetadata.java"
LINUX_METADATA_TEST = "ghidradwarfforge.output.LinuxMetadataFailureControls"
LINUX_APPLICATION_TEST = "ghidradwarfforge.output.LinuxMetadataApplicationFailureControls"
LINUX_METADATA_MUTANTS = [
    ("metadata-leaves-opened-descriptor-on-failure", LINUX_METADATA, LINUX_METADATA_TEST,
     'try { opened.close(); } catch (IOException closeFailure) { failure.addSuppressed(closeFailure); }',
     ''),
    ("metadata-ignores-final-path-identity", LINUX_METADATA, LINUX_METADATA_TEST,
     'require(result.facts().equals(stat(-100, pathBytes(path), 0x100)), "metadata path changed during inspection");',
     'stat(-100, pathBytes(path), 0x100);'),
    ("metadata-application-ignores-stage-size", LINUX_METADATA, LINUX_APPLICATION_TEST,
     'after.facts().bytes() == prior.facts().bytes() && after.facts().links() == 1',
     'after.facts().links() == 1'),
    ("metadata-application-ignores-stage-links", LINUX_METADATA, LINUX_APPLICATION_TEST,
     'after.facts().bytes() == prior.facts().bytes() && after.facts().links() == 1',
     'after.facts().bytes() == prior.facts().bytes()'),
    ("metadata-application-ignores-preservation-readback", LINUX_METADATA, LINUX_APPLICATION_TEST,
     'after.preservationSha256().equals(before.preservationSha256())', 'true'),
    ("metadata-application-ignores-source-path", LINUX_METADATA, LINUX_APPLICATION_TEST,
     'stat(-100, pathBytes(source), 0x100).equals(before.facts())', 'true'),
    ("metadata-application-ignores-stage-path", LINUX_METADATA, LINUX_APPLICATION_TEST,
     'stat(-100, pathBytes(stage), 0x100).equals(after.facts())', 'true'),
]
STACK_SPILL = "ghidradwarfforge/StackSpillLifetime.java"
STACK_SPILL_TEST = "ghidradwarfforge.StackSpillSmoke"
STACK_SPILL_MUTANTS = [
    ("spill-subtraction-adds-displacement", STACK_SPILL, STACK_SPILL_TEST,
     'Math.subtractExact(base.offset(), delta)', 'Math.addExact(base.offset(), delta)'),
    ("spill-commutes-subtraction", STACK_SPILL, STACK_SPILL_TEST,
     'if (operation.getOpcode() == PcodeOp.INT_ADD && first.isConstant()) {',
     'if (first.isConstant()) {'),
]
TRUNCATED_DEPTH = "ghidradwarfforge/TruncatedStackDepth.java"
TRUNCATED_DEPTH_TEST = "ghidradwarfforge.TruncatedStackDepthSmoke"
TRUNCATED_DEPTH_MUTANTS = [
    ("truncated-depth-commutes-subtraction", TRUNCATED_DEPTH, TRUNCATED_DEPTH_TEST,
     'if (opcode == PcodeOp.INT_ADD && first.isConstant()) {', 'if (first.isConstant()) {'),
    ("truncated-depth-ignores-big-endian-low-word", TRUNCATED_DEPTH, TRUNCATED_DEPTH_TEST,
     'node.getAddress().add(program.getLanguage().isBigEndian() ? node.getSize() - addressBytes : 0)',
     'node.getAddress()'),
]
ORIGINAL_OBJECTS = "ghidradwarfforge/elf/MatchedElfSidecarWriter.java"
ORIGINAL_OBJECTS_TEST = "ghidradwarfforge.elf.LocalSymbolMergeSmoke"
ORIGINAL_OBJECT_MUTANTS = [
    ("object-match-forgets-earlier-conflict", ORIGINAL_OBJECTS, ORIGINAL_OBJECTS_TEST,
     '(old, current) -> old == OriginalObjectMatch.CONFLICT ? old : current',
     '(old, current) -> current'),
    ("object-match-sign-extends-elf32-value", ORIGINAL_OBJECTS, ORIGINAL_OBJECTS_TEST,
     'Integer.toUnsignedLong(rows.getInt(at + 4))', '(long) rows.getInt(at + 4)'),
]
FRAME_RANGES = "ghidradwarfforge/unwind/OriginalFrameRanges.java"
ARM_MAPPING = "ghidradwarfforge/elf/Arm32SectionModes.java"
ARM_MAPPING_TEST = "ghidradwarfforge.elf.Arm32SectionModesSmoke"
ARM_MAPPING_MUTANTS = [
    ("arm-mapping-ignores-inherited-function-tag", ARM_MAPPING, ARM_MAPPING_TEST,
     'modes.floorEntry(entry.getKey()).getValue().equals(entry.getValue())', 'true'),
    ("arm-mapping-applies-end-marker-to-earlier-bytes", ARM_MAPPING, ARM_MAPPING_TEST,
     'if (b.getKey() == item.address() + item.size()) continue;', ''),
    ("arm-mapping-rejects-adjacent-allocation", ARM_MAPPING, ARM_MAPPING_TEST,
     'item.address() - other.address >= other.size', 'item.address() - other.address > other.size'),
    ("arm-mapping-ignores-reserved-name", ARM_MAPPING, ARM_MAPPING_TEST,
     '!reservedNames.contains(name) && ', ''),
    ("arm-mapping-allows-address-extent-overflow", ARM_MAPPING, ARM_MAPPING_TEST,
     'size > 0x1_0000_0000L - address', 'size > 0x1_0000_0000L'),
    ("arm-mapping-rejects-exact-boundary-count", ARM_MAPPING, ARM_MAPPING_TEST,
     'boundaries.size() > 65536', 'boundaries.size() >= 65536'),
    ("arm-mapping-accepts-duplicate-boundary", ARM_MAPPING, ARM_MAPPING_TEST,
     'boundary.offset() <= previous', 'boundary.offset() < previous'),
    ("arm-mapping-treats-allocated-data-as-code", ARM_MAPPING, ARM_MAPPING_TEST,
     '(s.flags & 6) == 6', '(s.flags & 2) == 2'),
]
LOCAL_OWNERSHIP = "ghidradwarfforge/RegisterDefinitionFlow.java"
LOCAL_OWNERSHIP_TEST = "ghidradwarfforge.LocalDefinitionFlowSmoke"
LOCAL_PREFIX_TEST = "ghidradwarfforge.LaterRegisterLocalSmoke"
LOCAL_OWNERSHIP_MUTANTS = [
    ("local-definition-ignores-curated-provenance", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     'variable.getSource() != SourceType.USER_DEFINED ||', ''),
    ("local-definition-ignores-overlapping-register-identity", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     'if (node.getAddress().getAddressSpace().equals(base.getAddress().getAddressSpace()) &&',
     'if (false && node.getAddress().getAddressSpace().equals(base.getAddress().getAddressSpace()) &&'),
    ("local-definition-confuses-adjacent-register", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     'node.getOffset() < Math.addExact(base.getOffset(), base.getMinimumByteSize())',
     'node.getOffset() <= Math.addExact(base.getOffset(), base.getMinimumByteSize())'),
    ("local-prefix-ignores-overlapping-register-identity", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST,
     'if (node.getAddress().getAddressSpace().equals(base.getAddress().getAddressSpace()) &&',
     'if (false && node.getAddress().getAddressSpace().equals(base.getAddress().getAddressSpace()) &&'),
    ("local-prefix-confuses-adjacent-register", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST,
     'node.getOffset() < Math.addExact(base.getOffset(), base.getMinimumByteSize())',
     'node.getOffset() <= Math.addExact(base.getOffset(), base.getMinimumByteSize())'),
    ("local-prefix-ignores-invalid-saved-owner", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST,
     'if (!otherStorage.isValid()) {', 'if (false) {'),
]
PUBLICATION_TIME_MUTANTS = [
    ("publication-loses-source-freshness", PUBLISH,
     'ghidradwarfforge.output.CompanionArtifactPublisherSmoke',
     'Files.setLastModifiedTime(stages[0], sourceTime);', ''),
]
LINUX_MOUNT = "ghidradwarfforge/output/LinuxAttachmentMount.java"
LINUX_MOUNT_TEST = "ghidradwarfforge.output.LinuxAttachmentMountSmoke"
LINUX_MOUNT_MUTANTS = [
    ("mount-accepts-contradictory-readonly-option", LINUX_MOUNT, LINUX_MOUNT_TEST,
     ' && !values.contains("ro")', ''),
    ("mount-accepts-empty-write-option", LINUX_MOUNT, LINUX_MOUNT_TEST,
     ' && !values.contains("")', ''),
    ("mount-accepts-noncanonical-id", LINUX_MOUNT, LINUX_MOUNT_TEST,
     "(value.length() > 1 && value.charAt(0) == '0')", 'false'),
]
FRAME_RANGES_TEST = "ghidradwarfforge.unwind.OriginalFrameRangesSmoke"
FRAME_RANGE_MUTANTS = [
    ("frame-rejects-exact-byte-budget", FRAME_RANGES, FRAME_RANGES_TEST,
     'data.length <= MAX_BYTES', 'data.length < MAX_BYTES'),
    ("frame-allows-extra-record", FRAME_RANGES, FRAME_RANGES_TEST,
     'records.size() < MAX_RECORDS', 'records.size() <= MAX_RECORDS'),
    ("frame-admits-unsupported-aligned-pointer", FRAME_RANGES, FRAME_RANGES_TEST,
     'application == 0x30 || application == 0x40',
     'application == 0x30 || application == 0x40 || application == 0x50'),
    ("frame-ignores-tenth-leb-overflow", FRAME_RANGES, FRAME_RANGES_TEST,
     'if (index == 9) require(signed ? payload == 0 || payload == 127 : payload <= 1,',
     'if (index == 9) require(true,'),
    ("frame-reads-signed-leb-as-unsigned", FRAME_RANGES, FRAME_RANGES_TEST,
     'case 9 -> leb(true);', 'case 9 -> leb(false);'),
]
BUILD_ID_HELPER = "ghidradwarfforge/output/BuildIdHelper.java"
ATTACHMENT_PREVIEW = "ghidradwarfforge/output/AttachmentHelper.java"
ATTACHMENT_PREVIEW_TEST = "ghidradwarfforge.output.AttachmentHelperSmoke"
ATTACHMENT_PREVIEW_MUTANTS = [
    ("attachment-preview-ignores-broken-output", ATTACHMENT_PREVIEW, ATTACHMENT_PREVIEW_TEST,
     'return output.checkError() ? 1 : status;\n    }\n\n    private static int recover',
     'return status;\n    }\n\n    private static int recover'),
    ("attachment-preview-rejects-exact-request-limit", ATTACHMENT_PREVIEW, ATTACHMENT_PREVIEW_TEST,
     'int REQUEST_LIMIT = 256 * 1024;', 'int REQUEST_LIMIT = 256 * 1024 - 1;'),
    ("attachment-preview-loses-cancellation-status", ATTACHMENT_PREVIEW, ATTACHMENT_PREVIEW_TEST,
     'status = failure instanceof CancellationException ? 130 : 1;\n            response.addProperty("outcome",',
     'status = 1;\n            response.addProperty("outcome",'),
]
BUILD_ID_HELPER_TEST = "ghidradwarfforge.output.BuildIdHelperSmoke"
BUILD_ID_HELPER_MUTANTS = [
    ("build-id-helper-ignores-request-pin", BUILD_ID_HELPER, BUILD_ID_HELPER_TEST,
     'require(hash(bytes).equals(command.sha256()), "build-ID request differs from selected SHA-256");', ''),
    ("build-id-helper-skips-request-recheck", BUILD_ID_HELPER, BUILD_ID_HELPER_TEST,
     'var plan = AttachmentPaths.preflight(selections);\n        readRequest(command, cancelled);',
     'var plan = AttachmentPaths.preflight(selections);'),
    ("build-id-helper-accepts-carriage-return-root", BUILD_ID_HELPER, BUILD_ID_HELPER_TEST,
     "rootText.indexOf('\\r') < 0 &&", ''),
    ("build-id-helper-ignores-response-failure", BUILD_ID_HELPER, BUILD_ID_HELPER_TEST,
     'return output.checkError() ? 1 : status;', 'return status;'),
    ("build-id-helper-ignores-cancellation", BUILD_ID_HELPER, BUILD_ID_HELPER_TEST,
     'if (cancelled.getAsBoolean()) throw new CancellationException("build-ID command cancelled");',
     'if (false) throw new CancellationException("build-ID command cancelled");'),
]
REPORT_TEXT = "ghidradwarfforge/output/ExportReport.java"
REPORT_TEXT_TEST = "ghidradwarfforge.output.ExportReportSmoke"
REPORT_TEXT_MUTANTS = [
    ("report-emits-raw-control-character", REPORT_TEXT, REPORT_TEXT_TEST,
     "if (character < 0x20) {", "if (false) {"),
    ("report-drops-backspace", REPORT_TEXT, REPORT_TEXT_TEST,
     'case \'\\b\' -> json.append("\\\\b");', "case '\\b' -> { }"),
    ("report-hides-decompilation-failure", REPORT_TEXT, REPORT_TEXT_TEST,
     'failures.isEmpty() &&', ''),
    ("report-hides-skipped-function", REPORT_TEXT, REPORT_TEXT_TEST,
     'skippedFunctions.isEmpty() &&', ''),
    ("report-hides-omitted-location", REPORT_TEXT, REPORT_TEXT_TEST,
     'omitted.isEmpty() &&', ''),
    ("report-hides-unsupported-construct", REPORT_TEXT, REPORT_TEXT_TEST,
     'unsupported.isEmpty() &&', ''),
    ("report-hides-diagnostic", REPORT_TEXT, REPORT_TEXT_TEST,
     '&& diagnostics.isEmpty()', ''),
    ("report-accepts-negative-static-count", REPORT_TEXT, REPORT_TEXT_TEST,
     'functionStaticVariables < 0', 'false'),
    ("report-accepts-invalid-artifact-hash", REPORT_TEXT, REPORT_TEXT_TEST,
     '!value.matches("[0-9a-fA-F]{64}")', 'false'),
    ("report-accepts-empty-omitted-range", REPORT_TEXT, REPORT_TEXT_TEST,
     'endAddress <= startAddress', 'endAddress < startAddress'),
    ("report-accepts-unsupported-address-size", REPORT_TEXT, REPORT_TEXT_TEST,
     'addressBits != 32 && addressBits != 64', 'false'),
]
FRAME_REREAD_MUTANTS = [
    ("frame-compression-sign-extends-alignment", FRAME_REREAD, FRAME_REREAD_TEST,
     'long alignment = wide ? fields.getLong() : Integer.toUnsignedLong(fields.getInt());',
     'long alignment = wide ? fields.getLong() : fields.getInt();'),
    ("frame-compression-rejects-zero-alignment", FRAME_REREAD, FRAME_REREAD_TEST,
     'alignment >= 0 && (alignment == 0 ||', 'alignment > 0 && (alignment == 0 ||'),
    ("frame-reread-ignores-stored-hash", FRAME_REREAD, FRAME_REREAD_TEST,
     'require(hash(stored, cancelled).equals(selected.storedSha256()), "original stored frame bytes changed");',
     ''),
    ("frame-reread-ignores-decoded-hash", FRAME_REREAD, FRAME_REREAD_TEST,
     'hash(plain, cancelled).equals(selected.decodedSha256())', 'true'),
    ("frame-reread-ignores-decoded-size", FRAME_REREAD, FRAME_REREAD_TEST,
     'plain.length == selected.decodedBytes() &&', ''),
    ("frame-reread-accepts-ambiguous-section", FRAME_REREAD, FRAME_REREAD_TEST,
     'require(section == null, "ambiguous original debug-frame section");', ''),
    ("frame-reread-accepts-duplicate-inventory", FRAME_REREAD, FRAME_REREAD_TEST,
     'require(selected == null, "multiple original debug-frame sources");', ''),
]
REGISTER_PROFILE_MUTANTS = [
    ("register-slice-ignores-parent-width", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "parent.getBitLength() != logicalSlice.parentBits() ||", ""),
    ("register-slice-ignores-physical-offset", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "register.getAddress().subtract(parent.getAddress()) != logicalSlice.byteOffset()", "false"),
    ("register-pair-ignores-child-offset", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "child.getLeastSignificantBitInBaseRegister() != expected.baseBitOffset() ||", ""),
    ("register-pair-ignores-child-width", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "child.getBitLength() != expected.bitSize()", "false"),
]
STACK_CARRIER_MUTANTS = [
    ("stack-carrier-admits-unsaved-parameter", STACK_FLOW, STACK_CARRIER_TEST,
     "parameter.getFunction() != function ||\n                parameter.getOrdinal() < 0 || function.getParameter(parameter.getOrdinal()) != parameter ||", ""),
    ("stack-carrier-admits-foreign-storage", STACK_FLOW, STACK_CARRIER_TEST,
     "storage.getProgramArchitecture() != program || !storage.isValid()", "!storage.isValid()"),
    ("stack-carrier-forgets-indirection", STACK_FLOW, STACK_CARRIER_TEST,
     "storage.isForcedIndirect() != indirect ||", ""),
]
MERGED_LIFETIME_MUTANTS = [
    ("merged-stack-ignores-curated-provenance", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "variable.getSource() != SourceType.USER_DEFINED || !variable.isValid() ||\n                    !variable.hasAssignedStorage() || assigned == null || !assigned.isValid() ||", "!variable.isValid() ||\n                    !variable.hasAssignedStorage() || assigned == null || !assigned.isValid() ||"),
    ("merged-register-ignores-curated-provenance", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "variable.getSource() != SourceType.USER_DEFINED || !variable.isValid() ||\n                    !variable.hasAssignedStorage() || variable.getRegister() != register ||", "!variable.isValid() ||\n                    !variable.hasAssignedStorage() || variable.getRegister() != register ||"),
    ("merged-register-ignores-formal-type", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "!variable.getDataType().equals(group.canonical().getDataType()) ||", ""),
    ("merged-stack-ignores-formal-type", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "!variable.getDataType().equals(canonical.getDataType()) ||", ""),
    ("merged-register-accepts-missing-definition", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "!GhidraVariableStorage.completeRegisterDefinition(instruction, register, variable.getLength()) ||", ""),
    ("merged-stack-accepts-missing-definition", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "!GhidraVariableStorage.completeRegisterDefinition(decoded.get(mapping.definition()),\n                            register, variable.getLength()) ||", ""),
    ("merged-register-loses-canonical-owner", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "if (!members.contains(group.canonical())) return List.of();", ""),
    ("merged-stack-claims-entire-frame", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "if (member.getVariableStorage().intersects(assigned)) return List.of();", "return List.of();"),
]

I386_ALLOCATION_MUTANTS = [
    ("i386-allocation-ignores-abi-revision", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "|| header[8] != 0", ""),
    ("i386-allocation-admits-relocatable-input", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "(image.type() != 2 && image.type() != 3)", "false"),
    ("i386-allocation-admits-extra-call-argument", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "signature.getArguments().length > 4095", "signature.getArguments().length > 4096"),
    ("i386-allocation-admits-extra-saved-argument", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "parameters.length > 4096", "parameters.length > 4097"),
    ("i386-allocation-uses-hidden-pointer-return", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "new SignatureResolution(adjusted[0], inputs)", "new SignatureResolution(expected[0], inputs)"),
    ("i386-allocation-loses-automatic-omission", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "new Resolution(changes, Set.of(parameters[0].getOrdinal()), adjusted[0])",
     "new Resolution(changes, Set.of(), adjusted[0])"),
    ("i386-allocation-rejects-unassigned-aggregate", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "if (prior.isUnassignedStorage() && replacement.isUnassignedStorage()) continue;", ""),
    ("i386-allocation-rejects-freed-input-slot", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "return !replacement.isForcedIndirect() && formalType.getLength() > 0 &&",
     "return replacement.isForcedIndirect() && formalType.getLength() > 0 &&"),
    ("i386-allocation-admits-partial-input-slot", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "replacement.size() == formalType.getLength();", "replacement.size() <= formalType.getLength();"),
    ("i386-allocation-invents-unassigned-call-input", I386_ALLOCATION, I386_ALLOCATION_TEST,
     "if (storage.isUnassignedStorage() && prior.isUnassignedStorage()) return null;",
     "if (storage.isUnassignedStorage() && prior.isUnassignedStorage()) { inputs.add(storage); continue; }"),
]

VALIDATOR_STATUS_MUTANTS = [
    ("validator-status-allows-extra-byte", VALIDATOR_STATUS, VALIDATOR_STATUS_TEST,
     "bytes.length > 4096", "bytes.length > 4097"),
    ("validator-status-allows-duplicate-fields", VALIDATOR_STATUS, VALIDATOR_STATUS_TEST,
     "if (!seen.add(name))", "if (false)"),
    ("validator-status-ignores-stderr-retention", VALIDATOR_STATUS, VALIDATOR_STATUS_TEST,
     'numbers.get("stderrObserved") < numbers.get("stderrRetained")', "false"),
    ("validator-status-allows-wrapped-exit-code", VALIDATOR_STATUS, VALIDATOR_STATUS_TEST,
     'numbers.get("exitCode") > 0xffff_ffffL', 'numbers.get("exitCode") > 0x1_0000_0000L'),
    ("validator-status-allows-next-invalid-signal", VALIDATOR_STATUS, VALIDATOR_STATUS_TEST,
     'numbers.get("exitSignal") > 64', 'numbers.get("exitSignal") > 65'),
    ("validator-status-narrows-observed-bytes", VALIDATOR_STATUS, VALIDATOR_STATUS_TEST,
     'numbers.get("stdoutObserved"), numbers.get("stdoutRetained")',
     'numbers.get("stdoutObserved").intValue(), numbers.get("stdoutRetained")'),
]

CALL_VALUE_MUTANTS = [
    ("call-value-folds-unsigned-shift-as-signed", CALL_VALUE, CALL_VALUE_TEST,
     "a.value() >>> b.value()", "a.value() >> b.value()"),
    ("call-value-uses-signed-shift-count-bound", CALL_VALUE, CALL_VALUE_TEST,
     "Long.compareUnsigned(b.value(), left.bytes() * 8L) >= 0 ? 0 : a.value() << b.value()",
     "b.value() >= left.bytes() * 8L ? 0 : a.value() << b.value()"),
    ("call-value-loses-nested-slice-offset", CALL_VALUE, CALL_VALUE_TEST,
     "part.lowBit() + lowBit", "lowBit"),
    ("call-value-loses-constant-sign-extension", CALL_VALUE, CALL_VALUE_TEST,
     "if (signed) value = signExtend(value, source.bytes());", "if (false) value = signExtend(value, source.bytes());"),
    ("call-value-reverses-constant-selection", CALL_VALUE, CALL_VALUE_TEST,
     "literal.value() != 0 ? yes : no", "literal.value() == 0 ? yes : no"),
    ("call-value-rejects-exact-node-budget", CALL_VALUE, CALL_VALUE_TEST,
     "nodes > 256", "nodes >= 256"),
]

CXX_PROFILE_MUTANTS = [
    ("cxx-profile-commits-preview", CXX_PROFILE, CXX_PROFILE_TEST,
     "commit = save;", "commit = true;"),
    ("cxx-profile-allows-retained-type-collision", CXX_PROFILE, CXX_PROFILE_TEST,
     "!types.add(result.binding().typeId())", "false"),
    ("cxx-profile-allows-stale-declaration", CXX_PROFILE, CXX_PROFILE_TEST,
     "if (GhidraDeclarationBindings.read(program, id, monitor, ignored -> { }).status() != GhidraDeclarationBindings.Status.VALID)",
     "if (false)"),
    ("cxx-profile-accepts-extra-candidate", CXX_PROFILE, CXX_PROFILE_TEST,
     "private static final int MAX_INVENTORY = 1024;", "private static final int MAX_INVENTORY = 1025;"),
    ("cxx-profile-accepts-extra-record", CXX_PROFILE, CXX_PROFILE_TEST,
     "private static final int MAX_RECORDS = 4096;", "private static final int MAX_RECORDS = 4097;"),
    ("cxx-profile-accepts-excess-saved-text", CXX_PROFILE, CXX_PROFILE_TEST,
     "chars > 16L * 1024 * 1024", "chars > 17L * 1024 * 1024"),
    ("cxx-table-ignores-lower-overlap", CXX_PROFILE, CXX_PROFILE_TEST,
     "lower != null && lower.getValue().compareTo(start) > 0", "false"),
    ("cxx-table-ignores-upper-overlap", CXX_PROFILE, CXX_PROFILE_TEST,
     "upper != null && upper.getKey().compareTo(end) < 0", "false"),
    ("cxx-table-rejects-touching-lower-boundary", CXX_PROFILE, CXX_PROFILE_TEST,
     "lower.getValue().compareTo(start) > 0", "lower.getValue().compareTo(start) >= 0"),
    ("cxx-table-rejects-touching-upper-boundary", CXX_PROFILE, CXX_PROFILE_TEST,
     "upper.getKey().compareTo(end) < 0", "upper.getKey().compareTo(end) <= 0"),
    ("cxx-table-allows-duplicate-mangled-name", CXX_PROFILE, CXX_PROFILE_TEST,
     "!mangled.add(table.mangledName())", "false"),
    ("cxx-table-allows-ambiguous-lookup-owner", CXX_PROFILE, CXX_PROFILE_TEST,
     "prior != null && prior != table.classId()", "false"),
]

CALL_MEMORY_MUTANTS = [
    ("call-memory-accepts-absolute-store", CALL_MEMORY, CALL_MEMORY_TEST,
     "address != null && address.stack() ? address.offset() : null",
     "address != null ? address.offset() : null"),
    ("call-memory-treats-stack-difference-as-pointer", CALL_MEMORY, CALL_MEMORY_TEST,
     "new Term(left.stack() != right.stack(), result)",
     "new Term(left.stack() || right.stack(), result)"),
    ("call-memory-accepts-narrow-offset-overflow", CALL_MEMORY, CALL_MEMORY_TEST,
     "return ((value << shift) >> shift) == value;", "return true;"),
    ("call-memory-does-not-translate-nested-write", CALL_MEMORY, CALL_MEMORY_TEST,
     "new Range(Math.addExact(calledSp.offset(), range.start()), Math.addExact(calledSp.offset(), range.end()))",
     "new Range(range.start(), range.end())"),
    ("call-memory-retains-released-stack-storage", CALL_MEMORY, CALL_MEMORY_TEST,
     "if (released) writes.add", "if (false) writes.add"),
]

CURATED_TYPE_MUTANTS = [
    ("curated-type-loses-utf-encoding", CURATED_TYPES, CURATED_TYPES_TEST,
     "positiveSize(type), BaseEncoding.UTF", "positiveSize(type), BaseEncoding.UNSIGNED"),
    ("curated-type-changes-member-const", CURATED_TYPES, CURATED_TYPES_TEST,
     "case MutabilitySettingsDefinition.CONSTANT -> TypeGraph.Qualifier.CONST;",
     "case MutabilitySettingsDefinition.CONSTANT -> TypeGraph.Qualifier.VOLATILE;"),
    ("curated-type-emits-zero-width-value", CURATED_TYPES, CURATED_TYPES_TEST,
     "if (bitSize == 0)", "if (false)"),
    ("curated-type-uses-base-bitfield-storage", CURATED_TYPES, CURATED_TYPES_TEST,
     "storageByteSize = bitField.getStorageSize();", "storageByteSize = memberType.getLength();"),
]

ARM_MODE_INVENTORY_MUTANTS = [
    ("arm-inventory-accepts-conflicting-mode", ARM_MODE_INVENTORY, ARM_MODE_INVENTORY_TEST,
     "old == null || old == mode", "true"),
    ("arm-inventory-rejects-section-end-marker", ARM_MODE_INVENTORY, ARM_MODE_INVENTORY_TEST,
     "value - section.address <= section.size", "value - section.address < section.size"),
    ("arm-inventory-uses-nonexecutable-mappings", ARM_MODE_INVENTORY, ARM_MODE_INVENTORY_TEST,
     "if ((section.flags & 6) == 6)", "if (true)"),
    ("arm-inventory-drops-sectionless-mirror", ARM_MODE_INVENTORY, ARM_MODE_INVENTORY_TEST,
     "if (mirror != null)", "if (false)"),
    ("arm-inventory-rejects-maximum-cue-count", ARM_MODE_INVENTORY, ARM_MODE_INVENTORY_TEST,
     "cues.size() > 65536", "cues.size() > 65535"),
    ("arm-inventory-ignores-comparison-budget", ARM_MODE_INVENTORY, ARM_MODE_INVENTORY_TEST,
     "(long) aliases.size() * reserved.size()", "0L"),
]

BOUNDED_SWITCH_MUTANTS = [
    ("switch-accepts-conflicting-read-widths", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "old == null || old.equals(read)", "true"),
    ("switch-exceeds-dispatch-window", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "count < 32", "count < 33"),
    ("switch-adds-instead-of-subtracting-index", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "case PcodeOp.INT_SUB -> a - b;", "case PcodeOp.INT_SUB -> a + b;"),
    ("switch-shifts-index-in-wrong-direction", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "? a << b : 0L", "? a >>> b : 0L"),
]

STATIC_RECOVERY_MUTANTS = [
    ("static-recovery-ignores-saved-symbol", STATIC_RECOVERY, STATIC_RECOVERY_TEST,
     "candidate.symbolId() != symbol.getID()", "false"),
    ("static-recovery-ignores-exact-extent", STATIC_RECOVERY, STATIC_RECOVERY_TEST,
     "exactSize > 0 && candidate.type().getLength() != exactSize", "false"),
    ("static-recovery-crosses-memory-block", STATIC_RECOVERY, STATIC_RECOVERY_TEST,
     "!block.contains(end)", "false"),
    ("memory-local-crosses-memory-block", "ghidradwarfforge/GhidraTypeGraph.java", STATIC_RECOVERY_TEST,
     'if (!memoryBlock.contains(memoryAddress.addNoWrap(type.getLength() - 1L))) continue;',
     'if (!memoryBlock.contains(memoryAddress.addNoWrap(0))) continue;'),
    ("memory-local-loses-address-normalization", "ghidradwarfforge/GhidraTypeGraph.java", STATIC_RECOVERY_TEST,
     'long memoryOffset = AddressNormalizer.toElfAddress(memoryAddress.getOffset(), rebaseDelta);',
     'long memoryOffset = memoryAddress.getOffset();'),
    ("memory-local-loses-inferred-provenance", "ghidradwarfforge/GhidraTypeGraph.java", STATIC_RECOVERY_TEST,
     '(inferred ? "DECOMPILER_INFERRED_TYPE; " : "")', '""'),
    ("memory-local-overrides-saved-type", "ghidradwarfforge/GhidraTypeGraph.java", STATIC_RECOVERY_TEST,
     'if (inferred) type = GhidraStaticRecovery.accept', 'if (true) type = GhidraStaticRecovery.accept'),
    ("memory-local-admits-mapped-address", "ghidradwarfforge/GhidraTypeGraph.java", STATIC_RECOVERY_TEST,
     'memoryBlock.isMapped()', 'false'),
    ("memory-local-flattens-overlay-address", "ghidradwarfforge/GhidraTypeGraph.java", STATIC_RECOVERY_TEST,
     'memoryBlock.isOverlay() || memoryBlock.isMapped() ||\n                        !memoryAddress.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())',
     'memoryBlock.isMapped()'),
    ("memory-local-flattens-physical-address-space", "ghidradwarfforge/GhidraTypeGraph.java", STATIC_RECOVERY_TEST,
     '!memoryAddress.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())', 'false'),
]

VTABLE_BINDING_MUTANTS = [
    ("vtable-forgets-relocation-type", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "out.writeInt(relocation.getType());", "out.writeInt(0);"),
    ("vtable-forgets-relocation-status", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "out.writeUTF(relocation.getStatus().name());", 'out.writeUTF("ignored");'),
    ("vtable-forgets-relocation-values", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "for (long value : values) out.writeLong(value);", "for (long value : values) out.writeLong(0);"),
    ("vtable-accepts-excessive-relocation-values", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "values.length > 4096", "values.length > 4097"),
    ("vtable-accepts-excessive-relocation-bytes", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "bytes.length > MAX_TABLE_BYTES", "bytes.length > MAX_TABLE_BYTES + 1"),
    ("vtable-accepts-excessive-inventory", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "keys.size() > 4096", "keys.size() > 4097"),
    ("vtable-undercharges-encoded-records", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     'encodedBytes += Objects.toString(options.getString(key, ""), "").length();', "encodedBytes += 1;"),
    ("vtable-undercharges-byte-witnesses", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "inspectedBytes[0] += size;", "inspectedBytes[0] += 1;"),
    ("vtable-accepts-discontiguous-file-offsets", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "if (file != first || absolute != Math.addExact(firstOffset, index))", "if (file != first)"),
    ("vtable-merges-distinct-file-identities", VTABLE_BINDINGS, VTABLE_BINDINGS_TEST,
     "if (file != first || absolute != Math.addExact(firstOffset, index))",
     "if (absolute != Math.addExact(firstOffset, index))"),
]

STACK_FLOW_MUTANTS = [
    ("value-flow-unions-zero-bits-across-paths", STACK_FLOW, STACK_FLOW_TEST,
     "zeros.replaceAll((node, mask) -> mask & other.zeros.getOrDefault(node, 0L));",
     "zeros.replaceAll((node, mask) -> mask | other.zeros.getOrDefault(node, 0L));"),
    ("value-flow-retains-first-path-zero-bits", STACK_FLOW, STACK_FLOW_TEST,
     "zeros.replaceAll((node, mask) -> mask & other.zeros.getOrDefault(node, 0L));",
     "zeros.replaceAll((node, mask) -> mask);"),
    ("value-flow-loses-first-byte-with-unrelated-overlap", STACK_FLOW, STACK_FLOW_TEST,
     "if (disjoint || (secondZeros & mask) == mask) values.add(value);", "if (disjoint) values.add(value);"),
    ("value-flow-loses-second-byte-with-unrelated-overlap", STACK_FLOW, STACK_FLOW_TEST,
     "if (disjoint || (firstZeros & mask) == mask) values.add(value);", "if (disjoint) values.add(value);"),
    ("value-flow-caps-wide-shifts-at-host-long", STACK_FLOW, STACK_FLOW_TEST,
     "bits >= (long) output.getSize() * Byte.SIZE", "bits >= Long.SIZE"),
    ("value-flow-wraps-wide-carrier-byte-offset", STACK_FLOW, STACK_FLOW_TEST,
     "long offset = value.offset() + displacement;", "long offset = (value.offset() + displacement) & 7;"),
    ("value-flow-invents-zero-sign-extension", STACK_FLOW, STACK_FLOW_TEST,
     "operation.getOpcode() == PcodeOp.INT_SEXT && (known & (1L << (first.getSize() * Byte.SIZE - 1))) != 0",
     "operation.getOpcode() == PcodeOp.INT_SEXT"),
    ("value-flow-zeroes-oversized-arithmetic-shift", STACK_FLOW, STACK_FLOW_TEST,
     "if (count >= bits) return opcode != PcodeOp.INT_SRIGHT || signZero ? mask : 0;",
     "if (count >= bits) return mask;"),
    ("value-flow-allows-carry-between-overlapping-values", STACK_FLOW, STACK_FLOW_TEST,
     "boolean disjoint = (firstZeros | secondZeros) == bitMask(output.getSize());", "boolean disjoint = true;"),
    ("value-flow-loses-second-operand-byte", STACK_FLOW, STACK_FLOW_TEST,
     "if (disjoint || (firstZeros & mask) == mask) values.add(value);", "if (false) values.add(value);"),
]

MIPS_ALLOCATION_MUTANTS = [
    ("mips-allocation-accepts-unknown-record-flags", MIPS_ALLOCATION, MIPS_ALLOCATION_TEST,
     "(fields.flags1() & ~1L) != 0", "false"),
    ("mips-allocation-loses-direct-field-alias", MIPS_ALLOCATION, MIPS_ALLOCATION_TEST,
     "while (field instanceof TypeDef alias && aliases.add(field) && aliases.size() <= 64)",
     "while (field instanceof TypeDef alias && false && aliases.add(field) && aliases.size() <= 64)"),
    ("mips-allocation-drops-aligned-argument-hole", MIPS_ALLOCATION, MIPS_ALLOCATION_TEST,
     "if (aligned && (slots & 1) != 0)", "if (false)"),
]

TRANSACTION_MUTANTS = [
    ("transaction-accepts-mismatched-sidecar-crc", TRANSACTION, TRANSACTION_TEST,
     'request.prepared().debuglinkCrc32() != snapshots.get("sidecar").digest().gnuDebuglinkCrc32()', "false"),
    ("transaction-refresh-reuses-operation-identity", TRANSACTION, TRANSACTION_TEST,
     "previous.operationId().equals(current.operationId())", "false"),
    ("transaction-recovery-follows-unrecorded-role", TRANSACTION, TRANSACTION_TEST,
     '!entry.getKey().equals("targetAfter") && !selectedPath.toString().equals(artifact.path())', "false"),
    ("transaction-rejects-already-restored-owned-image", TRANSACTION, TRANSACTION_TEST,
     "sameImage(observed, before) || allowAlreadyRestored &&", "sameImage(observed, before) || false &&"),
]

REPORT_CLAIMS_MUTANTS = [
    ("coverage-accepts-variable-across-function-gap", REPORT_CLAIMS, REPORT_CLAIMS_TEST,
     "outer.get(cursor).address() != end", "false"),
    ("coverage-invents-root-static-visibility", REPORT_CLAIMS, REPORT_CLAIMS_TEST,
     'require(!variable.location().scopeComplete(), "root static invents visibility");',
     'require(true, "root static invents visibility");'),
    ("coverage-emits-unrecovered-signature", REPORT_CLAIMS, REPORT_CLAIMS_TEST,
     'require(!emitted || recovered, "emitted signature has no recovered population");',
     'require(true, "emitted signature has no recovered population");'),
    ("coverage-wraps-type-union-upper-bound", REPORT_CLAIMS, REPORT_CLAIMS_TEST,
     "counts[i] > Long.MAX_VALUE - upper[i] ? Long.MAX_VALUE : upper[i] + counts[i]", "upper[i] + counts[i]"),
    ("coverage-accepts-duplicate-type-edge", REPORT_CLAIMS, TYPE_CLAIMS_TEST,
     'require(result.put(get(edge, "key"), (int) count) == null, "duplicate type edge");',
     'result.put(get(edge, "key"), (int) count);'),
]

SOURCE_FILES_MUTANTS = [
    ("source-bundle-accepts-wrong-dwarf-file-order", SOURCE_FILES, SOURCE_FILES_TEST,
     "if (!sourceNames().equals(dwarfFiles))", "if (false)"),
    ("source-bundle-misses-replaced-inventory", SOURCE_FILES, SOURCE_FILES_TEST,
     "!java.util.Objects.equals(before.fileKey(), state.key())", "false"),
    ("source-bundle-ignores-part-time-change", SOURCE_FILES, SOURCE_FILES_TEST,
     "!before.lastModifiedTime().equals(after.lastModifiedTime())", "false"),
    ("source-bundle-accepts-duplicate-function-identity", SOURCE_BUNDLE, SOURCE_BUNDLE_TEST,
     '!keys.add(function.address() + ":" + function.name())', "false"),
    ("source-bundle-accepts-function-outside-part", SOURCE_BUNDLE, SOURCE_BUNDLE_TEST,
     "last > part.last()", "false"),
    ("source-bundle-exceeds-function-budget", SOURCE_BUNDLE, SOURCE_BUNDLE_TEST,
     "functions.size() > 250000", "functions.size() > 250001"),
]

RECEIPT_MUTANTS = [
    ("receipt-accepts-shared-backup-identity", RECEIPT, RECEIPT_TEST,
     "before.identity().equals(backup.identity())", "false"),
    ("receipt-accepts-incomplete-restored-metadata", RECEIPT, RECEIPT_TEST,
     "!recovery.observedTarget().metadataSha256().equals(before.metadataSha256())", "false"),
    ("receipt-publishes-changed-stage-bytes", RECEIPT_STORE, RECEIPT_STORE_TEST,
     "if (!stagedFingerprint.equals(host.inspect(stage)) ||\n                    !sha256(bytes).equals(sha256(bounded(stage)))) {",
     "if (!stagedFingerprint.equals(host.inspect(stage))) {"),
    ("refresh-ignores-retained-debuglink-crc", OPERATION, OPERATION_TEST,
     "content.sidecarDigest().gnuDebuglinkCrc32() != previous.debuglinkCrc32()", "false"),
    ("refresh-accepts-unrelated-source-bundle", OPERATION, OPERATION_TEST,
     'if (!previousBundle.manifest().inputSha256().equals(snapshots.get("originalBackup").digest().sha256()))',
     "if (false)"),
    ("attachment-ignores-replaced-output-parent", OPERATION, OPERATION_TEST,
     "if (!parent.getValue().equals(host.directoryIdentity(parent.getKey())))", "if (false)"),
]

# Each edit names a specific safety/semantic guarantee. This is not a blanket
# mutation score: surviving, uncompilable or timed-out mutants fail this harness.
MUTANTS = [
    ("inheritance-loses-subobject-offset", INHERITANCE, INHERITANCE_TEST,
     "if (base.vptrOffset() != 0)", "if (false)"),
    ("inheritance-loses-signed-slot", INHERITANCE, INHERITANCE_TEST,
     "value >>= 7;", "value >>>= 7;"),
    ("inheritance-accepts-excessive-slot", INHERITANCE, INHERITANCE_TEST,
     "slot >= 65536", "slot > 65536"),
    ("repair-offset-truncation", REPAIR, REPAIR_TEST,
     "if ((buffer.getLong(cursor.offset) & 0xffffffff00000000L) != 0)", "if (false)"),
    ("repair-reference-not-adjusted", REPAIR, REPAIR_TEST,
     "long adjusted = adjust(reference.target(), deletions);", "long adjusted = reference.target();"),
    ("repair-wrong-byte-order", REPAIR, REPAIR_TEST,
     "order == ByteOrder.LITTLE_ENDIAN", "order == ByteOrder.BIG_ENDIAN"),
    ("relocation-wrong-directory-reference", RELOCATE, RELOCATE_TEST,
     "putInt(directoryReference, strings.length)", "putInt(directoryReference, 0)"),
    ("relocation-ignores-cancellation", RELOCATE, RELOCATE_TEST,
     "if (cancelled.getAsBoolean()) throw", "if (cancelled.getAsBoolean() && false) throw"),
    ("relocation-accepts-duplicate-file", RELOCATE, RELOCATE_TEST,
     "require(uniqueFiles.add(file.value()),", "require(uniqueFiles.add(file.value()) || true,"),
    ("publication-loses-primary-cleanup-diagnostic", PUBLISH, PUBLISH_TEST,
     "failure.addSuppressed(cleanupFailure);", "failure.getMessage();"),
    ("publication-loses-previous-generation", PUBLISH, PUBLISH_TEST,
     "move(backups[index], targets.get(index));", "Files.deleteIfExists(backups[index]);"),
    ("publication-ignores-final-cancellation", PUBLISH,
     "ghidradwarfforge.output.CompanionArtifactPublisherSmoke",
     "hook.afterInstall(index);\n            }\n            check.check();",
     "hook.afterInstall(index);\n            }\n            // Mutant drops the final cancellation check."),
    ("firmware-ignores-cancellation", FIRMWARE, FIRMWARE_TEST,
     'if (Objects.requireNonNull(cancelled, "cancelled").getAsBoolean())', 'if (false)'),
    ("firmware-leaks-failed-carriers", FIRMWARE, FIRMWARE_TEST,
     "try { remove(directory); }", "try { if (directory == null) remove(directory); }"),
    ("firmware-ignores-input-provenance", FIRMWARE, FIRMWARE_TEST,
     "digest.byteCount() != input.size() || !digest.sha256().equals(input.sha256())", "false"),
    ("firmware-confuses-file-offset", FIRMWARE, FIRMWARE_TEST,
     "long offset = span.fileOffset();", "long offset = 0;"),
]

PROJECT_MUTANTS = [
    ("project-allows-descendant", PROTECT, PROTECT_TEST,
     "if (path.startsWith(directory))", "if (false)"),
    ("project-misses-file-alias", PROTECT, PROTECT_TEST,
     "ghidradwarfforge.output.FileSystemPaths.aliases(output, protectedPath)",
     "output.equals(protectedPath)"),
    ("project-skips-linked-file", PROTECT, PROTECT_TEST,
     "Files.isRegularFile(path)", "Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)"),
    ("project-ignores-cancellation", PROTECT, PROTECT_TEST,
     "var file = program.getDomainFile();", "monitor = TaskMonitor.DUMMY; var file = program.getDomainFile();"),
]

RECORD_MUTANTS = [
    ("record-accepts-duplicate-field", RECORDS, RECORDS_TEST,
     "require(!value.has(name),", "require(true,"),
    ("record-truncates-artifact-size", RECORDS, RECORDS_TEST,
     "return Long.parseLong(value);", "return Long.parseLong(value) & 0xffffffffL;"),
    ("record-accepts-nonnormalized-path", RECORDS, RECORDS_TEST,
     'part.normalize().equals(part) && !part.startsWith("..")', '!part.startsWith("..")'),
    ("record-exceeds-value-budget", RECORDS, RECORDS_TEST,
     "++count[0] <= maximumValues", "++count[0] <= maximumValues + 1"),
]

UNWIND_REPORT_MUTANTS = [
    ("unwind-report-accepts-wrong-byte-address", UNWIND_REPORT, UNWIND_REPORT_TEST,
     "bytes.address() == normalized && bytes.fileOffset() >= 0", "bytes.fileOffset() >= 0"),
    ("unwind-report-shifts-file-offset", UNWIND_REPORT, UNWIND_REPORT_TEST,
     "hex(bytes.fileOffset())", "hex(bytes.fileOffset() + 1)"),
    ("unwind-report-accepts-pointer-overflow", UNWIND_REPORT, UNWIND_REPORT_TEST,
     "require(image.is64Bit() || Long.compareUnsigned(value, 0xffff_ffffL) <= 0,", "require(true,"),
]

MMIO_MUTANTS = [
    ("mmio-accepts-unsupported-access-width", MMIO, MMIO_TEST,
     "Set.of(1, 2, 4, 8).contains(r.width())", "true"),
    ("mmio-loses-analyst-read-effect", MMIO, MMIO_TEST,
     'words.get("read_effect"), views', '"none", views'),
    ("mmio-accepts-outside-register-view", MMIO, MMIO_TEST,
     "v.offset() >= 0 && v.offset() < r.width()", "v.offset() >= 0 && v.offset() <= r.width()"),
]

CXX_SELECTION_MUTANTS = [
    ("cxx-selection-rounds-decimal-identity", CXX_SELECTION, CXX_SELECTION_TEST,
     "return Long.parseLong(spelling);", "return (long) Double.parseDouble(spelling);"),
    ("cxx-selection-applies-removed-table", CXX_SELECTION, CXX_SELECTION_TEST,
     "!Collections.disjoint(tableIds, remove.vtables())", "false"),
    ("cxx-selection-exceeds-table-budget", CXX_SELECTION, CXX_SELECTION_TEST,
     ".sum() > 64L * 1024 * 1024", ".sum() > 65L * 1024 * 1024"),
]

PROGRAM_TYPE_MUTANTS = [
    ("type-model-leaks-location-outside-block", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "? location : scope.restrict(location)", "? location : location"),
    ("type-model-matches-owner-by-name-only", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "candidate.address() == location.functionAddress() &&", "true &&"),
    ("type-model-accepts-wrong-value-width", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "declaredSize > 0 && declaredSize != location.byteSize()", "false"),
    ("type-model-accepts-ambiguous-static-names", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "variable.name())) > 1).collect", "variable.name())) > 2).collect"),
    ("type-model-borrows-namespace-list", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "namespace = List.copyOf(namespace);", ""),
    ("type-model-allows-blank-namespace", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "part -> part == null || part.isBlank()", "part -> part == null"),
    ("type-model-allows-blank-external-identity", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "key == null || key.isBlank() || name == null", "key == null || name == null"),
    ("type-model-allows-zero-sized-local", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "byteSize <= 0", "byteSize < 0"),
    ("type-model-loses-local-first-use-order", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "Comparator.comparingInt(LocalVariable::firstUseOffset)\n                    .thenComparing(LocalVariable::name)",
     "Comparator.comparing(LocalVariable::name)"),
    ("type-model-exposes-mutable-global-list", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     ".thenComparing(GlobalVariable::name))\n            .toList();",
     ".thenComparing(GlobalVariable::name))\n            .collect(java.util.stream.Collectors.toCollection(java.util.ArrayList::new));"),
    ("type-model-sorts-abi-parameters-by-name", PROGRAM_TYPES, PROGRAM_TYPES_TEST,
     "parameters = List.copyOf(parameters);\n            validateObjectParameterCount(parameters);\n            locals = locals.stream()",
     "parameters = parameters.stream().sorted(Comparator.comparing(Parameter::name)).toList();\n            validateObjectParameterCount(parameters);\n            locals = locals.stream()"),
]

SECTIONLESS_MUTANTS = [
    ("sectionless-sign-extends-relocation-size", SECTIONLESS, SECTIONLESS_TEST,
     "Integer.toUnsignedLong(data.getInt(at + 8))", "(long) data.getInt(at + 8)"),
    ("sectionless-accepts-empty-sysv-buckets", SECTIONLESS, SECTIONLESS_TEST,
     "buckets > 0 && buckets <= MAX_SYMBOLS", "buckets >= 0 && buckets <= MAX_SYMBOLS"),
    ("sectionless-loses-zero-sized-end-marker", SECTIONLESS, SECTIONLESS_TEST,
     "if (selected == 0 && size == 0)", "if (false)"),
]

DYNAMIC_MUTANTS = [
    ("dynamic-requalifies-absolute-version-node", DYNAMIC, DYNAMIC_TEST,
     "if (section == 0xfff1 && value == 0 && Arrays.equals(name, versionName))", "if (false)"),
    ("dynamic-duplicates-qualified-name", DYNAMIC, DYNAMIC_TEST,
     "Integer position = appended.get(key);", "Integer position = null;"),
    ("dynamic-accepts-versioned-null-symbol", DYNAMIC, DYNAMIC_TEST,
     'require(version == 0, "dynamic null symbol has a version");',
     'require(true, "dynamic null symbol has a version");'),
    ("dynamic-accepts-unexpected-extended-index", DYNAMIC, DYNAMIC_TEST,
     'escaped < input.sectionCount() : escaped == 0', 'escaped < input.sectionCount() : true'),
    ("dynamic-accepts-duplicate-version-table", DYNAMIC, DYNAMIC_TEST,
     'require(versionSection == null && section.size == count * 2L',
     'require(true && section.size == count * 2L'),
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def execute(argv):
    start = time.monotonic()
    result = subprocess.run(list(map(str, argv)), text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=40, check=False)
    if len(result.stdout.encode()) > 32768:
        raise RuntimeError("unexpectedly large mutation diagnostic")
    return result, round(time.monotonic() - start, 3)


def verify_outcome(label, run, mutant, oracle=None):
    """Only a behavioral assertion detects a fault; setup and oracle I/O failures do not."""
    outputs = [run] + ([] if oracle is None else [oracle])
    if any(word in result.stdout for result in outputs
           for word in ("ClassNotFoundException", "NoClassDefFoundError", "LinkageError")):
        raise AssertionError(f"{label}: class-loading failure is not a behavioral detection")
    if mutant:
        if run.returncode != 0 and "java.lang.AssertionError:" in run.stdout and oracle is None:
            return "java-assertion"
        if (run.returncode == 0 and oracle is not None and oracle.returncode != 0
                and re.search(r"(?m)^AssertionError(?::|$)", oracle.stdout)
                and "missing boundary/random profiles" not in oracle.stdout):
            return "independent-dwarf-oracle-assertion"
        raise AssertionError(f"{label}: no behavioral assertion detected mutation\n" +
                             "\n".join(result.stdout for result in outputs))
    if run.returncode != 0 or "=PASS" not in run.stdout:
        raise AssertionError(f"{label}: unchanged-source baseline failed\n{run.stdout}")
    if oracle is not None and (oracle.returncode != 0 or "call-value-dwarf-vm=PASS" not in oracle.stdout):
        raise AssertionError(f"{label}: independent DWARF baseline failed\n{oracle.stdout}")
    return "baseline-pass"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--classes", type=Path, required=True)
    parser.add_argument("--tests", type=Path, required=True)
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ghidra", type=Path, help="also check project protection, records, unwind and analyst selections using Ghidra's API/Gson")
    args = parser.parse_args()
    classes, tests, output = args.classes.resolve(), args.tests.resolve(), args.output.resolve()
    if not classes.is_dir() or not tests.is_dir():
        raise ValueError("compiled production and test directories are required")
    output.mkdir(parents=True, exist_ok=False)
    java, javac = args.java_home.resolve() / "bin/java", args.java_home.resolve() / "bin/javac"
    mutants = MUTANTS + ALLOCATION_BOUNDARY_MUTANTS + ELF_READER_MUTANTS + RUNTIME_RELOCATION_MUTANTS + REGISTER_MAP_MUTANTS + STRICT_REPORT_MUTANTS + PROGRAM_TYPE_MUTANTS + SECTIONLESS_MUTANTS + DYNAMIC_MUTANTS + FRAME_REREAD_MUTANTS + ORIGINAL_OBJECT_MUTANTS + FRAME_RANGE_MUTANTS + PUBLICATION_TIME_MUTANTS + ARM_MAPPING_MUTANTS + (PROJECT_MUTANTS + RECORD_MUTANTS + UNWIND_REPORT_MUTANTS + MMIO_MUTANTS + CXX_SELECTION_MUTANTS + RECEIPT_MUTANTS + SOURCE_FILES_MUTANTS + REPORT_CLAIMS_MUTANTS + TRANSACTION_MUTANTS + MIPS_ALLOCATION_MUTANTS + STACK_FLOW_MUTANTS + VTABLE_BINDING_MUTANTS + STATIC_RECOVERY_MUTANTS + BOUNDED_SWITCH_MUTANTS + ARM_MODE_INVENTORY_MUTANTS + CURATED_TYPE_MUTANTS + CALL_MEMORY_MUTANTS + CXX_PROFILE_MUTANTS + CALL_VALUE_MUTANTS + VALIDATOR_STATUS_MUTANTS + I386_ALLOCATION_MUTANTS + MERGED_LIFETIME_MUTANTS + STACK_CARRIER_MUTANTS + REGISTER_PROFILE_MUTANTS + MIXED_PREFIX_MUTANTS + BACKUP_READBACK_MUTANTS + REPORT_TEXT_MUTANTS + BUILD_ID_HELPER_MUTANTS + LINUX_METADATA_MUTANTS + LINUX_MOUNT_MUTANTS + STACK_SPILL_MUTANTS + TRUNCATED_DEPTH_MUTANTS + LOCAL_OWNERSHIP_MUTANTS + ATTACHMENT_PREVIEW_MUTANTS if args.ghidra else [])
    dependencies = sorted(args.ghidra.resolve().glob("Ghidra/**/lib/*.jar")) if args.ghidra else []
    if args.ghidra and not dependencies:
        raise ValueError("Ghidra installation libraries are required")
    sources = {row[1]: REPO / "src/main/java" / row[1] for row in mutants}
    original = {name: path.read_text() for name, path in sources.items()}
    hashes = {name: digest(path) for name, path in sources.items()}
    results = []
    peak = 0
    started = time.monotonic()

    def check(label, name, test, source, mutant):
        nonlocal peak
        with tempfile.TemporaryDirectory(prefix="classes-", dir=output) as temporary:
            root = Path(temporary)
            path = root / name
            path.parent.mkdir(parents=True)
            path.write_text(source)
            # The production publisher's private exception is never serialized;
            # its existing missing serialVersionUID is unrelated to these mutants.
            selected_dependencies = dependencies if test in (
                PROTECT_TEST, RECORDS_TEST, UNWIND_REPORT_TEST, MMIO_TEST, CXX_SELECTION_TEST,
                RECEIPT_TEST, RECEIPT_STORE_TEST, OPERATION_TEST, SOURCE_FILES_TEST, SOURCE_BUNDLE_TEST,
                REPORT_CLAIMS_TEST, TYPE_CLAIMS_TEST, TRANSACTION_TEST, MIPS_ALLOCATION_TEST, STACK_FLOW_TEST, VTABLE_BINDINGS_TEST, STATIC_RECOVERY_TEST, BOUNDED_SWITCH_TEST, ARM_MODE_INVENTORY_TEST, CURATED_TYPES_TEST, CALL_MEMORY_TEST, CXX_PROFILE_TEST, CALL_VALUE_TEST, VALIDATOR_STATUS_TEST, I386_ALLOCATION_TEST, MERGED_LIFETIME_TEST, STACK_CARRIER_TEST, REGISTER_PROFILE_TEST, MIXED_PREFIX_TEST, BACKUP_READBACK_TEST, REPORT_TEXT_TEST, BUILD_ID_HELPER_TEST, LINUX_METADATA_TEST, LINUX_APPLICATION_TEST, LINUX_MOUNT_TEST, STACK_SPILL_TEST, TRUNCATED_DEPTH_TEST, LOCAL_OWNERSHIP_TEST, LOCAL_PREFIX_TEST, ATTACHMENT_PREVIEW_TEST) else []
            compile_path = os.pathsep.join(map(str, [classes, *selected_dependencies]))
            # Distributed Ghidra dependency manifests reference optional jars not
            # shipped beside them. Suppress only that path warning for API tests;
            # missing API classes and every other compiler warning remain fatal.
            lint = "-Xlint:all,-serial,-path" if selected_dependencies else "-Xlint:all,-serial"
            # DynamicSymbolMirror already casts its int locals count to int.
            # That unchanged redundant cast is unrelated to version-identity
            # mutations; retain all other warnings as errors for this source.
            if name == DYNAMIC:
                lint += ",-cast"
            # GhidraTypeGraph's existing DataType.VOID reference is deprecated
            # by the pinned API. Its bytecode and that unrelated use remain
            # unchanged; retain every other warning as an error for this file.
            if name == CURATED_TYPES:
                lint += ",-deprecation"
            compiled, compile_seconds = execute([javac, lint, "-proc:none", "-Werror", "-cp", compile_path,
                                                 "-d", root, path])
            if compiled.returncode:
                raise AssertionError(f"{label}: compilation failed, not a detected mutant\n{compiled.stdout}")
            classpath = os.pathsep.join(map(str, [root, classes, tests, *selected_dependencies]))
            test_args = [args.ghidra.resolve()] if test in (PROTECT_TEST, MIPS_ALLOCATION_TEST, STACK_FLOW_TEST, VTABLE_BINDINGS_TEST, STATIC_RECOVERY_TEST, BOUNDED_SWITCH_TEST, CURATED_TYPES_TEST, CALL_MEMORY_TEST, CXX_PROFILE_TEST, I386_ALLOCATION_TEST, MERGED_LIFETIME_TEST, STACK_CARRIER_TEST, REGISTER_PROFILE_TEST, MIXED_PREFIX_TEST, STACK_SPILL_TEST, TRUNCATED_DEPTH_TEST, LOCAL_OWNERSHIP_TEST, LOCAL_PREFIX_TEST) else []
            if test == STRICT_REPORT_TEST:
                test_args.append(REPO / "src/test/fixtures/dwarfdump")
            if test == LINUX_MOUNT_TEST:
                test_args.append("--parser-only")
            if test == BOUNDED_SWITCH_TEST:
                test_args.append(root / "fixtures")
            if test == CALL_VALUE_TEST:
                test_args.append(root / "vectors.json")
            run, run_seconds = execute([java, "-Djava.io.tmpdir=" + str(root),
                "-Dapplication.settingsdir=" + str(root / "settings"), "-Djava.awt.headless=true",
                "-cp", classpath, test, *test_args])
            oracle, oracle_evidence = None, None
            if test == CALL_VALUE_TEST and run.returncode == 0:
                oracle, oracle_seconds = execute([sys.executable, "-B", CALL_VALUE_ORACLE, root / "vectors.json"])
                oracle_evidence = {"source": str(CALL_VALUE_ORACLE.relative_to(REPO)),
                    "sha256": digest(CALL_VALUE_ORACLE), "vectorsSha256": digest(root / "vectors.json"),
                    "exitCode": oracle.returncode, "seconds": oracle_seconds}
                run_seconds += oracle_seconds
            (output / (label + ".log")).write_text(run.stdout + ("\nIndependent DWARF oracle:\n" + oracle.stdout if oracle else ""))
            detection = verify_outcome(label, run, mutant, oracle)
            peak = max(peak, sum(p.stat().st_size for p in root.rglob("*") if p.is_file()))
            results.append({"label": label, "source": name, "test": test,
                            "status": "DETECTED" if mutant else "BASELINE_PASS",
                            "exitCode": run.returncode if oracle is None else oracle.returncode,
                            "detection": detection, "independentOracle": oracle_evidence,
                            "compileSeconds": compile_seconds, "testSeconds": run_seconds})

    for index, (name, test) in enumerate(dict.fromkeys((row[1], row[2]) for row in mutants)):
        check(f"baseline-{index}", name, test, original[name], False)
    for label, name, test, before, after in mutants:
        if original[name].count(before) != 1:
            raise AssertionError(f"{label}: mutation anchor is not unique; review source change")
        check(label, name, test, original[name].replace(before, after), True)
    if hashes != {name: digest(path) for name, path in sources.items()}:
        raise AssertionError("mutation run changed checkout sources")
    report = {"status": "PASS", "mutantsDetected": len(mutants), "sourceSha256": hashes,
              "elapsedSeconds": round(time.monotonic() - started, 3),
              "peakDisposableClassBytes": peak, "results": results,
              "scope": "Selected faults only; not a repository-wide mutation score"}
    (output / "result.json").write_text(json.dumps(report, indent=4) + "\n")
    print(json.dumps({key: report[key] for key in ("status", "mutantsDetected", "elapsedSeconds", "peakDisposableClassBytes")}))


if __name__ == "__main__":
    main()

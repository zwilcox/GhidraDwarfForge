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
UNWIND_ARITHMETIC = "ghidradwarfforge/unwind/UnwindFlow.java"
UNWIND_ARITHMETIC_TEST = "ghidradwarfforge.unwind.UnwindArithmeticSmoke"
UNWIND_MEMORY_TEST = "ghidradwarfforge.unwind.UnwindMemorySmoke"
UNWIND_CALL_MEMORY_TEST = "ghidradwarfforge.unwind.UnwindCallMemorySmoke"
UNWIND_CALL_MEMORY_MUTANTS = [
    ("unwind-call-ignores-write-bound", UNWIND_ARITHMETIC, UNWIND_CALL_MEMORY_TEST,
     "slot.offset() < bound", "false"),
    ("unwind-call-drops-exact-boundary-slot", UNWIND_ARITHMETIC, UNWIND_CALL_MEMORY_TEST,
     "slot.offset() < bound", "slot.offset() <= bound"),
    ("unwind-call-wraps-write-bound", UNWIND_ARITHMETIC, UNWIND_CALL_MEMORY_TEST,
     "Math.addExact(address.offset(), call.writeBound())", "address.offset() + call.writeBound()"),
    ("unwind-call-preserves-partial-register-alias", UNWIND_ARITHMETIC, UNWIND_CALL_MEMORY_TEST,
     "!call.preserved().contains(cell)", "call.preserved().stream().noneMatch(kept -> overlaps(kept, cell))"),
    ("unwind-call-forgets-stack-adjustment", UNWIND_ARITHMETIC, UNWIND_CALL_MEMORY_TEST,
     "plus(stack, new Constant(call.stackAdjustment(), stackPointer.bytes()), false, stackPointer.bytes())",
     "plus(stack, new Constant(0, stackPointer.bytes()), false, stackPointer.bytes())"),
    ("unwind-call-retains-released-memory", UNWIND_ARITHMETIC, UNWIND_CALL_MEMORY_TEST,
     "if (stackWritten) {", "if (false) {"),
    ("unwind-call-truncates-summary-adjustment", UNWIND_ARITHMETIC, UNWIND_CALL_MEMORY_TEST,
     "new Constant(call.stackAdjustment(), stackPointer.bytes()).signed() != call.stackAdjustment()", "false"),
]
UNWIND_MEMORY_MUTANTS = [
    ("unwind-memory-misses-last-byte-overlap", UNWIND_ARITHMETIC, UNWIND_MEMORY_TEST,
     "left <= right + rightBytes - 1", "left < right + rightBytes - 1"),
    ("unwind-memory-misses-first-byte-overlap", UNWIND_ARITHMETIC, UNWIND_MEMORY_TEST,
     "right <= left + leftBytes - 1", "right < left + leftBytes - 1"),
    ("unwind-memory-retains-unknown-store-aliases", UNWIND_ARITHMETIC, UNWIND_MEMORY_TEST,
     "else if (!separation.permits(address, store.bytes())) memory.clear();",
     "else if (!separation.permits(address, store.bytes())) { }"),
    ("unwind-memory-stores-mismatched-value-width", UNWIND_ARITHMETIC, UNWIND_MEMORY_TEST,
     "value != null && value.bytes() == store.bytes()", "value != null"),
    ("unwind-memory-reloads-adjacent-address", UNWIND_ARITHMETIC, UNWIND_MEMORY_TEST,
     "memory.get(new Slot(stack.offset(), output.bytes()))", "memory.get(new Slot(stack.offset() + 1, output.bytes()))"),
]
UNWIND_ARITHMETIC_MUTANTS = [
    ("unwind-arithmetic-ignores-left-width", UNWIND_ARITHMETIC, UNWIND_ARITHMETIC_TEST,
     "left.bytes() != bytes", "false"),
    ("unwind-arithmetic-ignores-right-width", UNWIND_ARITHMETIC, UNWIND_ARITHMETIC_TEST,
     "right.bytes() != bytes", "false"),
    ("unwind-arithmetic-commutes-subtraction", UNWIND_ARITHMETIC, UNWIND_ARITHMETIC_TEST,
     "!subtract && left instanceof Constant && !(right instanceof Constant)",
     "left instanceof Constant && !(right instanceof Constant)"),
    ("unwind-arithmetic-preserves-shifted-caller-value", UNWIND_ARITHMETIC, UNWIND_ARITHMETIC_TEST,
     "return offset == 0 ? left : null;", "return left;"),
    ("unwind-arithmetic-wraps-stack-offset", UNWIND_ARITHMETIC, UNWIND_ARITHMETIC_TEST,
     "Math.addExact(stack.offset(), offset)", "stack.offset() + offset"),
    ("unwind-arithmetic-exceeds-target-offset-width", UNWIND_ARITHMETIC, UNWIND_ARITHMETIC_TEST,
     "bytes < 8 && (offset <", "false && (offset <"),
]
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
INTRA_RAW = "ghidradwarfforge/IntraInstructionFlow.java"
FIRMWARE_MAP = "ghidradwarfforge/firmware/FirmwareMemoryMap.java"
FIRMWARE_MAP_TEST = "ghidradwarfforge.firmware.FirmwareMemoryMapSmoke"
MIPS_AGGREGATE = "ghidradwarfforge/elf/MipsAggregateCallPolicy.java"
MIPS_AGGREGATE_TEST = "ghidradwarfforge.elf.MipsAggregateCallPolicySmoke"
MIPS_SIGNATURE = "ghidradwarfforge/elf/MipsWideCallPolicy.java"
MIPS_SIGNATURE_TEST = "ghidradwarfforge.elf.MipsWideSignatureBoundarySmoke"
ARM_SIGNATURE = "ghidradwarfforge/elf/Arm32CallPolicy.java"
ARM_SIGNATURE_TEST = "ghidradwarfforge.elf.ArmCallSignatureBoundarySmoke"
ARM_ABI_METADATA = "ghidradwarfforge/elf/Arm32CallAbi.java"
ARM_ABI_METADATA_TEST = "ghidradwarfforge.elf.Arm32CallPolicySmoke"
SOURCE_DISPOSITION = "ghidradwarfforge/source/SyntheticSourceFile.java"
SOURCE_DISPOSITION_TEST = "ghidradwarfforge.source.SyntheticSourceDispositionSmoke"
INHERITANCE_BUDGET = "ghidradwarfforge/GhidraInheritanceBindings.java"
INHERITANCE_BUDGET_TEST = "ghidradwarfforge.InheritanceBudgetSmoke"
OMISSION_AUTHORITY_TEST = "ghidradwarfforge.AllocationOmissionAuthoritySmoke"
INTRA_RAW_TEST = "ghidradwarfforge.IntraInstructionBoundarySmoke"
CUSTOM_SCALAR = "ghidradwarfforge/GhidraCustomCallStorage.java"
CUSTOM_SCALAR_TEST = "ghidradwarfforge.CustomScalarCallStorageSmoke"
FRAME_DISCOVERY = "ghidradwarfforge/elf/SectionlessUnwind.java"
TRUNCATED_AFFINE_TEST = "ghidradwarfforge.TruncatedAffineBoundarySmoke"
DELAY_CONTRACT_TEST = "ghidradwarfforge.DelayedReturnPrefixSmoke"
COPY_CHAIN_IDENTITY_TEST = "ghidradwarfforge.RegisterCopyChainSmoke"
REGISTER_CONTROL_TEST = "ghidradwarfforge.RegisterControlBoundarySmoke"
FORMATTER_SELECTION_TEST = "ghidradwarfforge.formatters.FormatterPlanSmoke"
VALIDATOR_OBSERVATION_TEST = "ghidradwarfforge.output.ValidatorObservationBoundarySmoke"
INVOCATION_BOUNDARY_TEST = "ghidradwarfforge.output.AttachmentInvocationSmoke"
REPORT_INVENTORY_TEST = "ghidradwarfforge.output.ExportReportDetailsSmoke"
FIRMWARE_INPUT_TEST = "ghidradwarfforge.output.FirmwareInputsSmoke"
FRAME_CORROBORATE_TEST = "ghidradwarfforge.elf.InheritedFrameBytesSmoke"
FRAME_DISCOVERY_TEST = "ghidradwarfforge.elf.SectionlessUnwindBoundarySmoke"
RELOCATED_POINTER = "ghidradwarfforge/elf/ElfRelocatedPointers.java"
RELOCATED_POINTER_TEST = "ghidradwarfforge.elf.ElfRelocatedPointersSmoke"
FIRMWARE_CAPTURE = "ghidradwarfforge/firmware/GhidraFirmwareMemoryMap.java"
FIRMWARE_CAPTURE_TEST = "ghidradwarfforge.firmware.FirmwareCaptureConsistencySmoke"
ARM_HFA = "ghidradwarfforge/targets/ArmHfaParameterAllocation.java"
ARM_HFA_TEST = "ghidradwarfforge.ArmHfaAdmissionSmoke"
ARM_COMPOSITE = "ghidradwarfforge/targets/ArmCompositeParameterAllocation.java"
ARM_COMPOSITE_TEST = "ghidradwarfforge.ArmCompositeAdmissionSmoke"
UNWIND_CAPTURE = "ghidradwarfforge/unwind/GhidraUnwindInstructions.java"
UNWIND_CAPTURE_TEST = "ghidradwarfforge.unwind.UnwindCaptureAdmissionSmoke"
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
BUILD_ID_LOCK = "ghidradwarfforge/output/BuildIdFileLock.java"
BUILD_ID_LOCK_TEST = "ghidradwarfforge.output.BuildIdFileLockSmoke"
LOCAL_MAPPING = "ghidradwarfforge/GhidraLocalMappings.java"
LOCAL_MAPPING_TEST = "ghidradwarfforge.LocalMappingsSmoke"
TARGET_STORE = "ghidradwarfforge/output/AttachmentTargetStore.java"
TARGET_STORE_TEST = "ghidradwarfforge.output.AttachmentTargetStoreSmoke"
MIPS_ALLOCATION = "ghidradwarfforge/targets/MipsWideParameterAllocation.java"
MIPS_ALLOCATION_TEST = "ghidradwarfforge.MipsN32ParameterAllocationSmoke"
STACK_FLOW = "ghidradwarfforge/StackValueFlow.java"
STACK_FLOW_TEST = "ghidradwarfforge.RegisterByteSliceFlowSmoke"
STACK_TRANSFER_TEST = "ghidradwarfforge.StackTransferShapeSmoke"
STACK_CARRIER_TEST = "ghidradwarfforge.StackValueFlowSmoke"
STACK_LOCAL_TEST = "ghidradwarfforge.StackLocalLifetimeSmoke"
STACK_LOCAL = "ghidradwarfforge/StackLocalLifetime.java"
INDIRECT_METADATA_TEST = "ghidradwarfforge.IndirectParameterStorageSmoke"
STORAGE_REFINEMENT_TEST = "ghidradwarfforge.StorageRefinementSmoke"
VTABLE_BINDINGS = "ghidradwarfforge/GhidraVtableBindings.java"
VTABLE_BINDINGS_TEST = "ghidradwarfforge.VtableBindingEvidenceSmoke"
STATIC_RECOVERY = "ghidradwarfforge/GhidraStaticRecovery.java"
STATIC_RECOVERY_TEST = "ghidradwarfforge.StaticRecoverySmoke"
LEXICAL_RECORD_TEST = "ghidradwarfforge.LexicalScopeEvidenceSmoke"
STATIC_BINDING_TEST = "ghidradwarfforge.StaticBindingEvidenceSmoke"
BOUNDED_SWITCH = "ghidradwarfforge/calls/GhidraBoundedSwitch.java"
BOUNDED_SWITCH_TEST = "ghidradwarfforge.calls.BoundedSwitchProofSmoke"
ARM_MODE_INVENTORY = "ghidradwarfforge/elf/Arm32FunctionAliasSymbols.java"
ARM_MODE_INVENTORY_TEST = "ghidradwarfforge.elf.Arm32FunctionAliasSymbolsSmoke"
ARM_MODE_SYMBOLS = "ghidradwarfforge/elf/Arm32ModeSymbols.java"
ARM_MODE_SYMBOLS_TEST = "ghidradwarfforge.elf.Arm32ModeSymbolsSmoke"
ARM_SAVED_MODES = "ghidradwarfforge/GhidraArm32FunctionModes.java"
ARM_SAVED_MODES_TEST = "ghidradwarfforge.GhidraArm32FunctionModesSmoke"
ARM_SECTION_EVIDENCE = "ghidradwarfforge/GhidraArm32SectionModes.java"
ARM_SECTION_EVIDENCE_TEST = "ghidradwarfforge.GhidraArm32SectionModesSmoke"
CURATED_TYPES = "ghidradwarfforge/GhidraTypeGraph.java"
CURATED_TYPES_TEST = "ghidradwarfforge.FloatingTypeLayoutSmoke"
TYPE_IDENTITY_TEST = "ghidradwarfforge.DefaultTypeIdentitySmoke"
TARGET_DESCRIPTOR_TEST = "ghidradwarfforge.nativeapi.DwarfTargetSmoke"
CALL_MEMORY = "ghidradwarfforge/CallMemoryEffects.java"
CALL_MEMORY_TEST = "ghidradwarfforge.CallMemoryEffectsSmoke"
CALL_PARAMETERS = "ghidradwarfforge/GhidraCallParameters.java"
CALL_PARAMETERS_TEST = "ghidradwarfforge.calls.GhidraCallArgumentFlowSmoke"

CXX_PROFILE = "ghidradwarfforge/GhidraCxxProfile.java"
CXX_PROFILE_TEST = "ghidradwarfforge.CxxProfileSmoke"
CALL_VALUE = "ghidradwarfforge/calls/CallValue.java"
CALL_VALUE_TEST = "ghidradwarfforge.calls.CallValueSmoke"
CALL_VALUE_ORACLE = REPO / "src/test/integration/check-call-values.py"
VALIDATOR_STATUS = "ghidradwarfforge/output/ValidatorSupervisor.java"
VALIDATOR_STATUS_TEST = "ghidradwarfforge.output.ValidatorStatusBoundarySmoke"
VALIDATOR_PROVENANCE_TEST = "ghidradwarfforge.output.ValidatorLaunchBoundarySmoke"
REPORT_LEXICAL = "ghidradwarfforge/output/ReportJsonReader.java"
REPORT_LEXICAL_TEST = "ghidradwarfforge.output.ReportValueReaderSmoke"
REPORT_LEXICAL_MUTANTS = [
    ("report-limit-accepts-zero-" + field, REPORT_LEXICAL, REPORT_LEXICAL_TEST,
     field + " < 1", field + " < 0")
    for field in ("bytes", "stringUnits", "depth", "values", "arrayItems", "coverageValues", "totalValues")
] + [
    ("report-null-spelling-ignored", REPORT_LEXICAL, REPORT_LEXICAL_TEST,
     'character != "null".charAt(bareLength++)', 'bareLength++ < 0'),
    ("report-zero-read-enters-decoder", REPORT_LEXICAL, REPORT_LEXICAL_TEST,
     'checkCancelled(cancelled);\n        if (length == 0)', 'checkCancelled(cancelled);\n        if (false)'),
    ("report-replaces-malformed-utf8", REPORT_LEXICAL, REPORT_LEXICAL_TEST,
     '.onMalformedInput(CodingErrorAction.REPORT)', '.onMalformedInput(CodingErrorAction.REPLACE)'),
    ("report-accepts-unmatched-container-close", REPORT_LEXICAL, REPORT_LEXICAL_TEST,
     'throw invalid("unmatched closing container");', 'depth = 0;'),
    ("report-accepts-unfinished-container", REPORT_LEXICAL, REPORT_LEXICAL_TEST,
     'inString || depth != 0', 'inString'),
]
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
AARCH64_ALLOCATION = "ghidradwarfforge/targets/Aarch64ParameterAllocation.java"
AARCH64_ALLOCATION_TEST = "ghidradwarfforge.Aarch64ParameterAllocationSmoke"
AARCH64_ALLOCATION_MUTANTS = [
    ("aarch64-allocation-loses-typedef", AARCH64_ALLOCATION, AARCH64_ALLOCATION_TEST,
     'type = alias.getBaseDataType();', 'break;'),
    ("aarch64-allocation-rejects-nine-bytes", AARCH64_ALLOCATION, AARCH64_ALLOCATION_TEST,
     'type.getLength() < 9', 'type.getLength() < 10'),
    ("aarch64-allocation-rejects-sixteen-bytes", AARCH64_ALLOCATION, AARCH64_ALLOCATION_TEST,
     'type.getLength() > 16', 'type.getLength() > 15'),
]

MERGED_LIFETIME = "ghidradwarfforge/MergedLocalLifetime.java"
MERGED_LIFETIME_TEST = "ghidradwarfforge.MergedLocalLifetimeSmoke"
REGISTER_PROFILE = "ghidradwarfforge/GhidraVariableStorage.java"
REGISTER_PROFILE_TEST = "ghidradwarfforge.RegisterAliasSmoke"
ALLOCATION_OVERRIDE = "ghidradwarfforge/GhidraAllocationDecompiler.java"
ALLOCATION_OVERRIDE_TEST = "ghidradwarfforge.AllocationDecompilerSmoke"
ALLOCATION_OVERRIDE_MUTANTS = [
    ("allocation-override-accepts-unknown-parameter", ALLOCATION_OVERRIDE, ALLOCATION_OVERRIDE_TEST,
     'if (!parameter.id().equals(ELEM_PARAM))', 'if (false)'),
    ("allocation-override-discards-address-children", ALLOCATION_OVERRIDE, ALLOCATION_OVERRIDE_TEST,
     '!address.attributes().isEmpty() || !address.children().isEmpty()', '!address.attributes().isEmpty()'),
    ("allocation-view-omits-explicit-parameter", ALLOCATION_OVERRIDE, ALLOCATION_OVERRIDE_TEST,
     'if (!parameter.isAutoParameter())', 'if (false)'),
]
CALL_EVIDENCE = "ghidradwarfforge/calls/GhidraCallSiteEvidence.java"
CALL_EVIDENCE_TEST = "ghidradwarfforge.calls.GhidraCallSiteEvidenceSmoke"
CALL_EVIDENCE_MUTANTS = [
    ("call-evidence-accepts-delay-owner", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "instruction.getDelaySlotDepth() == 0 &&", "true &&"),
    ("call-evidence-accepts-delay-slot", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "!instruction.isInDelaySlot()", "true"),
    ("call-evidence-ignores-parsed-byte-count", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "parsed.length == instruction.getLength() &&", "true &&"),
    ("call-evidence-ignores-short-read", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "program.getMemory().getBytes(address, live) == live.length", "program.getMemory().getBytes(address, live) >= 0"),
    ("call-evidence-accepts-nonadjacent-return-pc", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "Objects.equals(instruction.getFallThrough(), instruction.getMaxAddress().next())", "true"),
    ("call-evidence-accepts-transfer-output", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "transfer.output() == null && !transfer.inputs().isEmpty()", "!transfer.inputs().isEmpty()"),
    ("call-evidence-accepts-extra-call-operand", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "transfer.inputs().size() == 1 &&", "true &&"),
    ("call-evidence-accepts-effects-after-call", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "operations.getLast() == transfer &&", "true &&"),
    ("call-evidence-ignores-conditional-internal-flow", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "operations.stream().noneMatch(operation -> operation.opcode() == PcodeOp.BRANCH ||\n"
     "                operation.opcode() == PcodeOp.CBRANCH)",
     "operations.stream().noneMatch(operation -> operation.opcode() == PcodeOp.BRANCH)"),
    ("call-evidence-trusts-contradictory-target", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "targets.getFirst().equals(transfer.inputs().getFirst().address()) &&", "true &&"),
    ("call-evidence-accepts-excess-raw-operations", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "raw.length > 4096", "raw.length > 4097"),
    ("call-evidence-ignores-branch-condition", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     "(opcode == PcodeOp.CBRANCH) == flow.isConditional()", "true"),
    ("call-evidence-rejects-exact-body-budget", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     'body.getNumAddresses() > 1_048_576', 'body.getNumAddresses() >= 1_048_576'),
    ("call-evidence-accepts-foreign-function", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     'if (function.getProgram() != program)', 'if (false)'),
    ("call-evidence-ignores-escaping-fallthrough", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     'instruction.fallThrough() != null && !starts.contains(instruction.fallThrough())', 'false'),
    ("call-evidence-accepts-interior-branch-boundary", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     'instruction.transfer().kind() == Kind.INTERNAL_BRANCH && !starts.contains(instruction.transfer().target())', 'false'),
    ("call-evidence-accepts-overridden-length", CALL_EVIDENCE, CALL_EVIDENCE_TEST,
     'instruction.getLength() == instruction.getParsedLength() && !instruction.isLengthOverridden()', 'true'),
]
DYNAMIC_STORAGE_TEST = "ghidradwarfforge.DynamicParameterStorageSmoke"
DYNAMIC_STORAGE_MUTANTS = [
    ("parameter-unnamed-slice-ignores-formal-width", REGISTER_PROFILE, DYNAMIC_STORAGE_TEST,
     'node.getSize() == parameter.getLength() &&\n'
     '                    storage.size() == parameter.getLength()', 'true'),
    ("parameter-named-register-ignores-required-width", REGISTER_PROFILE, DYNAMIC_STORAGE_TEST,
     'requiredBits > register.getBitLength() ||', ''),
    ("parameter-byte-slice-crosses-container", "ghidradwarfforge/RegisterByteSlice.java", DYNAMIC_STORAGE_TEST,
     'offset <= register.getMinimumByteSize() - node.getSize()',
     'offset <= register.getMinimumByteSize()'),
]
CLOSED_FLOW_TEST = "ghidradwarfforge.ClosedFlowBoundarySmoke"
COMPOSITE_FLOW = "ghidradwarfforge/CompositeValueFlow.java"
COMPOSITE_FLOW_TEST = "ghidradwarfforge.CompositeValueFlowSmoke"
COMPOSITE_FLOW_MUTANTS = [
    ("composite-metadata-ignores-owner", COMPOSITE_FLOW, COMPOSITE_FLOW_TEST,
     'parameter.getFunction() != function ||', ''),
    ("composite-metadata-accepts-negative-ordinal", COMPOSITE_FLOW, COMPOSITE_FLOW_TEST,
     'parameter.getOrdinal() < 0 ||', ''),
    ("composite-metadata-accepts-detached-parameter", COMPOSITE_FLOW, COMPOSITE_FLOW_TEST,
     'function.getParameter(parameter.getOrdinal()) != parameter ||', ''),
    ("composite-metadata-ignores-first-use", COMPOSITE_FLOW, COMPOSITE_FLOW_TEST,
     'parameter.getFirstUseOffset() != 0 ||', ''),
    ("composite-metadata-ignores-formal-size", COMPOSITE_FLOW, COMPOSITE_FLOW_TEST,
     'formal.getLength() != bytes ||', ''),
    ("composite-emits-body-hole", COMPOSITE_FLOW, COMPOSITE_FLOW_TEST,
     'if (!covered) continue;', 'if (false) continue;'),
    ("composite-merges-across-body-hole", COMPOSITE_FLOW, COMPOSITE_FLOW_TEST,
     'result.getLast().end() == start && result.getLast().storage().equals(value)',
     'result.getLast().storage().equals(value)'),
]
CLOSED_FLOW_MUTANTS = [
    ("closed-flow-accepts-negative-delay-depth", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     "instruction.getDelaySlotDepth() < 0) {", "false) {"),
    ("closed-flow-accepts-shared-delay-slot", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     "delayOwners.put(next, instruction.getAddress()) != null",
     "(delayOwners.put(next, instruction.getAddress()) != null && false)"),
    ("closed-flow-accepts-entry-in-delay-slot", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     "if (delayOwners.containsKey(function.getEntryPoint()))", "if (false)"),
    ("closed-flow-accepts-orphan-delay-slot", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     "!delayOwners.containsKey(instruction.getAddress())", "false"),
    ("closed-flow-ignores-slot-default-targets", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     "(defaults != null && defaults.length != 0) ||\n"
     "                        (references != null && references.length != 0)",
     "(references != null && references.length != 0)"),
    ("closed-flow-accepts-branch-into-delay-slot", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     "!decoded.containsKey(target) || delayOwners.containsKey(target)", "!decoded.containsKey(target)"),
    ("closed-flow-accepts-return-without-return-op", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     "operations[operations.length - 1].getOpcode() != PcodeOp.RETURN", "false"),
    ("closed-flow-accepts-conditional-return", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     'if (flow.isConditional() || flow.isJump() || flow.hasFallthrough() ||\n'
     '                        operations.length == 0 ||\n'
     '                        operations[operations.length - 1].getOpcode() != PcodeOp.RETURN)',
     'if (false)'),
    ("closed-flow-ignores-slot-references", REGISTER_PROFILE, CLOSED_FLOW_TEST,
     '(defaults != null && defaults.length != 0) ||\n'
     '                        (references != null && references.length != 0)',
     '(defaults != null && defaults.length != 0)'),
]
REGISTER_MAP = "ghidradwarfforge/locations/TargetRegisterMap.java"
LEXICAL_SCOPE = "ghidradwarfforge/types/LexicalScopeModel.java"
LEXICAL_SCOPE_TEST = "ghidradwarfforge.types.LexicalScopeBoundarySmoke"
CLASS_EVIDENCE_TEST = "ghidradwarfforge.types.ClassEvidenceBoundarySmoke"
CLASS_EVIDENCE_MUTANTS = [
    ("vtable-accepts-inferred-owner", "ghidradwarfforge/types/ClassScopeModel.java", CLASS_EVIDENCE_TEST,
     "binding.source() == BindingSource.EXPLICIT_SAVED", "true"),
    ("vtable-accepts-wrong-abi", "ghidradwarfforge/types/ClassScopeModel.java", CLASS_EVIDENCE_TEST,
     "table.abi() != inheritance.abi()", "false"),
    ("vtable-address-wraps", "ghidradwarfforge/types/VtableEvidence.java", CLASS_EVIDENCE_TEST,
     "Math.addExact(address, byteSize);", "// Fault: unchecked address extent."),
    ("vtable-file-offset-wraps", "ghidradwarfforge/types/VtableEvidence.java", CLASS_EVIDENCE_TEST,
     "Math.addExact(fileOffset, byteSize);", "// Fault: unchecked file extent."),
]
LEXICAL_SCOPE_MUTANTS = [
    ("lexical-scope-extends-location-end", LEXICAL_SCOPE, LEXICAL_SCOPE_TEST,
     'long end = Math.min(visible.endExclusive(), old.end());',
     'long end = Math.max(visible.endExclusive(), old.end());'),
    ("lexical-scope-drops-unproved-prefix", LEXICAL_SCOPE, LEXICAL_SCOPE_TEST,
     'if (cursor < start) ranges.add(unavailable(cursor, start));', ''),
]
REGISTER_MAP_TEST = "ghidradwarfforge.locations.VariableStorageSmoke"
RUNTIME_RELOCATIONS = "ghidradwarfforge/elf/ElfRuntimeRelocations.java"
RUNTIME_RELOCATIONS_TEST = "ghidradwarfforge.elf.ElfRuntimeRelocationsSmoke"
RELOCATION_EFFECTS = "ghidradwarfforge/elf/ElfRelocationEffects.java"
RELOCATION_EFFECTS_TEST = "ghidradwarfforge.elf.ElfRelocationEffectsSmoke"
ELF_READER = "ghidradwarfforge/elf/ElfImage.java"
ELF_BUILD_ID = "ghidradwarfforge/elf/ElfBuildId.java"
ELF_BUILD_ID_TEST = "ghidradwarfforge.elf.ElfBuildIdSmoke"
ELF_READER_TEST = "ghidradwarfforge.elf.ElfImageReaderSmoke"
ALLOCATIONS = "ghidradwarfforge/elf/MatchedElfAllocations.java"
ALLOCATIONS_TEST = "ghidradwarfforge.elf.MatchedElfAllocationsSmoke"
ALLOCATION_CHANGE_MUTANTS = [
    ("allocation-misses-original-size-race", ALLOCATIONS, ALLOCATIONS_TEST,
     'before.fileSize() != originalState.size()', 'false'),
    ("allocation-misses-candidate-size-race", ALLOCATIONS, ALLOCATIONS_TEST,
     'after.fileSize() != candidateState.size()', 'false'),
    ("allocation-misses-late-size-change", ALLOCATIONS, ALLOCATIONS_TEST,
     'before.size() != after.size()', 'false'),
    ("allocation-misses-late-time-change", ALLOCATIONS, ALLOCATIONS_TEST,
     '!before.lastModifiedTime().equals(after.lastModifiedTime())', 'false'),
    ("allocation-misses-late-file-replacement", ALLOCATIONS, ALLOCATIONS_TEST,
     '!Objects.equals(before.fileKey(), after.fileKey())', 'false'),
    ("allocation-misses-name-table-start-change", ALLOCATIONS, ALLOCATIONS_TEST,
     'bytes[0] != 0', 'false'),
    ("allocation-misses-name-table-end-change", ALLOCATIONS, ALLOCATIONS_TEST,
     'bytes[bytes.length - 1] != 0', 'false'),
]
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
GDB_COMPANION = "ghidradwarfforge/elf/GdbCompanion.java"
GDB_COMPANION_TEST = "ghidradwarfforge.elf.GdbCompanionSmoke"
GDB_COMPANION_MUTANTS = [
    ("companion-accepts-writable-executable", GDB_COMPANION, GDB_COMPANION_TEST,
     "(segment.flags & 2) != 0", "false"),
    ("companion-accepts-excess-loads", GDB_COMPANION, GDB_COMPANION_TEST,
     "loads.size() > MAX_SEGMENTS", "false"),
    ("companion-accepts-excess-probes", GDB_COMPANION, GDB_COMPANION_TEST,
     "probes.size() > MAX_SEGMENTS", "false"),
    ("companion-accepts-no-executable", GDB_COMPANION, GDB_COMPANION_TEST,
     "!executable ||", "false ||"),
    ("companion-ignores-runtime-byte-budget", GDB_COMPANION, GDB_COMPANION_TEST,
     "probe.size() > MAX_CHECK_BYTES - total", "false"),
    ("companion-skips-elf32-header-identity-byte", GDB_COMPANION, GDB_COMPANION_TEST,
     "{{32, 36}, {46, 52}}", "{{32, 37}, {46, 52}}"),
    ("companion-omits-mapped-header-identity", GDB_COMPANION, GDB_COMPANION_TEST,
     "segment.fileSize >= image.headerBytes().length", "false"),
]

ELF_BUILD_ID_MUTANTS = [
    ("build-id-ignores-following-padding-overlap", ELF_BUILD_ID, ELF_BUILD_ID_TEST,
     "following != null && following.getKey() < end", "false"),
    ("build-id-ignores-later-record-overlap", ELF_BUILD_ID, ELF_BUILD_ID_TEST,
     "after != null && after.getKey() < layout.end", "false"),
    ("build-id-accepts-container-overflow", ELF_BUILD_ID, ELF_BUILD_ID_TEST,
     "size > Long.MAX_VALUE - offset", "false"),
    ("build-id-accepts-oversized-occurrence", ELF_BUILD_ID, ELF_BUILD_ID_TEST,
     "descriptorSize > MAX_BUILD_ID_BYTES", "false"),
    ("build-id-accepts-invalid-observation-hex", ELF_BUILD_ID, ELF_BUILD_ID_TEST,
     '!hex.get().matches("[0-9a-f]+")', "false"),
]

ELF_READER_MUTANTS = [
    ("elf-reader-ignores-magic-byte", ELF_READER, ELF_READER_TEST,
     "ident[2] != 'L'", 'false'),
    ("elf-reader-allows-header-overlap", ELF_READER, ELF_READER_TEST,
     'sectionOffset < encodedHeaderSize', 'false'),
    ("elf-reader-allows-dangling-name-index", ELF_READER, ELF_READER_TEST,
     'encodedCount != 0 || encodedNameIndex != 0', 'encodedCount != 0'),
]
RELOCATION_EFFECTS_MUTANTS = [
    ("relocation-effects-assigns-file-bytes-to-bss", RELOCATION_EFFECTS, RELOCATION_EFFECTS_TEST,
     "Math.min(size, Math.max(0, selected.fileSize() - delta))", "size"),
    ("relocation-effects-rejects-weak-copy", RELOCATION_EFFECTS, RELOCATION_EFFECTS_TEST,
     "entry.info() >>> 4 == 2", "false"),
    ("relocation-effects-rejects-empty-file-query", RELOCATION_EFFECTS, RELOCATION_EFFECTS_TEST,
     "require(size == 0 || write.fileBytes() == 0 ||", "require(write.fileBytes() == 0 ||"),
    ("relocation-effects-invents-zero-size-write", RELOCATION_EFFECTS, RELOCATION_EFFECTS_TEST,
     "if (size == 0) continue;", "if (false) continue;"),
    ("relocation-effects-rejects-zero-absent-prefix", RELOCATION_EFFECTS, RELOCATION_EFFECTS_TEST,
     "count == 0 || table.isPresent()", "table.isPresent()"),
    ("relocation-effects-trusts-unqualified-sframe", RELOCATION_EFFECTS, RELOCATION_EFFECTS_TEST,
     '!section.name.equals(".sframe") || section.size == 0', 'true'),
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
    ("mixed-metadata-ignores-first-use", REGISTER_PROFILE, MIXED_PREFIX_TEST,
     'parameter.getFirstUseOffset() != 0 ||\n                bytes <= 0', 'bytes <= 0'),
    ("mixed-metadata-ignores-formal-size", REGISTER_PROFILE, MIXED_PREFIX_TEST,
     'formal.getLength() != bytes ||\n                storage.size()', 'storage.size()'),
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
LINUX_CANARY_TEST = "ghidradwarfforge.output.LinuxMetadataVisibilitySmoke"
LINUX_METADATA_MUTANTS = [
    ("metadata-canary-ignores-links", LINUX_METADATA, LINUX_CANARY_TEST,
     'expected.facts().links() == 1', 'true'),
    ("metadata-policy-ignores-extent-size", LINUX_METADATA, LINUX_CANARY_TEST,
     'inode.extentSize() == 0', 'true'),
    ("metadata-policy-ignores-project-id", LINUX_METADATA, LINUX_CANARY_TEST,
     'inode.projectId() == 0', 'true'),
    ("metadata-policy-ignores-cow-extent-size", LINUX_METADATA, LINUX_CANARY_TEST,
     'inode.cowExtentSize() == 0', 'true'),
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
    ("stack-spill-ignores-instruction-space", STACK_SPILL, STACK_SPILL_TEST,
     "instruction.getAddress().getAddressSpace() != code ||", ""),
    ("stack-spill-ignores-instruction-extent", STACK_SPILL, STACK_SPILL_TEST,
     "next != Math.addExact(instruction.getAddress().getOffset(), instruction.getLength()) ||", ""),
    ("stack-spill-ignores-return-output", STACK_SPILL, STACK_SPILL_TEST,
     "index != operations.length - 1 || operation.getOutput() != null ||", "index != operations.length - 1 ||"),
    ("stack-spill-ignores-return-width", STACK_SPILL, STACK_SPILL_TEST,
     "operation.getInput(0).getSize() != code.getPointerSize()", "false"),
    ("stack-spill-accepts-extra-return-operand", STACK_SPILL, STACK_SPILL_TEST,
     "operation.getNumInputs() != 1 ||", "operation.getNumInputs() < 1 ||"),
    ("stack-spill-allows-effects-after-return", STACK_SPILL, STACK_SPILL_TEST,
     "index != operations.length - 1 ||", ""),
    ("spill-ignores-signed-pointer-width", STACK_SPILL, STACK_SPILL_TEST,
     'long delta = (second.getOffset() << shift) >> shift;', 'long delta = second.getOffset();'),
    ("spill-accepts-narrow-displacement-overflow", STACK_SPILL, STACK_SPILL_TEST,
     '((offset << shift) >> shift) == offset', 'true'),
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
    ("symbol-inventory-accepts-oversized-name", ORIGINAL_OBJECTS, ORIGINAL_OBJECTS_TEST,
     'end - nameIndex > ElfImage.MAX_NAME_BYTES ||', ''),
    ("symbol-inventory-ignores-decoded-name-budget", ORIGINAL_OBJECTS, ORIGINAL_OBJECTS_TEST,
     '(nameBytes += end - nameIndex) > ElfImage.MAX_NAME_TABLE_BYTES', 'false'),
    ("symbol-inventory-accepts-zero-extended-index", ORIGINAL_OBJECTS, ORIGINAL_OBJECTS_TEST,
     'extra == null || extendedIndex == 0 || extendedIndex >= image.sections().size()',
     'extra == null || extendedIndex >= image.sections().size()'),
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
LOCAL_PREFIX_ADMISSION = '        if (!(rejected instanceof UnavailableStorage unavailable) ||\n                unavailable.reason() != OmissionReason.UNKNOWN_LIFETIME ||\n                !(variable instanceof ghidra.program.model.listing.LocalVariable) ||\n                variable.getSource() != ghidra.program.model.symbol.SourceType.USER_DEFINED ||\n                variable.getProgram() != program || variable.getFunction() != function ||\n                function.getProgram() != program || variable.getFirstUseOffset() <= 0 ||\n                !variable.isValid() || !variable.hasAssignedStorage() || storage == null ||\n                storage.getProgramArchitecture() != program || !storage.isValid() ||\n                storage.isBadStorage() || storage.isForcedIndirect() || !storage.isRegisterStorage() ||\n                storage.getVarnodeCount() != 1 || register == null || variable.getLength() <= 0 ||\n                variable.getDataType().getLength() != variable.getLength() ||\n                storage.size() != variable.getLength() ||\n                register.getBitLength() != variable.getLength() * 8L ||\n                !storage.getFirstVarnode().getAddress().equals(register.getAddress()) ||\n                function.getBody().getNumAddressRanges() != 1 ||\n                !function.getEntryPoint().equals(function.getBody().getMinAddress())) {\n'
LOCAL_OWNERSHIP_MUTANTS = [
    ("local-definition-ignores-validity", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     '!variable.isValid() || ', ""),
    ("local-definition-ignores-assignment", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     '!variable.hasAssignedStorage() || ', ""),
    ("local-definition-ignores-type-extent", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     'variable.getDataType().getLength() != variable.getLength() ||', ""),
    ("local-definition-ignores-foreign-storage", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     'storage.getProgramArchitecture() != program || ', ""),
    ("local-definition-ignores-indirect-storage", LOCAL_OWNERSHIP, LOCAL_OWNERSHIP_TEST,
     'storage.isForcedIndirect() || ', ""),
    ("local-prefix-ignores-validity", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST, LOCAL_PREFIX_ADMISSION, LOCAL_PREFIX_ADMISSION.replace('!variable.isValid() || ', "")),
    ("local-prefix-ignores-assignment", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST, LOCAL_PREFIX_ADMISSION, LOCAL_PREFIX_ADMISSION.replace('!variable.hasAssignedStorage() || ', "")),
    ("local-prefix-ignores-type-extent", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST, LOCAL_PREFIX_ADMISSION, LOCAL_PREFIX_ADMISSION.replace('variable.getDataType().getLength() != variable.getLength() ||', "")),
    ("local-prefix-ignores-foreign-storage", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST, LOCAL_PREFIX_ADMISSION, LOCAL_PREFIX_ADMISSION.replace('storage.getProgramArchitecture() != program || ', "")),
    ("local-prefix-ignores-indirect-storage", "ghidradwarfforge/GhidraVariableStorage.java",
     LOCAL_PREFIX_TEST, LOCAL_PREFIX_ADMISSION, LOCAL_PREFIX_ADMISSION.replace('storage.isForcedIndirect() || ', "")),

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
DELAY_CONTRACT_MUTANTS = [
    ("delay-contract-ignores-owner-length", "ghidradwarfforge/GhidraVariableStorage.java", DELAY_CONTRACT_TEST,
     "owner.isFallThroughOverridden() || owner.getLength() <= 0 ||", "owner.isFallThroughOverridden() ||"),
    ("delay-contract-ignores-owner-parsed-length", "ghidradwarfforge/GhidraVariableStorage.java", DELAY_CONTRACT_TEST,
     "owner.getLength() != owner.getParsedLength()", "false"),
    ("delay-contract-ignores-slot-adjacency", "ghidradwarfforge/GhidraVariableStorage.java", DELAY_CONTRACT_TEST,
     "!next.equals(delayed.getAddress()) ||", ""),
    ("delay-contract-ignores-slot-extent", "ghidradwarfforge/GhidraVariableStorage.java", DELAY_CONTRACT_TEST,
     "delayed.getMaxAddress().getOffset() + 1 != delayed.getAddress().getOffset() + delayed.getLength()", "false"),
    ("delay-contract-ignores-slot-fallthrough", "ghidradwarfforge/GhidraVariableStorage.java", DELAY_CONTRACT_TEST,
     "if (next == null || !next.equals(delayed.getFallThrough())) return -1;", "if (next == null) return -1;"),
    ("delay-contract-invents-undecoded-tail", "ghidradwarfforge/GhidraVariableStorage.java", DELAY_CONTRACT_TEST,
     "return next.getOffset() == end ? end : -1;", "return end;"),
]

COPY_CHAIN_CONDITION = 'while (boundary < end && backup.bits() != null &&\n                    function.getProgram() == program && storage.getProgramArchitecture() == program &&\n                    parameter.getFunction() == function && parameter.getOrdinal() >= 0 &&\n                    function.getParameter(parameter.getOrdinal()) == parameter && parameter.getFirstUseOffset() == 0 &&\n                    storage.isValid() && !storage.isBadStorage() && !storage.isForcedIndirect()) {'
COPY_CHAIN_IDENTITY_MUTANTS = [
    ("copy-chain-ignores-function-program", "ghidradwarfforge/GhidraVariableStorage.java", COPY_CHAIN_IDENTITY_TEST,
        COPY_CHAIN_CONDITION, COPY_CHAIN_CONDITION.replace('function.getProgram() == program && ', "")),
    ("copy-chain-ignores-storage-program", "ghidradwarfforge/GhidraVariableStorage.java", COPY_CHAIN_IDENTITY_TEST,
        COPY_CHAIN_CONDITION, COPY_CHAIN_CONDITION.replace('storage.getProgramArchitecture() == program &&', "")),
    ("copy-chain-ignores-parameter-function", "ghidradwarfforge/GhidraVariableStorage.java", COPY_CHAIN_IDENTITY_TEST,
        COPY_CHAIN_CONDITION, COPY_CHAIN_CONDITION.replace('parameter.getFunction() == function && ', "")),
    ("copy-chain-ignores-parameter-ordinal", "ghidradwarfforge/GhidraVariableStorage.java", COPY_CHAIN_IDENTITY_TEST,
        COPY_CHAIN_CONDITION, COPY_CHAIN_CONDITION.replace('parameter.getOrdinal() >= 0 &&', "")),
    ("copy-chain-ignores-saved-row", "ghidradwarfforge/GhidraVariableStorage.java", COPY_CHAIN_IDENTITY_TEST,
        COPY_CHAIN_CONDITION, COPY_CHAIN_CONDITION.replace('function.getParameter(parameter.getOrdinal()) == parameter && ', "")),
    ("copy-chain-ignores-first-use", "ghidradwarfforge/GhidraVariableStorage.java", COPY_CHAIN_IDENTITY_TEST,
        COPY_CHAIN_CONDITION, COPY_CHAIN_CONDITION.replace('parameter.getFirstUseOffset() == 0 &&', "")),
    ("copy-chain-ignores-indirect-storage", "ghidradwarfforge/GhidraVariableStorage.java", COPY_CHAIN_IDENTITY_TEST,
        COPY_CHAIN_CONDITION, COPY_CHAIN_CONDITION.replace(' && !storage.isForcedIndirect()', "")),
]

TRUNCATED_AFFINE_MUTANTS = [
    ('truncated-affine-retains-temporaries', "ghidradwarfforge/TruncatedStackDepth.java", TRUNCATED_AFFINE_TEST,
     'state.facts.keySet().removeIf(Varnode::isUnique);', ''),
    ('truncated-affine-accepts-shifted-subpiece', "ghidradwarfforge/TruncatedStackDepth.java", TRUNCATED_AFFINE_TEST,
     'operation.getInput(1).getOffset() == 0 &&', ''),
    ('truncated-affine-accepts-equal-extension', "ghidradwarfforge/TruncatedStackDepth.java", TRUNCATED_AFFINE_TEST,
     'input.getSize() >= output.getSize()', 'false'),
    ('truncated-affine-accepts-copy-width-mismatch', "ghidradwarfforge/TruncatedStackDepth.java", TRUNCATED_AFFINE_TEST,
     'input.getSize() != output.getSize()', 'false'),
    ('truncated-affine-ignores-first-operand-width', "ghidradwarfforge/TruncatedStackDepth.java", TRUNCATED_AFFINE_TEST,
     'first.getSize() != output.getSize() ||', ''),
    ('truncated-affine-uses-high-big-endian-bytes', "ghidradwarfforge/TruncatedStackDepth.java", TRUNCATED_AFFINE_TEST,
     'program.getLanguage().isBigEndian() ? node.getSize() - addressBytes : 0', '0'),
    ('truncated-affine-treats-register-as-constant', "ghidradwarfforge/TruncatedStackDepth.java", TRUNCATED_AFFINE_TEST,
     'value == null || !second.isConstant()', 'value == null'),
]
REGISTER_CONTROL_MUTANTS = [
    ('register-control-ignores-condition-width', "ghidradwarfforge/RegisterDefinitionFlow.java", REGISTER_CONTROL_TEST,
     'operation.getInput(1).getSize() != 1', 'false'),
    ('register-control-ignores-return-width', "ghidradwarfforge/RegisterDefinitionFlow.java", REGISTER_CONTROL_TEST,
     'operation.getInput(0).getSize() != instruction.getAddress().getAddressSpace().getPointerSize() ||', ''),
    ('register-control-ignores-branch-output', "ghidradwarfforge/RegisterDefinitionFlow.java", REGISTER_CONTROL_TEST,
     'if (++branches != 1 || index != operations.length - 1 || operation.getOutput() != null ||',
     'if (++branches != 1 || index != operations.length - 1 ||'),
    ('register-control-ignores-return-output', "ghidradwarfforge/RegisterDefinitionFlow.java", REGISTER_CONTROL_TEST,
     'if (++returns != 1 || index != operations.length - 1 || operation.getOutput() != null ||',
     'if (++returns != 1 || index != operations.length - 1 ||'),
    ('register-control-ignores-branch-target', "ghidradwarfforge/RegisterDefinitionFlow.java", REGISTER_CONTROL_TEST,
     '!defaults[0].equals(operation.getInput(0).getAddress()) ||', ''),
    ('register-control-allows-effects-after-branch', "ghidradwarfforge/RegisterDefinitionFlow.java", REGISTER_CONTROL_TEST,
     'if (++branches != 1 || index != operations.length - 1 ||', 'if (++branches != 1 ||'),
]
FORMATTER_SELECTION_MUTANTS = [
    ('formatter-selection-accepts-129', "ghidradwarfforge/output/FormatterSelection.java", FORMATTER_SELECTION_TEST,
     'modes.size() > 128', 'modes.size() > 129'),
    ('formatter-selection-rejects-128', "ghidradwarfforge/output/FormatterSelection.java", FORMATTER_SELECTION_TEST,
     'modes.size() > 128', 'modes.size() >= 128'),
    ('formatter-selection-ignores-blank-key', "ghidradwarfforge/output/FormatterSelection.java", FORMATTER_SELECTION_TEST,
     'entry.getKey().isBlank() ||', ''),
    ('formatter-selection-ignores-duplicate', "ghidradwarfforge/output/FormatterSelection.java", FORMATTER_SELECTION_TEST,
     'modes.putIfAbsent(row.get("key"), row.get("mode")) != null',
     'modes.putIfAbsent(row.get("key"), row.get("mode")) != null && false'),
]
VALIDATOR_OBSERVATION_MUTANTS = [
    ('validator-observation-accepts-empty-identity', "ghidradwarfforge/output/ValidatorInput.java", VALIDATOR_OBSERVATION_TEST,
     'identity.isEmpty() ||', ''),
    ('validator-observation-accepts-zero-links', "ghidradwarfforge/output/ValidatorInput.java", VALIDATOR_OBSERVATION_TEST,
     'links < 1', 'links < 0'),
    ('validator-observation-accepts-negative-size', "ghidradwarfforge/output/ValidatorInput.java", VALIDATOR_OBSERVATION_TEST,
     'bytes < 0', 'false'),
    ('validator-observation-ignores-concurrent-change', "ghidradwarfforge/output/ValidatorInput.java", VALIDATOR_OBSERVATION_TEST,
     '!before.equals(after) || digest.byteCount() != after.bytes()', 'false'),
]
INVOCATION_BOUNDARY_MUTANTS = [
    ('invocation-counts-characters-not-bytes', "ghidradwarfforge/output/AttachmentInvocation.java", INVOCATION_BOUNDARY_TEST,
     'result.getBytes(StandardCharsets.UTF_8).length > LIMITS.bytes()', 'result.length() > LIMITS.bytes()'),
    ('invocation-rejects-exact-byte-limit', "ghidradwarfforge/output/AttachmentInvocation.java", INVOCATION_BOUNDARY_TEST,
     'result.getBytes(StandardCharsets.UTF_8).length > LIMITS.bytes()', 'result.getBytes(StandardCharsets.UTF_8).length >= LIMITS.bytes()'),
    ('invocation-ignores-tool-inventory', "ghidradwarfforge/output/AttachmentInvocation.java", INVOCATION_BOUNDARY_TEST,
     '!validatorTools.keySet().equals(TOOLS)', 'false'),
    ('invocation-ignores-operation-paths', "ghidradwarfforge/output/AttachmentInvocation.java", INVOCATION_BOUNDARY_TEST,
     'for (var path : paths(operation).values()) absolute(path);', ''),
]
REPORT_INVENTORY_MUTANTS = [
    ('report-inventory-ignores-failed', "ghidradwarfforge/output/ExportReportClaims.java", REPORT_INVENTORY_TEST,
     'counts.functionsFailed() != failedFunctions.size() ||', ''),
    ('report-inventory-ignores-skipped', "ghidradwarfforge/output/ExportReportClaims.java", REPORT_INVENTORY_TEST,
     'counts.functionsSkipped() != skippedFunctions.size() ||', ''),
    ('report-inventory-ignores-omitted', "ghidradwarfforge/output/ExportReportClaims.java", REPORT_INVENTORY_TEST,
     'counts.omittedLocationRanges() != omittedLocations.size() ||', ''),
    ('report-inventory-ignores-unsupported', "ghidradwarfforge/output/ExportReportClaims.java", REPORT_INVENTORY_TEST,
     'counts.unsupportedConstructs() != unsupportedConstructs.size() ||', ''),
    ('report-inventory-ignores-diagnostics', "ghidradwarfforge/output/ExportReportClaims.java", REPORT_INVENTORY_TEST,
     'counts.diagnostics() != diagnostics.size()', 'false'),
    ('report-inventory-ignores-status', "ghidradwarfforge/output/ExportReportClaims.java", REPORT_INVENTORY_TEST,
     'partial != (claims.status() == ExportReport.Status.PARTIAL)', 'false'),
]
FIRMWARE_INPUT_MUTANTS = [
    ('firmware-input-accepts-129', "ghidradwarfforge/output/FirmwareInputs.java", FIRMWARE_INPUT_TEST,
     'inputs.size() > 128', 'inputs.size() > 129'),
    ('firmware-input-rejects-128', "ghidradwarfforge/output/FirmwareInputs.java", FIRMWARE_INPUT_TEST,
     'inputs.size() > 128', 'inputs.size() >= 128'),
    ('firmware-input-ignores-index-alias', "ghidradwarfforge/output/FirmwareInputs.java", FIRMWARE_INPUT_TEST,
     ' || !indices.add(input.fileBytesIndex())', ''),
    ('firmware-input-retains-caller-list', "ghidradwarfforge/output/FirmwareInputs.java", FIRMWARE_INPUT_TEST,
     'inputs = List.copyOf(inputs);', ''),
]
FRAME_APPEND_MUTANTS = [
    ('frame-append-forgets-enclosing-tail', "ghidradwarfforge/dwarf/DwarfDebugFrame.java", "ghidradwarfforge.unwind.FrameAppendCoverageSmoke",
     'Long.compareUnsigned(end, prior.getValue()) > 0', 'false'),
    ('frame-append-reserves-empty-range', "ghidradwarfforge/dwarf/DwarfDebugFrame.java", "ghidradwarfforge.unwind.FrameAppendCoverageSmoke",
     'if (frame.size() == 0) continue;', ''),
    ('frame-append-allows-prior-last-byte', "ghidradwarfforge/dwarf/DwarfDebugFrame.java", "ghidradwarfforge.unwind.FrameAppendCoverageSmoke",
     'if ((prior != null && Long.compareUnsigned(prior.getValue(), frame.address()) >= 0)',
     'if ((prior != null && Long.compareUnsigned(prior.getValue(), frame.address()) > 0)'),
    ('frame-append-allows-next-first-byte', "ghidradwarfforge/dwarf/DwarfDebugFrame.java", "ghidradwarfforge.unwind.FrameAppendCoverageSmoke",
     'Long.compareUnsigned(next.getKey(), frame.address() + frame.size() - 1) <= 0',
     'Long.compareUnsigned(next.getKey(), frame.address() + frame.size() - 1) < 0'),
]
DEBUGLINK_BOUNDARY_MUTANTS = [
    ('debuglink-allows-extra-byte', "ghidradwarfforge/output/DebuglinkBasename.java", "ghidradwarfforge.output.DebuglinkBasenameSmoke",
     'encoded.remaining() > 65536', 'encoded.remaining() > 65537'),
    ('debuglink-rejects-exact-byte-bound', "ghidradwarfforge/output/DebuglinkBasename.java", "ghidradwarfforge.output.DebuglinkBasenameSmoke",
     'encoded.remaining() > 65536', 'encoded.remaining() >= 65536'),
    ('debuglink-counts-characters-not-bytes', "ghidradwarfforge/output/DebuglinkBasename.java", "ghidradwarfforge.output.DebuglinkBasenameSmoke",
     'encoded.remaining() > 65536', 'name.length() > 65536'),
    ('debuglink-ignores-native-encoding', "ghidradwarfforge/output/DebuglinkBasename.java", "ghidradwarfforge.output.DebuglinkBasenameSmoke",
     'nativeEncoding == null || !Charset.forName(nativeEncoding).equals(StandardCharsets.UTF_8)', 'false'),
]
ATTACHMENT_PATH_MUTANTS = [
    ('attachment-path-accepts-129', "ghidradwarfforge/output/AttachmentPaths.java", "ghidradwarfforge.output.AttachmentPathBoundarySmoke",
     'selections.size() > 128', 'selections.size() > 129'),
    ('attachment-path-rejects-128', "ghidradwarfforge/output/AttachmentPaths.java", "ghidradwarfforge.output.AttachmentPathBoundarySmoke",
     'selections.size() > 128', 'selections.size() >= 128'),
    ('attachment-path-ignores-size', "ghidradwarfforge/output/AttachmentPaths.java", "ghidradwarfforge.output.AttachmentPathBoundarySmoke",
     'expected.size() != current.size() ||', ''),
    ('attachment-path-ignores-time', "ghidradwarfforge/output/AttachmentPaths.java", "ghidradwarfforge.output.AttachmentPathBoundarySmoke",
     '!Objects.equals(expected.modified(), current.modified())', 'false'),
    ('attachment-path-ignores-identity', "ghidradwarfforge/output/AttachmentPaths.java", "ghidradwarfforge.output.AttachmentPathBoundarySmoke",
     '!Objects.equals(expected.identity(), current.identity()) ||', ''),
    ('attachment-path-ignores-parent', "ghidradwarfforge/output/AttachmentPaths.java", "ghidradwarfforge.output.AttachmentPathBoundarySmoke",
     'if (!FileSystemPaths.resolveLeaf(expected.selection().path(), expected.selection().role())',
     'if (false && !FileSystemPaths.resolveLeaf(expected.selection().path(), expected.selection().role())'),
]
FRAME_CORROBORATE_MUTANTS = [
    ('inherited-frame-ignores-machine', "ghidradwarfforge/elf/InheritedFrameBytes.java", FRAME_CORROBORATE_TEST,
     'before.machine() != after.machine() ||', ''),
    ('inherited-frame-ignores-elf-flags', "ghidradwarfforge/elf/InheritedFrameBytes.java", FRAME_CORROBORATE_TEST,
     'before.flags() != after.flags()', 'false'),
    ('inherited-frame-ignores-address', "ghidradwarfforge/elf/InheritedFrameBytes.java", FRAME_CORROBORATE_TEST,
     'originalFrame.address != sidecarFrame.address ||', ''),
    ('inherited-frame-ignores-section-flags', "ghidradwarfforge/elf/InheritedFrameBytes.java", FRAME_CORROBORATE_TEST,
     'originalFrame.flags != sidecarFrame.flags ||', ''),
    ('inherited-frame-ignores-payload', "ghidradwarfforge/elf/InheritedFrameBytes.java", FRAME_CORROBORATE_TEST,
     '!Arrays.equals(originalBytes, sidecarBytes)', 'false'),
    ('inherited-frame-accepts-duplicate', "ghidradwarfforge/elf/InheritedFrameBytes.java", FRAME_CORROBORATE_TEST,
     'frames.size() != 1', 'frames.isEmpty()'),
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
    ("register-pair-admits-incomplete-child-coverage", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "if (bits != requiredBits)", "if (false)"),
    ("register-slice-ignores-parent-width", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "parent.getBitLength() != logicalSlice.parentBits() ||", ""),
    ("register-slice-ignores-physical-offset", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "register.getAddress().subtract(parent.getAddress()) != logicalSlice.byteOffset()", "false"),
    ("register-pair-ignores-child-offset", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "child.getLeastSignificantBitInBaseRegister() != expected.baseBitOffset() ||", ""),
    ("register-pair-ignores-child-width", REGISTER_PROFILE, REGISTER_PROFILE_TEST,
     "child.getBitLength() != expected.bitSize()", "false"),
]
STACK_TRANSFER_MUTANTS = [
    ("stack-load-accepts-extra-operand", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     "if (opcode == PcodeOp.LOAD && operation.getNumInputs() == 2 &&", "if (opcode == PcodeOp.LOAD && operation.getNumInputs() >= 2 &&"),
    ("stack-load-truncates-space-id", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     "(id != (int) id && id != Integer.toUnsignedLong((int) id)) ||", ""),
    ("stack-load-ignores-space-id", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     "(int) id != memory.getSpaceID()) return null;", "false) return null;"),
    ("stack-load-wraps-relative-window", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     "Math.subtractExact(slot, source.offset())", "(slot - source.offset())"),
    ("stack-load-treats-value-as-address", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     "address != null && address.kind() == Kind.STACK_ADDRESS ? address : null", "address != null ? address : null"),
    ("stack-transfer-accepts-extra-copy-operand", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     'if ((opcode == PcodeOp.COPY || opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) &&\n                operation.getNumInputs() == 1 &&', 'if ((opcode == PcodeOp.COPY || opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) &&\n                operation.getNumInputs() >= 1 &&'),
    ("stack-transfer-accepts-extra-subpiece-operand", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     'if (opcode == PcodeOp.SUBPIECE && operation.getNumInputs() == 2 &&', 'if (opcode == PcodeOp.SUBPIECE && operation.getNumInputs() >= 2 &&'),
    ("stack-transfer-accepts-extra-piece-operand", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     'if (opcode == PcodeOp.PIECE && operation.getNumInputs() == 2 &&', 'if (opcode == PcodeOp.PIECE && operation.getNumInputs() >= 2 &&'),
    ("stack-transfer-accepts-extra-shift-operand", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     'if ((opcode == PcodeOp.INT_LEFT || opcode == PcodeOp.INT_RIGHT || opcode == PcodeOp.INT_SRIGHT) &&\n                operation.getNumInputs() == 2 &&', 'if ((opcode == PcodeOp.INT_LEFT || opcode == PcodeOp.INT_RIGHT || opcode == PcodeOp.INT_SRIGHT) &&\n                operation.getNumInputs() >= 2 &&'),
    ("stack-transfer-accepts-extra-join-operand", "ghidradwarfforge/StackValueFlow.java", STACK_TRANSFER_TEST,
     'if ((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_OR) && operation.getNumInputs() == 2 &&', 'if ((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_OR) && operation.getNumInputs() >= 2 &&'),
    ("stack-transfer-copy-ignores-width", STACK_FLOW, STACK_TRANSFER_TEST,
     "opcode == PcodeOp.COPY ? input.getSize() != output.getSize() : input.getSize() >= output.getSize()",
     "opcode == PcodeOp.COPY ? false : input.getSize() >= output.getSize()"),
    ("stack-transfer-rejects-last-subpiece", STACK_FLOW, STACK_TRANSFER_TEST,
     "removed > operation.getInput(0).getSize() - output.getSize()",
     "removed >= operation.getInput(0).getSize() - output.getSize()"),
    ("stack-transfer-rounds-bit-shift", STACK_FLOW, STACK_TRANSFER_TEST,
     "bits % Byte.SIZE != 0 ||", ""),
    ("stack-transfer-places-high-piece-low", STACK_FLOW, STACK_TRANSFER_TEST,
     "shiftedValues(operation.getInput(0), operation.getInput(1).getSize(), output.getSize())",
     "shiftedValues(operation.getInput(0), 0, output.getSize())"),
    ("stack-transfer-retains-unique-temporaries", STACK_FLOW, STACK_TRANSFER_TEST,
     "facts.keySet().removeIf(Varnode::isUnique);", "facts.keySet().removeIf(node -> false);"),
    ("stack-transfer-right-shifts-left", STACK_FLOW, STACK_TRANSFER_TEST,
     "opcode == PcodeOp.INT_LEFT ? shift : -shift", "shift"),
]
STACK_LOCAL_MUTANTS = [
    ("stack-local-replaces-unrelated-omission", STACK_LOCAL, STACK_LOCAL_TEST,
     'unavailable.reason() != OmissionReason.UNKNOWN_LIFETIME ||', ''),
    ("stack-local-ignores-curated-source", STACK_LOCAL, STACK_LOCAL_TEST,
     'variable.getSource() != SourceType.USER_DEFINED ||', ''),
    ("stack-local-ignores-invalid-variable", STACK_LOCAL, STACK_LOCAL_TEST,
     '!variable.isValid() ||', ''),
    ("stack-local-ignores-unassigned-variable", STACK_LOCAL, STACK_LOCAL_TEST,
     '!variable.hasAssignedStorage() ||', ''),
    ("stack-local-ignores-type-extent", STACK_LOCAL, STACK_LOCAL_TEST,
     'variable.getDataType().getLength() != variable.getLength() ||', ''),
    ("stack-local-ignores-invalid-other-owner", STACK_LOCAL, STACK_LOCAL_TEST,
     'if (!otherStorage.isValid()) return List.of();', ''),
    ("stack-local-admits-detached-owner", STACK_LOCAL, STACK_LOCAL_TEST,
     'if (!attached || analysis == null)', 'if (analysis == null)'),
    ("stack-local-admits-foreign-storage", STACK_LOCAL, STACK_LOCAL_TEST,
     'storage.getProgramArchitecture() != program ||', ''),
]
STACK_CARRIER_MUTANTS = [
    ("scalar-metadata-ignores-first-use", STACK_FLOW, STACK_CARRIER_TEST,
     'parameter.getFirstUseOffset() != 0 ||', ''),
    ("scalar-metadata-ignores-formal-size", STACK_FLOW, STACK_CARRIER_TEST,
     '(!indirect && parameter.getFormalDataType().getLength() != bytes) ||', ''),
    ("scalar-metadata-accepts-detached-parameter", STACK_FLOW, STACK_CARRIER_TEST,
     'function.getParameter(parameter.getOrdinal()) != parameter ||', ''),
    ("indirect-metadata-ignores-pointee", STACK_FLOW, INDIRECT_METADATA_TEST,
     '!effective.getDataType().isEquivalent(parameter.getFormalDataType()) ||', ''),
    ("indirect-metadata-accepts-empty-object", STACK_FLOW, INDIRECT_METADATA_TEST,
     'parameter.getFormalDataType().getLength() <= 0 ||', ''),
    ("indirect-metadata-accepts-narrow-abi-pointer", STACK_FLOW, INDIRECT_METADATA_TEST,
     'bytes != memory.getPointerSize()', 'false'),
    ("stack-narrow-load-retires-intact-memory", STACK_FLOW, STACK_CARRIER_TEST,
     "if (opcode == PcodeOp.LOAD && operation.getNumInputs() == 2 && output.getSize() >= bytes) {",
     "if (opcode == PcodeOp.LOAD && output.getSize() < bytes) slots.clear();\n        if (opcode == PcodeOp.LOAD && operation.getNumInputs() == 2 && output.getSize() >= bytes) {"),
    ("stack-slot-touch-before-retires-value", STACK_FLOW, STACK_CARRIER_TEST,
     "slots.keySet().removeIf(start -> intersects(start, bytes, offset, end));",
     "slots.keySet().removeIf(start -> intersects(start, bytes, offset, end) || start == end);"),
    ("stack-slot-touch-after-retires-value", STACK_FLOW, STACK_CARRIER_TEST,
     "slots.keySet().removeIf(start -> intersects(start, bytes, offset, end));",
     "slots.keySet().removeIf(start -> intersects(start, bytes, offset, end) || Math.addExact(start, bytes) == offset);"),
    ("stack-carrier-admits-unsaved-parameter", STACK_FLOW, STACK_CARRIER_TEST,
     "parameter.getFunction() != function ||\n                parameter.getOrdinal() < 0 || function.getParameter(parameter.getOrdinal()) != parameter ||", ""),
    ("stack-carrier-admits-foreign-storage", STACK_FLOW, STACK_CARRIER_TEST,
     "storage.getProgramArchitecture() != program || !storage.isValid()", "!storage.isValid()"),
    ("stack-carrier-forgets-indirection", STACK_FLOW, STACK_CARRIER_TEST,
     "storage.isForcedIndirect() != indirect ||", ""),
]
MERGED_LIFETIME_MUTANTS = [
    ("merged-stack-metadata-ignores-validity", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     '!variable.isValid() ||\n                    !variable.hasAssignedStorage() || assigned == null',
     '!variable.hasAssignedStorage() || assigned == null'),
    ("merged-register-metadata-ignores-validity", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     '!variable.isValid() ||\n                    !variable.hasAssignedStorage() || variable.getRegister()',
     '!variable.hasAssignedStorage() || variable.getRegister()'),
    ("merged-stack-metadata-ignores-assignment", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     '!variable.hasAssignedStorage() || assigned == null', 'assigned == null'),
    ("merged-register-metadata-ignores-assignment", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     '!variable.hasAssignedStorage() || variable.getRegister()', 'variable.getRegister()'),
    ("merged-stack-metadata-admits-foreign-storage", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     'assigned.getProgramArchitecture() != program ||', ''),
    ("merged-stack-metadata-admits-indirect-storage", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     'assigned.isForcedIndirect() ||', ''),
    ("merged-stack-metadata-admits-detached-member", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     'if (attached != members.size()) return List.of();\n        var analysis =', 'var analysis ='),
    ("merged-register-metadata-admits-detached-member", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     'if (attached != members.size()) return List.of();\n        Map<Address, Set<Address>> successors',
     'Map<Address, Set<Address>> successors'),
    ("merged-lifetime-ignores-invalid-stack-owner", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "if (!assigned.isValid()) return List.of();", ""),
    ("merged-lifetime-ignores-invalid-register-owner", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "if (!storage.isValid()) return List.of();", ""),
    ("merged-lifetime-allows-register-on-stack-canonical", MERGED_LIFETIME, MERGED_LIFETIME_TEST,
     "if (mapping.register() != null || stackDefinition != null)", "if (stackDefinition != null)"),
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
    ("validator-provenance-ignores-file-identity", VALIDATOR_STATUS, VALIDATOR_PROVENANCE_TEST,
     '!Objects.equals(before.fileKey(), after.fileKey()) || ', ''),
    ("validator-provenance-ignores-file-size", VALIDATOR_STATUS, VALIDATOR_PROVENANCE_TEST,
     'before.size() != after.size() ||', ''),
    ("validator-provenance-ignores-modification-time", VALIDATOR_STATUS, VALIDATOR_PROVENANCE_TEST,
     '!before.lastModifiedTime().equals(after.lastModifiedTime()) || ', ''),
    ("validator-provenance-ignores-observed-byte-count", VALIDATOR_STATUS, VALIDATOR_PROVENANCE_TEST,
     ' || after.size() != digest.byteCount()', ''),
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

CALL_PARAMETERS_MUTANTS = [
    ('entry-location-drops-prefix', CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     'if (range.start() < elfEntryAddress) ranges.add', 'if (false) ranges.add'),
    ('entry-location-drops-suffix', CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     'if (elfEntryAddress + 1 < range.end()) ranges.add', 'if (false) ranges.add'),
    ('entry-location-expands-lifetime', CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     'Math.addExact(elfEntryAddress, 1)', 'Math.addExact(elfEntryAddress, 2)'),
    ('entry-location-includes-exclusive-end', CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     'elfEntryAddress < range.end()', 'elfEntryAddress <= range.end()'),
    ('entry-location-precedes-range', CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     'range.start() <= elfEntryAddress', 'true'),
    ('entry-location-accepts-stale-owner', CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     'entry.functionId() == function.getID()', 'true'),
    ("call-parameters-accept-stale-owner", CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     "entry.functionId() != callee.getID()", "false"),
    ("call-parameters-accept-duplicate-snapshot", CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     "snapshots.put(entry.ordinal(), entry) != null", "(snapshots.put(entry.ordinal(), entry) != null && false)"),
    ("call-parameters-assign-overlapping-carrier", CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     "if (counts.get(argument.dwarfRegister()) == 1) return false;", "if (counts.get(argument.dwarfRegister()) >= 1) return false;"),
    ("call-parameters-reject-qualified-integer", CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     "else if (node instanceof TypeGraph.QualifiedType qualified) node = nodes.get(qualified.target().key());",
     "else if (node instanceof TypeGraph.QualifiedType qualified) return -1;"),
    ("call-parameters-bind-hidden-return", CALL_PARAMETERS, CALL_PARAMETERS_TEST,
     'require(!formal.returnStorage(), "hidden return carrier is not a formal argument");',
     '// hidden return guard omitted'),
]

STACK_FACTORY_GUARD = '        if (bytes <= 0 || pointer == null || pointer != pointer.getBaseRegister() ||\n                memory == null || memory.isOverlaySpace() || memory.getType() != AddressSpace.TYPE_RAM ||\n                memory.getAddressableUnitSize() != 1 || memory.getPointerSize() <= 0 ||\n                memory.getPointerSize() > Long.BYTES || pointer.getBitLength() != memory.getPointerSize() * 8 ||\n                program.getAddressFactory().getAddressSpace(memory.getSpaceID()) != memory) return null;'

CALL_MEMORY_MUTANTS = [
    ("stack-factory-admits-zero-width", STACK_FLOW, CALL_MEMORY_TEST,
     STACK_FACTORY_GUARD, STACK_FACTORY_GUARD.replace('bytes <= 0 || ', '')),
    ("stack-factory-admits-overlay", STACK_FLOW, CALL_MEMORY_TEST,
     STACK_FACTORY_GUARD, STACK_FACTORY_GUARD.replace('memory.isOverlaySpace() || ', '')),
    ("stack-factory-admits-register-space", STACK_FLOW, CALL_MEMORY_TEST,
     STACK_FACTORY_GUARD, STACK_FACTORY_GUARD.replace('memory.getType() != AddressSpace.TYPE_RAM ||', '')),
    ("stack-factory-admits-word-addressing", STACK_FLOW, CALL_MEMORY_TEST,
     STACK_FACTORY_GUARD, STACK_FACTORY_GUARD.replace('memory.getAddressableUnitSize() != 1 || ', '')),
    ("stack-factory-ignores-pointer-width", STACK_FLOW, CALL_MEMORY_TEST,
     STACK_FACTORY_GUARD, STACK_FACTORY_GUARD.replace('pointer.getBitLength() != memory.getPointerSize() * 8 ||', '')),
    ("stack-factory-admits-unregistered-space", STACK_FLOW, CALL_MEMORY_TEST,
     STACK_FACTORY_GUARD, STACK_FACTORY_GUARD.replace('program.getAddressFactory().getAddressSpace(memory.getSpaceID()) != memory', 'false')),
    ("incoming-piece-admits-stack-pointer-value", STACK_FLOW, CALL_MEMORY_TEST,
     'register == null || register.getBaseRegister() == state.pointer', 'register == null'),
    ("incoming-piece-invents-memory-value", STACK_FLOW, CALL_MEMORY_TEST,
     'else return null;\n        return state;', 'else state.slots.put(incoming.getOffset(), true);\n        return state;'),
    ("call-memory-profile-admits-overlay", CALL_MEMORY, CALL_MEMORY_TEST,
     'memory.isOverlaySpace() ||', ''),
    ("call-memory-profile-admits-register-space", CALL_MEMORY, CALL_MEMORY_TEST,
     'memory.getType() != AddressSpace.TYPE_RAM ||', ''),
    ("call-memory-profile-admits-word-addressing", CALL_MEMORY, CALL_MEMORY_TEST,
     'memory.getAddressableUnitSize() != 1 ||', ''),
    ("call-memory-profile-ignores-pointer-width", CALL_MEMORY, CALL_MEMORY_TEST,
     'pointer.getBitLength() != memory.getPointerSize() * 8', 'false'),
    ("call-memory-profile-assumes-downward-stack", CALL_MEMORY, CALL_MEMORY_TEST,
     'program.getCompilerSpec().stackGrowsNegative() ? derived.offset() > before.offset() : derived.offset() < before.offset()',
     'derived.offset() > before.offset()'),
    ("call-memory-accepts-extra-store-operand", CALL_MEMORY, CALL_MEMORY_TEST,
     "operation.getNumInputs() != 3 ||", "operation.getNumInputs() < 3 ||"),
    ("call-memory-truncates-space-id", CALL_MEMORY, CALL_MEMORY_TEST,
     "(id != (int) id && id != Integer.toUnsignedLong((int) id)) ||", ""),
    ("call-memory-ignores-offset-width", CALL_MEMORY, CALL_MEMORY_TEST,
     "second.getSize() != width", "false"),
    ("call-memory-retains-instruction-temporaries", CALL_MEMORY, CALL_MEMORY_TEST,
     "state.keySet().removeIf(Varnode::isUnique);", ""),
    ("call-memory-ignores-memory-output", CALL_MEMORY, CALL_MEMORY_TEST,
     "if (destination.getAddress().getAddressSpace().isMemorySpace()) return null;", ""),
    ("call-memory-wraps-affine-addition", CALL_MEMORY, CALL_MEMORY_TEST,
     "Math.addExact(left.offset(), right.offset())", "(left.offset() + right.offset())"),
    ("call-memory-wraps-affine-subtraction", CALL_MEMORY, CALL_MEMORY_TEST,
     "Math.subtractExact(left.offset(), right.offset())", "(left.offset() - right.offset())"),
    ("call-memory-wraps-write-end", CALL_MEMORY, CALL_MEMORY_TEST,
     "Math.addExact(destination, operation.getInput(2).getSize())", "(destination + operation.getInput(2).getSize())"),
    ("call-memory-rejects-negative-affine-offset", CALL_MEMORY, CALL_MEMORY_TEST,
     "return fits(result, width) ?", "return result >= 0 && fits(result, width) ?"),
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
    ("target-descriptor-allows-empty-processor", "ghidradwarfforge/nativeapi/DwarfTarget.java", TARGET_DESCRIPTOR_TEST,
     "ghidraProcessor == null || ghidraProcessor.isBlank()", "false"),
    ("target-descriptor-ignores-instruction-image", "ghidradwarfforge/nativeapi/DwarfTarget.java", TARGET_DESCRIPTOR_TEST,
     'if (!equals(fromElf(elf))) throw new IllegalArgumentException("instruction target disagrees with ELF");',
     '// instruction image agreement omitted'),
    ("target-descriptor-ignores-call-origin-image", "ghidradwarfforge/nativeapi/DwarfTarget.java", TARGET_DESCRIPTOR_TEST,
     'if (!equals(fromElf(image))) throw new IllegalArgumentException("call-origin target disagrees with ELF");',
     '// call origin image agreement omitted'),
    ("type-identity-merges-conflicting-layouts", CURATED_TYPES, TYPE_IDENTITY_TEST,
     "if (owner == null || owner.isEquivalent(type))", "if (true)"),
    ("type-identity-admits-ambiguous-collision", CURATED_TYPES, TYPE_IDENTITY_TEST,
     "if (qualifiedOwner != null && !qualifiedOwner.isEquivalent(type))", "if (false)"),
    ("types-promote-ai-to-user-evidence", CURATED_TYPES, CURATED_TYPES_TEST,
     'case AI -> Confidence.DECOMPILER;', 'case AI -> Confidence.USER_DEFINED;'),
    ("types-erase-imported-evidence", CURATED_TYPES, CURATED_TYPES_TEST,
     'case IMPORTED -> Confidence.IMPORTED;', 'case IMPORTED -> Confidence.ANALYSIS;'),
    ("types-invert-character-signedness", CURATED_TYPES, CURATED_TYPES_TEST,
     '? BaseEncoding.SIGNED_CHAR : BaseEncoding.UNSIGNED_CHAR',
     '? BaseEncoding.UNSIGNED_CHAR : BaseEncoding.SIGNED_CHAR'),
    ("types-hide-missing-signature", CURATED_TYPES, CURATED_TYPES_TEST,
     'diagnostic.accept("No Ghidra signature found for exported function " +\n'
     '                missing.name());', ''),
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
    ("arm-section-accepts-partial-code-unit", ARM_SECTION_EVIDENCE, ARM_SECTION_EVIDENCE_TEST,
     "unit.getLength() <= allocation.size() - offset", "true"),
    ("arm-section-ignores-file-backing", ARM_SECTION_EVIDENCE, ARM_SECTION_EVIDENCE_TEST,
     "allocation.fileSize() == allocation.size()", "true"),
    ("arm-section-rejects-exact-byte-budget", ARM_SECTION_EVIDENCE, ARM_SECTION_EVIDENCE_TEST,
     "allocation.size() <= MAX_BYTES - bytes", "allocation.size() < MAX_BYTES - bytes"),
    ("arm-saved-mode-ignores-renamed-owner", ARM_SAVED_MODES, ARM_SAVED_MODES_TEST,
     "function.getName().equals(symbol.name())", "true"),
    ("arm-saved-mode-ignores-resized-body", ARM_SAVED_MODES, ARM_SAVED_MODES_TEST,
     "symbol.ranges().get(0).size() == size", "true"),
    ("arm-saved-mode-accepts-thunk", ARM_SAVED_MODES, ARM_SAVED_MODES_TEST,
     "!function.isExternal() && !function.isThunk()", "!function.isExternal()"),
    ("arm-saved-mode-rejects-exact-alias-limit", ARM_SAVED_MODES, ARM_SAVED_MODES_TEST,
     "aliases.size() > 65536", "aliases.size() > 65535"),
    ("arm-mode-rejects-exact-dynamic-limit", ARM_MODE_SYMBOLS, ARM_MODE_SYMBOLS_TEST,
     "MAX_DYNAMIC_SYMBOLS = 262144", "MAX_DYNAMIC_SYMBOLS = 262143"),
    ("arm-mode-rejects-exact-comparison-budget", ARM_MODE_SYMBOLS, ARM_MODE_SYMBOLS_TEST,
     "extents.size() * cues.size() > 16L", "extents.size() * cues.size() >= 16L"),
    ("arm-mode-accepts-odd-thumb-extent", ARM_MODE_SYMBOLS, ARM_MODE_SYMBOLS_TEST,
     "thumb && (cue.size() & 1) != 0", "false"),
    ("arm-mode-accepts-malformed-extended-table", ARM_MODE_SYMBOLS, ARM_MODE_SYMBOLS_TEST,
     "other.entrySize != 4 || other.size != (long) count * 4", "false"),
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
    ("switch-reads-low-byte-for-high-byte-index", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "return mask(entry.getValue() >>> (8 * (key.offset() - owner.offset())), key.bytes());",
     "return mask(entry.getValue(), key.bytes());"),
    ("switch-preserves-overwritten-register-alias", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "state.keySet().removeIf(key -> overlap(key, output));",
     "state.keySet().removeIf(key -> key.equals(output));"),
    ("switch-ignores-unbounded-right-operand", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "if (b == null) return null;", "if (b == null) return a;"),
    ("switch-accepts-conflicting-read-widths", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "old == null || old.equals(read)", "true"),
    ("switch-exceeds-dispatch-window", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "count < 32", "count < 33"),
    ("switch-adds-instead-of-subtracting-index", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "case PcodeOp.INT_SUB -> a - b;", "case PcodeOp.INT_SUB -> a + b;"),
    ("switch-shifts-index-in-wrong-direction", BOUNDED_SWITCH, BOUNDED_SWITCH_TEST,
     "? a << b : 0L", "? a >>> b : 0L"),
]

LEXICAL_RECORD_MUTANTS = [
    ('lexical-record-ignores-type-id', "ghidradwarfforge/GhidraLexicalScopes.java", LEXICAL_RECORD_TEST,
     'function.getProgram().getDataTypeManager().getID(variable.getDataType()) != typeId ||', ''),
    ('lexical-record-ignores-size', "ghidradwarfforge/GhidraLexicalScopes.java", LEXICAL_RECORD_TEST,
     'variable.getLength() != size ||', ''),
    ('lexical-record-ignores-first-use', "ghidradwarfforge/GhidraLexicalScopes.java", LEXICAL_RECORD_TEST,
     'variable.getFirstUseOffset() != firstUse ||', ''),
    ('lexical-record-ignores-type-path', "ghidradwarfforge/GhidraLexicalScopes.java", LEXICAL_RECORD_TEST,
     '!variable.getDataType().getPathName().equals(type) ||', ''),
    ('lexical-record-ignores-storage', "ghidradwarfforge/GhidraLexicalScopes.java", LEXICAL_RECORD_TEST,
     '!variable.getVariableStorage().getSerializationString().equals(storage)', 'false'),
    ('lexical-record-accepts-missing-block', "ghidradwarfforge/GhidraLexicalScopes.java", LEXICAL_RECORD_TEST,
     'if (!local.block().isEmpty() && !byId.containsKey(local.block())) throw invalid("missing local block");', ''),
]
STATIC_RECORD_MUTANTS = [
    ('static-record-ignores-namespace', "ghidradwarfforge/GhidraStaticBindings.java", STATIC_BINDING_TEST,
     'symbol.getParentNamespace().getID() != namespace ||', ''),
    ('static-record-ignores-offset', "ghidradwarfforge/GhidraStaticBindings.java", STATIC_BINDING_TEST,
     'relative(symbol, owner) != offset ||', ''),
    ('static-record-ignores-size', "ghidradwarfforge/GhidraStaticBindings.java", STATIC_BINDING_TEST,
     'data.getLength() != size ||', ''),
    ('static-record-ignores-type-path', "ghidradwarfforge/GhidraStaticBindings.java", STATIC_BINDING_TEST,
     '!data.getDataType().getPathName().equals(typePath) ||', ''),
    ('static-record-ignores-universal', "ghidradwarfforge/GhidraStaticBindings.java", STATIC_BINDING_TEST,
     '!java.util.Objects.equals(universal, currentUniversal == null ? null : currentUniversal.getValue())', 'false'),
    ('static-record-ignores-decoded-limit', "ghidradwarfforge/GhidraStaticBindings.java", STATIC_BINDING_TEST,
     'if (bytes.length > MAX_BYTES) throw invalid("oversized static binding");', ''),
]
STATIC_RECOVERY_MUTANTS = [
    ("static-accepts-missing-lexical-block", "ghidradwarfforge/GhidraStaticBindings.java", STATIC_BINDING_TEST,
     'if (scopes.blocks().stream().noneMatch(candidate -> candidate.id().equals(block))) {',
     'if (false) {'),
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

STORAGE_REFINEMENT_MUTANTS = [
    ("storage-refinement-overwrites-established-location", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'if (interval.storage().available()) {', 'if (false) {'),
    ("storage-refinement-accepts-unavailable-evidence", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     '!extra.storage().available() || extra.end() <= cursor', 'extra.end() <= cursor'),
    ("storage-refinement-extends-before-original", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'long low = Math.max(cursor, extra.start());', 'long low = Math.min(cursor, extra.start());'),
    ("storage-refinement-extends-after-original", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'long high = Math.min(interval.end(), extra.end());', 'long high = Math.max(interval.end(), extra.end());'),
    ("storage-refinement-drops-unavailable-prefix", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'if (cursor < low) append(result, cursor, low, interval.storage());', ''),
    ("storage-refinement-drops-unavailable-suffix", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'if (cursor < interval.end()) append(result, cursor, interval.end(), interval.storage());', ''),
    ("storage-refinement-retains-stale-cursor", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'cursor = high;', 'cursor = low;'),
    ("storage-refinement-empty-proof-erases-existing", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'if (proven.isEmpty()) return List.copyOf(existing);', 'if (proven.isEmpty()) return List.of();'),
    ("storage-refinement-discards-new-proof", STACK_FLOW, STORAGE_REFINEMENT_TEST,
     'append(result, low, high, extra.storage());', 'append(result, low, high, interval.storage());'),
]

LOCAL_MAPPING_MUTANTS = [
    ("local-map-accepts-duplicate-definition-pc", LOCAL_MAPPING, LOCAL_MAPPING_TEST,
     'mapping.definition().equals(savedDefinition)', 'false'),
    ("local-map-accepts-nonpoint-definition", LOCAL_MAPPING, LOCAL_MAPPING_TEST,
     'first != null && first.equals(last)', 'first != null'),
    ("local-map-narrows-storage-width", LOCAL_MAPPING, LOCAL_MAPPING_TEST,
     'bytes <= 0 || bytes > Integer.MAX_VALUE', 'bytes <= 0'),
    ("local-map-ignores-pending-storage", LOCAL_MAPPING, LOCAL_MAPPING_TEST,
     'if (pending) valid = false;', ''),
    ("local-map-accepts-nested-storage", LOCAL_MAPPING, LOCAL_MAPPING_TEST,
     'if (path.size() > 2 && path.toArray()[path.size() - 2].equals(ElementId.ELEM_ADDR)) valid = false;', ''),
]

BUILD_ID_LOCK_MUTANTS = [
    ("build-id-lock-skips-initial-metadata-check", BUILD_ID_LOCK, BUILD_ID_LOCK_TEST,
     'require(fingerprint.equals(host.inspect(path)), "build-ID lock identity or metadata changed");\n        require(channel.size()',
     'require(channel.size()'),
    ("build-id-lock-skips-final-metadata-check", BUILD_ID_LOCK, BUILD_ID_LOCK_TEST,
     'require(fingerprint.equals(host.inspect(path)), "build-ID lock identity or metadata changed");\n        check(cancelled);',
     'check(cancelled);'),
]

TRANSACTION_MUTANTS = [
    ("transaction-accepts-foreign-recovery-terminal", TRANSACTION, TRANSACTION_TEST,
     "current.receipt().equals(intendedRecovery)",
     "current.receipt().phase() != AttachmentReceipt.Phase.PREPARED"),
    ("transaction-discards-published-recovery-preparation", TRANSACTION, TRANSACTION_TEST,
     "current.receipt().equals(recoveryClaims) || current.receipt().equals(intendedRecovery)",
     "current.receipt().equals(intendedRecovery)"),
    ("transaction-refresh-ignores-previous-image-hash", TRANSACTION, TRANSACTION_TEST,
     "previous.sha256().equals(current.sha256())", "true"),
    ("transaction-refresh-ignores-previous-image-size", TRANSACTION, TRANSACTION_TEST,
     "previous.bytes() == current.bytes()", "true"),
    ("transaction-replays-completed-record", TRANSACTION, TRANSACTION_TEST,
     "prepared.phase() != AttachmentReceipt.Phase.PREPARED || prepared.recovery() != null ||",
     "prepared.recovery() != null ||"),
    ("transaction-admits-recovery-as-new-request", TRANSACTION, TRANSACTION_TEST,
     "prepared.phase() != AttachmentReceipt.Phase.PREPARED || prepared.recovery() != null ||",
     "prepared.phase() != AttachmentReceipt.Phase.PREPARED ||"),
    ("transaction-admits-mismatched-file-roles", TRANSACTION, TRANSACTION_TEST,
     "!files.keySet().equals(prepared.files().keySet())", "false"),
    ("target-accepts-changed-installed-bytes", TARGET_STORE, TARGET_STORE_TEST,
        "!installed.digest().equals(ownedStage.digest())", "false"),
    ("target-accepts-changed-installed-fingerprint", TARGET_STORE, TARGET_STORE_TEST,
        "!installed.fingerprint().equals(ownedStage.fingerprint())", "false"),
    ("target-restores-from-target-itself", TARGET_STORE, TARGET_STORE_TEST,
        "expectedTarget.fingerprint().identity().equals(verifiedBackup.fingerprint().identity())", "false"),
    ("target-restores-from-metadata-mismatch", TARGET_STORE, TARGET_STORE_TEST,
        "!expectedTarget.fingerprint().metadataSha256().equals(verifiedBackup.fingerprint().metadataSha256())", "false"),
    ("target-skips-destination-directory-sync", TARGET_STORE, TARGET_STORE_TEST,
        "if (!target.getParent().equals(stage.getParent())) host.syncDirectory(target.getParent());", "// destination directory sync omitted"),
    ("transaction-ignores-replaced-parent", TRANSACTION, TRANSACTION_TEST,
     'if (!plan.targetParentIdentity().equals(host.directoryIdentity(plan.snapshots().get("targetBefore").path().getParent())))',
     'if (false)'),
    ("transaction-reports-stale-target", TRANSACTION, TRANSACTION_TEST,
     'catch (IOException | RuntimeException unavailable) { observed = null; }',
     'catch (IOException | RuntimeException unavailable) { observed = before; }'),
    ("transaction-accepts-mismatched-sidecar-crc", TRANSACTION, TRANSACTION_TEST,
     'request.prepared().debuglinkCrc32() != snapshots.get("sidecar").digest().gnuDebuglinkCrc32()', "false"),
    ("transaction-refresh-reuses-operation-identity", TRANSACTION, TRANSACTION_TEST,
     "previous.operationId().equals(current.operationId())", "false"),
    ("transaction-recovery-follows-unrecorded-role", TRANSACTION, TRANSACTION_TEST,
     '!entry.getKey().equals("targetAfter") && !selectedPath.toString().equals(artifact.path())', "false"),
    ("transaction-rejects-already-restored-owned-image", TRANSACTION, TRANSACTION_TEST,
     "sameImage(observed, before) || allowAlreadyRestored &&", "sameImage(observed, before) || false &&"),
    ("transaction-recovery-ignores-record-digest-change", TRANSACTION, TRANSACTION_TEST,
     '!record.sha256().equals(originalRecord.digest().sha256())', "false"),
    ("transaction-recovery-ignores-record-fingerprint-change", TRANSACTION, TRANSACTION_TEST,
     '!record.fingerprint().equals(originalRecord.fingerprint())', "false"),
    ("transaction-diagnostic-retains-controls", TRANSACTION, TRANSACTION_TEST,
     'character < 32 || character == 127 || Character.isSurrogate(character)',
     'Character.isSurrogate(character)'),
    ("transaction-diagnostic-retains-surrogates", TRANSACTION, TRANSACTION_TEST,
     'character < 32 || character == 127 || Character.isSurrogate(character)',
     'character < 32 || character == 127'),
    ("transaction-diagnostic-unbounded", TRANSACTION, TRANSACTION_TEST,
     'index < value.length() && safe.length() < 8000', 'index < value.length()'),
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
    ('relocation-rejects-exact-attribute-cap', RELOCATE, RELOCATE_TEST,
     'attributes.size() < 128', 'attributes.size() < 127'),
    ('relocation-allows-extra-attribute', RELOCATE, RELOCATE_TEST,
     'attributes.size() < 128', 'attributes.size() <= 128'),
    ('relocation-rejects-exact-abbreviation-cap', RELOCATE, RELOCATE_TEST,
     'codes.size() < 65536', 'codes.size() < 65535'),
    ('relocation-allows-extra-abbreviation', RELOCATE, RELOCATE_TEST,
     'codes.size() < 65536', 'codes.size() <= 65536'),
    ('relocation-rejects-exact-file-cap', RELOCATE, RELOCATE_TEST,
     'fileCount <= 65537', 'fileCount < 65537'),
    ('relocation-allows-extra-source-file', RELOCATE, RELOCATE_TEST,
     'fileCount <= 65537', 'fileCount <= 65538'),
    ('relocation-charges-characters-not-utf8-bytes', RELOCATE, RELOCATE_TEST,
     'encoded.remaining() < MAX_STRING', 'value.length() < MAX_STRING'),
    ('relocation-allows-extra-directory-byte', RELOCATE, RELOCATE_TEST,
     'encoded.remaining() < MAX_STRING', 'encoded.remaining() <= MAX_STRING'),
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

FIRMWARE_TARGET_MUTANTS = [
    ('firmware-target-accepts-wide-machine', "ghidradwarfforge/firmware/FirmwareTarget.java", FIRMWARE_MAP_TEST,
     'machine > 0xffff ||', ''),
    ('firmware-target-accepts-bad-address-width', "ghidradwarfforge/firmware/FirmwareTarget.java", FIRMWARE_MAP_TEST,
     '(addressBits != 32 && addressBits != 64)', 'false'),
    ('firmware-target-accepts-bad-pointer-width', "ghidradwarfforge/firmware/FirmwareTarget.java", FIRMWARE_MAP_TEST,
     '(pointerBits != 32 && pointerBits != 64)', 'false'),
    ('firmware-target-accepts-wide-flags', "ghidradwarfforge/firmware/FirmwareTarget.java", FIRMWARE_MAP_TEST,
     'elfFlags > 0xffff_ffffL', 'false'),
    ('firmware-target-accepts-nul-identity', "ghidradwarfforge/firmware/FirmwareTarget.java", FIRMWARE_MAP_TEST,
     "value.indexOf('\\0') >= 0", 'false'),
    ('firmware-target-checks-only-profile-name', "ghidradwarfforge/firmware/FirmwareTarget.java", FIRMWARE_MAP_TEST,
     '!equals(PROFILES.get(profile))', '!PROFILES.containsKey(profile)'),
]
FIRMWARE_MAP_MUTANTS = [
    ('firmware-map-rejects-adjacent-regions', FIRMWARE_MAP, FIRMWARE_MAP_TEST,
     'region.address() < previousEnd', 'region.address() <= previousEnd'),
    ('firmware-map-rejects-last-32bit-byte', FIRMWARE_MAP, FIRMWARE_MAP_TEST,
     'limit > 0x1_0000_0000L', 'limit >= 0x1_0000_0000L'),
    ('firmware-map-rejects-largest-offset-end', FIRMWARE_MAP, FIRMWARE_MAP_TEST,
     'start > Long.MAX_VALUE - length', 'start >= Long.MAX_VALUE - length'),
    ('firmware-map-accepts-invalid-unicode-name', FIRMWARE_MAP, FIRMWARE_MAP_TEST,
     '!java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(name)', 'false'),
    ('firmware-map-allows-no-inputs', FIRMWARE_MAP, FIRMWARE_MAP_TEST,
     'if (inputs.isEmpty())', 'if (false)'),
    ('firmware-map-exposes-mutable-spans', FIRMWARE_MAP, FIRMWARE_MAP_TEST,
     'spans = List.copyOf(ordered);', 'spans = ordered;'),
]

MIPS_AGGREGATE_MUTANTS = [
    ('mips-o32-admits-elf64-container', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     'image.is64Bit() ||', 'false ||'),
    ('mips-o32-admits-core-image', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     '(image.type() != 2 && image.type() != 3)', '(image.type() != 2 && image.type() != 3 && image.type() != 4)'),
    ('mips-o32-rejects-pic-flags', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     '(image.flags() & ~7L)', '(image.flags() & ~3L)'),
    ('mips-o32-ignores-isa-revision', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     'fields.isaRevision() == 2', 'true'),
    ('mips-o32-ignores-gpr-width', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     'fields.gprSize() == 1', 'true'),
    ('mips-o32-ignores-coprocessor', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     'fields.cpr2Size() == 0', 'true'),
    ('mips-o32-ignores-ase-extension', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     'fields.ases() == 0', 'true'),
    ('mips-o32-ignores-unknown-abi-flags', MIPS_AGGREGATE, MIPS_AGGREGATE_TEST,
     '(fields.flags1() & ~1L) == 0', 'true'),
]

MIPS_SIGNATURE_MUTANTS = [
    ('mips-signature-rejects-exact-wrapper-cap', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     'visited.size() > 64', 'visited.size() >= 64'),
    ('mips-signature-allows-extra-wrapper', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     'visited.size() > 64', 'visited.size() > 65'),
    ('mips-signature-admits-small-result-carrier', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     'returned.byteSize() <= 16', 'returned.byteSize() < 16'),
    ('mips-signature-admits-duplicate-result-carrier', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     '++hidden > 1', '++hidden > 2'),
    ('mips-signature-admits-reference-result-carrier', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     'pointer.kind() != TypeGraph.IndirectionKind.POINTER', 'false'),
    ('mips-signature-admits-short-aggregate-field', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     'base.byteSize() != 8', 'false'),
    ('mips-signature-admits-unknown-automatic-role', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     'parameter.artificial() || !transfer', 'false || !transfer'),
    ('mips-signature-admits-quad-float', MIPS_SIGNATURE, MIPS_SIGNATURE_TEST,
     '(base.byteSize() == 4 || base.byteSize() == 8)', '(base.byteSize() == 4 || base.byteSize() == 8 || base.byteSize() == 16)'),
]

ARM_SIGNATURE_MUTANTS = [
    ('arm-signature-rejects-exact-parameter-cap', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'parameters.size() > 4096', 'parameters.size() >= 4096'),
    ('arm-signature-allows-extra-parameter', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'parameters.size() > 4096', 'parameters.size() > 4097'),
    ('arm-signature-rejects-exact-wrapper-cap', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'visited.size() > 64', 'visited.size() >= 64'),
    ('arm-signature-allows-extra-wrapper', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'visited.size() > 64', 'visited.size() > 65'),
    ('arm-signature-allows-two-result-pointers', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     '++hidden > 1', '++hidden > 2'),
    ('arm-signature-allows-reference-result-carrier', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'pointer.kind() != TypeGraph.IndirectionKind.POINTER', 'false'),
    ('arm-signature-homogenizes-mixed-float-widths', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'else if (floatingWidth != base.byteSize()) homogeneous = false;', 'else if (false) homogeneous = false;'),
    ('arm-signature-ignores-aggregate-tail-padding', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'offset == aggregate.byteSize() && offset % alignment == 0', 'offset % alignment == 0'),
    ('arm-signature-trusts-unknown-automatic-role', ARM_SIGNATURE, ARM_SIGNATURE_TEST,
     'if (parameter.artificial())', 'if (false)'),
]

ARM_ABI_METADATA_MUTANTS = [
    ('arm-call-abi-ignores-machine', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'image.machine() != 40', 'false'),
    ('arm-call-abi-admits-elf64', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'image.is64Bit()', 'false'),
    ('arm-call-abi-admits-abi-revision', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'header[8] != 0', 'header[8] != 0 && header[8] != 1'),
    ('arm-call-abi-selects-first-attribute-section', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'sections.size() == 1', '!sections.isEmpty()'),
    ('arm-call-abi-rejects-exact-attribute-cap', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'section.size <= 65536', 'section.size < 65536'),
    ('arm-call-abi-allows-extra-attribute-byte', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'section.size <= 65536', 'section.size <= 65537'),
    ('arm-call-abi-parses-foreign-vendor', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'if (!vendor.equals("aeabi"))', 'if (false)'),
    ('arm-call-abi-rejects-max-optional-tag', ARM_ABI_METADATA, ARM_ABI_METADATA_TEST,
     'tag <= Integer.MAX_VALUE', 'tag < Integer.MAX_VALUE'),
]

SOURCE_DISPOSITION_MUTANTS = [
    ('source-allows-no-disposition', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     '(omissionDiagnostic == null ? 0 : 1) != 1', '(omissionDiagnostic == null ? 0 : 1) > 1'),
    ('source-maps-failed-decompilation', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     'if (c == null && !mappedLines.isEmpty())', 'if (false)'),
    ('source-maps-comment-opening', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     '!line.startsWith("/*")', 'true'),
    ('source-maps-comment-continuation', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     '!line.startsWith("*")', 'true'),
    ('source-maps-line-comment', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     '!line.startsWith("//")', 'true'),
    ('source-maps-row-past-body', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     'mapping.line() <= textLines', 'mapping.line() <= textLines + 1'),
    ('source-borrows-mutable-token-addresses', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     'List.copyOf(line.addresses())', 'line.addresses()'),
    ('source-retains-trailing-tab', SOURCE_DISPOSITION, SOURCE_DISPOSITION_TEST,
     "normalized.charAt(end - 1) == '\\t'", 'false'),
]

INHERITANCE_BUDGET_MUTANTS = [
    ('inheritance-rejects-exact-byte-cap', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     'length > MAX_BYTES - count', 'length >= MAX_BYTES - count'),
    ('inheritance-allows-extra-encoded-byte', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     'length > MAX_BYTES - count', 'length > MAX_BYTES - count + 1'),
    ('inheritance-trusts-base64-text-limit', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     'if (bytes.length > MAX_BYTES)', 'if (false)'),
    ('inheritance-rejects-exact-layout-visits', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     '++budget.visits > 65536', '++budget.visits >= 65536'),
    ('inheritance-allows-extra-layout-visit', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     '++budget.visits > 65536', '++budget.visits > 65537'),
    ('inheritance-rejects-exact-layout-graph', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     'visited.size() > MAX_RECORDS', 'visited.size() >= MAX_RECORDS'),
    ('inheritance-allows-extra-layout-node', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     'visited.size() > MAX_RECORDS', 'visited.size() > MAX_RECORDS + 1'),
    ('inheritance-skips-component-budget', INHERITANCE_BUDGET, INHERITANCE_BUDGET_TEST,
     'count < 0 || count > 65536 - budget.components', 'count < 0'),
]

OMISSION_AUTHORITY_MUTANTS = [
    ('allocation-omits-explicit-definition', CURATED_TYPES, OMISSION_AUTHORITY_TEST,
     'for (Parameter parameter : function.getParameters()) {\n                if (allocationResult.omittedAutomaticParameters().contains(parameter.getOrdinal())) {\n                    if (!parameter.isAutoParameter()) throw new IllegalStateException("Cannot omit an explicit parameter");', 'for (Parameter parameter : function.getParameters()) {\n                if (allocationResult.omittedAutomaticParameters().contains(parameter.getOrdinal())) {\n                    // fault: trust policy omission'),
    ('allocation-retains-hidden-definition', CURATED_TYPES, OMISSION_AUTHORITY_TEST,
     'for (Parameter parameter : function.getParameters()) {\n                if (allocationResult.omittedAutomaticParameters().contains(parameter.getOrdinal())) {\n                    ', 'for (Parameter parameter : function.getParameters()) {\n                if (false) {\n                    '),
    ('allocation-omits-explicit-declaration', CURATED_TYPES, OMISSION_AUTHORITY_TEST,
     'for (Parameter parameter : external.getParameters()) {\n                if (allocationResult.omittedAutomaticParameters().contains(parameter.getOrdinal())) {\n                    if (!parameter.isAutoParameter()) throw new IllegalStateException("Cannot omit an explicit parameter");', 'for (Parameter parameter : external.getParameters()) {\n                if (allocationResult.omittedAutomaticParameters().contains(parameter.getOrdinal())) {\n                    // fault: trust policy omission'),
    ('allocation-retains-hidden-declaration', CURATED_TYPES, OMISSION_AUTHORITY_TEST,
     'for (Parameter parameter : external.getParameters()) {\n                if (allocationResult.omittedAutomaticParameters().contains(parameter.getOrdinal())) {\n                    ', 'for (Parameter parameter : external.getParameters()) {\n                if (false) {\n                    '),
]

INTRA_RAW_MUTANTS = [
    ("intra-flow-rejects-exact-operation-cap", INTRA_RAW, INTRA_RAW_TEST,
     'operations.length > 4096', 'operations.length >= 4096'),
    ("intra-flow-trusts-wide-condition", INTRA_RAW, INTRA_RAW_TEST,
     'operation.getInput(1).getSize() != 1', 'operation.getInput(1).getSize() > 2'),
    ("intra-flow-dereferences-null-operation", INTRA_RAW, INTRA_RAW_TEST,
     'if (operation == null) return null;', 'if (false) return null;'),
    ("intra-flow-admits-self-branch", INTRA_RAW, INTRA_RAW_TEST,
     'distance <= 0', 'distance < 0'),
    ("intra-flow-invents-branchless-proof", INTRA_RAW, INTRA_RAW_TEST,
     'return branched ? targets : null;', 'return targets;'),
    ("intra-flow-uses-next-operation-base", INTRA_RAW, INTRA_RAW_TEST,
     'targets[index] = index + (int) distance;', 'targets[index] = index + 1 + (int) distance;'),
]

CUSTOM_SCALAR_MUTANTS = [
    ("custom-scalar-rejects-enums", CUSTOM_SCALAR, CUSTOM_SCALAR_TEST,
     'type instanceof Enum', 'false'),
    ("custom-scalar-rejects-pointers", CUSTOM_SCALAR, CUSTOM_SCALAR_TEST,
     'type instanceof Pointer', 'false'),
    ("custom-scalar-rejects-floating-types", CUSTOM_SCALAR, CUSTOM_SCALAR_TEST,
     'type instanceof AbstractFloatDataType', 'false'),
    ("custom-scalar-rejects-typedefs", CUSTOM_SCALAR, CUSTOM_SCALAR_TEST,
     'type = alias.getBaseDataType();', 'return false;'),
    ("custom-scalar-bypasses-type-classification", CUSTOM_SCALAR, CUSTOM_SCALAR_TEST,
     'if (!scalar(types[index], index == 0))', 'if (false)'),
    ("custom-scalar-trusts-unassigned-storage", CUSTOM_SCALAR, CUSTOM_SCALAR_TEST,
     '!normal.isValid() || !actual.isValid() ||', 'false ||'),
]

FRAME_DISCOVERY_MUTANTS = [
    ("frame-discovery-rejects-exact-record-cap", FRAME_DISCOVERY, FRAME_DISCOVERY_TEST,
     '++records <= MAX_RECORDS', '++records < MAX_RECORDS'),
    ("frame-discovery-allows-extra-record", FRAME_DISCOVERY, FRAME_DISCOVERY_TEST,
     '++records <= MAX_RECORDS', '++records <= MAX_RECORDS + 1'),
    ("frame-discovery-accepts-equal-pcs", FRAME_DISCOVERY, FRAME_DISCOVERY_TEST,
     'initialLocation > lastPc', 'initialLocation >= lastPc'),
    ("frame-discovery-trusts-short-v4-cie", FRAME_DISCOVERY, FRAME_DISCOVERY_TEST,
     'version != 4 || length >= 11', 'version != 4 || length >= 10'),
    ("frame-discovery-drops-version-three", FRAME_DISCOVERY, FRAME_DISCOVERY_TEST,
     'version == 1 || version == 3 || version == 4', 'version == 1 || version == 4'),
    ("frame-discovery-shifts-initial-pc", FRAME_DISCOVERY, FRAME_DISCOVERY_TEST,
     'initialLocations.put(fde, initialLocation)', 'initialLocations.put(fde, initialLocation + 1)'),
]

RELOCATED_POINTER_MUTANTS = [
    ("relative-pointer-rejects-exact-candidate-cap", RELOCATED_POINTER, RELOCATED_POINTER_TEST,
     'result.size() <= 64', 'result.size() < 64'),
    ("relative-pointer-keeps-record-order", RELOCATED_POINTER, RELOCATED_POINTER_TEST,
     'result.sort(Comparator.comparingLong(Pointer::address));', '/* incorrect record order */'),
    ("relative-pointer-hashes-invented-bytes", RELOCATED_POINTER, RELOCATED_POINTER_TEST,
     'sha256(bytes.array())', 'sha256(new byte[width])'),
    ("relative-pointer-trusts-duplicate-relro", RELOCATED_POINTER, RELOCATED_POINTER_TEST,
     'protections != 1', 'protections == 0'),
    ("relative-pointer-trusts-ambiguous-target", RELOCATED_POINTER, RELOCATED_POINTER_TEST,
     'targets != 1', 'targets == 0'),
    ("relative-pointer-trusts-write-only-slot", RELOCATED_POINTER, RELOCATED_POINTER_TEST,
     '(segment.flags & 6) == 6', '(segment.flags & 2) == 2'),
]

FIRMWARE_CAPTURE_MUTANTS = [
    ("firmware-capture-ignores-final-input-change", FIRMWARE_CAPTURE, FIRMWARE_CAPTURE_TEST,
     'if (!digests.get(binding.id()).equals(FileDigests.read(binding.path(), monitor::isCancelled)))',
     'if (!digests.get(binding.id()).equals(FileDigests.read(binding.path(), monitor::isCancelled)) && false)'),
    ("firmware-capture-ignores-program-change", FIRMWARE_CAPTURE, FIRMWARE_CAPTURE_TEST,
     'program.getModificationNumber() != modification', 'program.getModificationNumber() < modification'),
    ("firmware-capture-drops-import-file-offset", FIRMWARE_CAPTURE, FIRMWARE_CAPTURE_TEST,
     'Math.addExact(bytes.getFileOffset(), offset)', 'offset'),
    ("firmware-capture-trusts-modified-analysis-bytes", FIRMWARE_CAPTURE, FIRMWARE_CAPTURE_TEST,
     '!Arrays.equals(original, 0, count, current, 0, count)', 'false'),
]

ARM_HFA_MUTANTS = [
    ("arm-hfa-rejects-exact-type-budget", ARM_HFA, ARM_HFA_TEST,
     '--budget[0] < 0', '--budget[0] <= 0'),
    ("arm-hfa-ignores-type-budget", ARM_HFA, ARM_HFA_TEST,
     '--budget[0] < 0', 'false'),
    ("arm-hfa-rejects-exact-parameter-cap", ARM_HFA, ARM_HFA_TEST,
     'parameters.length > 4096', 'parameters.length >= 4096'),
    ("arm-hfa-includes-hidden-parameter", ARM_HFA, ARM_HFA_TEST,
     'if (!parameter.isAutoParameter()) signature.add', 'if (true) signature.add'),
    ("arm-hfa-trusts-unaudited-compiler", ARM_HFA, ARM_HFA_TEST,
     '!program.getCompilerSpec().getCompilerSpecID().toString().equals("default") ||', 'false ||'),
    ("arm-hfa-reverses-big-endian-pieces", ARM_HFA, ARM_HFA_TEST,
     'big ? pieces : pieces.reversed()', 'pieces.reversed()'),
]

ARM_COMPOSITE_MUTANTS = [
    ("arm-composite-trusts-unaudited-compiler", ARM_COMPOSITE, ARM_COMPOSITE_TEST,
     '!program.getCompilerSpec().getCompilerSpecID().toString().equals("default") ||', 'false ||'),
    ("arm-composite-trusts-invalid-eabi", ARM_COMPOSITE, ARM_COMPOSITE_TEST,
     '!Arm32CallAbi.observe(image, monitor::isCancelled).valid()', 'false'),
    ("arm-composite-rejects-exact-parameter-cap", ARM_COMPOSITE, ARM_COMPOSITE_TEST,
     'parameters.length > 4096', 'parameters.length >= 4096'),
    ("arm-composite-includes-hidden-parameter", ARM_COMPOSITE, ARM_COMPOSITE_TEST,
     'if (!parameter.isAutoParameter()) signature.add', 'if (true) signature.add'),
    ("arm-composite-retains-stack-padding", ARM_COMPOSITE, ARM_COMPOSITE_TEST,
     'stack.getAddress().subtract(padding)', 'stack.getAddress()'),
]

UNWIND_CAPTURE_MUTANTS = [
    ("unwind-capture-ignores-parsed-length", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "instruction.getLength() != instruction.getParsedLength()", "false"),
    ("unwind-capture-ignores-parsed-byte-count", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "bytes.length != instruction.getLength()", "false"),
    ("unwind-capture-ignores-short-memory-read", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "program.getMemory().getBytes(address, live) != live.length", "program.getMemory().getBytes(address, live) < 0"),
    ("unwind-capture-trusts-stale-decoded-bytes", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "!Arrays.equals(bytes, live)", "false"),
    ("unwind-capture-trusts-nonadjacent-fallthrough", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "!next.equals(instruction.getMaxAddress().next())", "false"),
    ("unwind-capture-trusts-thunk-body", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "function.isExternal() || function.isThunk() || body.isEmpty()", "function.isExternal() || body.isEmpty()"),
    ("unwind-capture-trusts-changed-body", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "if (!body.equals(function.getBody()))", "if (false)"),
    ("unwind-capture-rejects-exact-instruction-cap", UNWIND_CAPTURE, UNWIND_CAPTURE_TEST,
     "if (graph.size() > 65_536)", "if (graph.size() >= 65_536)"),
]

SECTIONLESS_MUTANTS = [
    ("sectionless-trusts-mismatched-named-width", SECTIONLESS, SECTIONLESS_TEST,
     "section.entrySize == width &&", "true &&"),
    ("sectionless-trusts-compressed-named-records", SECTIONLESS, SECTIONLESS_TEST,
     "(section.flags & 0x802) == 2", "(section.flags & 2) == 2"),
    ("sectionless-ignores-named-file-mapping", SECTIONLESS, SECTIONLESS_TEST,
     "reader.locate(section.address, section.size) == section.offset", "true"),
    ("sectionless-rejects-exact-named-record-cap", SECTIONLESS, SECTIONLESS_TEST,
     "section.size / width <= MAX_SYMBOLS", "section.size / width < MAX_SYMBOLS"),
    ("sectionless-trusts-conflicting-count-sources", SECTIONLESS, SECTIONLESS_TEST,
     'require(count == observed, "PT_DYNAMIC symbol count sources disagree");',
     'require(true, "PT_DYNAMIC symbol count sources disagree");'),
    ("sectionless-sign-extends-relocation-size", SECTIONLESS, SECTIONLESS_TEST,
     "Integer.toUnsignedLong(data.getInt(at + 8))", "(long) data.getInt(at + 8)"),
    ("sectionless-accepts-empty-sysv-buckets", SECTIONLESS, SECTIONLESS_TEST,
     "buckets > 0 && buckets <= MAX_SYMBOLS", "buckets >= 0 && buckets <= MAX_SYMBOLS"),
    ("sectionless-loses-zero-sized-end-marker", SECTIONLESS, SECTIONLESS_TEST,
     "if (selected == 0 && size == 0)", "if (false)"),
]

DYNAMIC_MUTANTS = [
    ("dynamic-name-allows-extra-byte", DYNAMIC, DYNAMIC_TEST,
     "++end - start <= ElfImage.MAX_NAME_BYTES", "++end - start <= ElfImage.MAX_NAME_BYTES + 1"),
    ("dynamic-name-forgets-aggregate", DYNAMIC, DYNAMIC_TEST,
     "(total += end - start)", "(total = end - start)"),
    ("dynamic-name-forgets-version-separator", DYNAMIC, DYNAMIC_TEST,
     "(long) name.length + separator + versionName.length <= ElfImage.MAX_NAME_BYTES",
     "(long) name.length + versionName.length <= ElfImage.MAX_NAME_BYTES"),
    ("dynamic-name-omits-scan-cancellation", DYNAMIC, DYNAMIC_TEST,
     "if ((end & 1023) == 0)", "if (false)"),
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
    parser.add_argument("--only", action="append", help="run an exact mutation label and its baseline; repeatable")
    args = parser.parse_args()
    classes, tests, output = args.classes.resolve(), args.tests.resolve(), args.output.resolve()
    if not classes.is_dir() or not tests.is_dir():
        raise ValueError("compiled production and test directories are required")
    output.mkdir(parents=True, exist_ok=False)
    java, javac = args.java_home.resolve() / "bin/java", args.java_home.resolve() / "bin/javac"
    mutants = UNWIND_CALL_MEMORY_MUTANTS + UNWIND_MEMORY_MUTANTS + UNWIND_ARITHMETIC_MUTANTS + FRAME_APPEND_MUTANTS + DEBUGLINK_BOUNDARY_MUTANTS + ATTACHMENT_PATH_MUTANTS + FRAME_CORROBORATE_MUTANTS + FIRMWARE_TARGET_MUTANTS + FIRMWARE_MAP_MUTANTS + MIPS_AGGREGATE_MUTANTS + MIPS_SIGNATURE_MUTANTS + ARM_SIGNATURE_MUTANTS + SOURCE_DISPOSITION_MUTANTS + FRAME_DISCOVERY_MUTANTS + RELOCATED_POINTER_MUTANTS + MUTANTS + ALLOCATION_CHANGE_MUTANTS + ALLOCATION_BOUNDARY_MUTANTS + ELF_READER_MUTANTS + ELF_BUILD_ID_MUTANTS + GDB_COMPANION_MUTANTS + RUNTIME_RELOCATION_MUTANTS + RELOCATION_EFFECTS_MUTANTS + REGISTER_MAP_MUTANTS + STRICT_REPORT_MUTANTS + PROGRAM_TYPE_MUTANTS + LEXICAL_SCOPE_MUTANTS + CLASS_EVIDENCE_MUTANTS + SECTIONLESS_MUTANTS + DYNAMIC_MUTANTS + FRAME_REREAD_MUTANTS + ORIGINAL_OBJECT_MUTANTS + FRAME_RANGE_MUTANTS + PUBLICATION_TIME_MUTANTS + ARM_MAPPING_MUTANTS + (DELAY_CONTRACT_MUTANTS + COPY_CHAIN_IDENTITY_MUTANTS + TRUNCATED_AFFINE_MUTANTS + REGISTER_CONTROL_MUTANTS + FORMATTER_SELECTION_MUTANTS + VALIDATOR_OBSERVATION_MUTANTS + INVOCATION_BOUNDARY_MUTANTS + REPORT_INVENTORY_MUTANTS + FIRMWARE_INPUT_MUTANTS + LEXICAL_RECORD_MUTANTS + STATIC_RECORD_MUTANTS + STACK_TRANSFER_MUTANTS + ARM_ABI_METADATA_MUTANTS + INHERITANCE_BUDGET_MUTANTS + OMISSION_AUTHORITY_MUTANTS + INTRA_RAW_MUTANTS + CUSTOM_SCALAR_MUTANTS + FIRMWARE_CAPTURE_MUTANTS + ARM_HFA_MUTANTS + ARM_COMPOSITE_MUTANTS + UNWIND_CAPTURE_MUTANTS + STORAGE_REFINEMENT_MUTANTS + REPORT_LEXICAL_MUTANTS + PROJECT_MUTANTS + RECORD_MUTANTS + UNWIND_REPORT_MUTANTS + MMIO_MUTANTS + CXX_SELECTION_MUTANTS + RECEIPT_MUTANTS + SOURCE_FILES_MUTANTS + REPORT_CLAIMS_MUTANTS + TRANSACTION_MUTANTS + BUILD_ID_LOCK_MUTANTS + LOCAL_MAPPING_MUTANTS + MIPS_ALLOCATION_MUTANTS + STACK_FLOW_MUTANTS + VTABLE_BINDING_MUTANTS + STATIC_RECOVERY_MUTANTS + BOUNDED_SWITCH_MUTANTS + ARM_MODE_INVENTORY_MUTANTS + CURATED_TYPE_MUTANTS + CALL_MEMORY_MUTANTS + CALL_PARAMETERS_MUTANTS + CXX_PROFILE_MUTANTS + CALL_VALUE_MUTANTS + VALIDATOR_STATUS_MUTANTS + I386_ALLOCATION_MUTANTS + AARCH64_ALLOCATION_MUTANTS + MERGED_LIFETIME_MUTANTS + STACK_CARRIER_MUTANTS + STACK_LOCAL_MUTANTS + REGISTER_PROFILE_MUTANTS + DYNAMIC_STORAGE_MUTANTS + CALL_EVIDENCE_MUTANTS + ALLOCATION_OVERRIDE_MUTANTS + CLOSED_FLOW_MUTANTS + COMPOSITE_FLOW_MUTANTS + MIXED_PREFIX_MUTANTS + BACKUP_READBACK_MUTANTS + REPORT_TEXT_MUTANTS + BUILD_ID_HELPER_MUTANTS + LINUX_METADATA_MUTANTS + LINUX_MOUNT_MUTANTS + STACK_SPILL_MUTANTS + TRUNCATED_DEPTH_MUTANTS + LOCAL_OWNERSHIP_MUTANTS + ATTACHMENT_PREVIEW_MUTANTS if args.ghidra else [])
    if args.only:
        selected = set(args.only)
        unknown = selected - {row[0] for row in mutants}
        if unknown:
            parser.error("unknown or unavailable mutation labels: " + ", ".join(sorted(unknown)))
        mutants = [row for row in mutants if row[0] in selected]
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
            selected_dependencies = dependencies if test in (DELAY_CONTRACT_TEST,COPY_CHAIN_IDENTITY_TEST,
                TRUNCATED_AFFINE_TEST,
                REGISTER_CONTROL_TEST,
                FORMATTER_SELECTION_TEST,
                VALIDATOR_OBSERVATION_TEST,
                INVOCATION_BOUNDARY_TEST,
                REPORT_INVENTORY_TEST,
                FIRMWARE_INPUT_TEST,
                STACK_TRANSFER_TEST, ARM_ABI_METADATA_TEST, INHERITANCE_BUDGET_TEST, OMISSION_AUTHORITY_TEST, INTRA_RAW_TEST, CUSTOM_SCALAR_TEST, FIRMWARE_CAPTURE_TEST, ARM_HFA_TEST, ARM_COMPOSITE_TEST, UNWIND_CAPTURE_TEST, ARM_SECTION_EVIDENCE_TEST, ARM_SAVED_MODES_TEST, VALIDATOR_PROVENANCE_TEST, LOCAL_MAPPING_TEST, BUILD_ID_LOCK_TEST, TARGET_DESCRIPTOR_TEST, TYPE_IDENTITY_TEST, STORAGE_REFINEMENT_TEST, REPORT_LEXICAL_TEST, PROTECT_TEST, RECORDS_TEST, UNWIND_REPORT_TEST, MMIO_TEST, CXX_SELECTION_TEST,
                RECEIPT_TEST, RECEIPT_STORE_TEST, OPERATION_TEST, SOURCE_FILES_TEST, SOURCE_BUNDLE_TEST,
                REPORT_CLAIMS_TEST, TYPE_CLAIMS_TEST, TRANSACTION_TEST, TARGET_STORE_TEST, MIPS_ALLOCATION_TEST, STACK_FLOW_TEST, VTABLE_BINDINGS_TEST, STATIC_RECOVERY_TEST, STATIC_BINDING_TEST, LEXICAL_RECORD_TEST, BOUNDED_SWITCH_TEST, ARM_MODE_INVENTORY_TEST, CURATED_TYPES_TEST, CALL_MEMORY_TEST, CALL_PARAMETERS_TEST, CXX_PROFILE_TEST, CALL_VALUE_TEST, VALIDATOR_STATUS_TEST, I386_ALLOCATION_TEST, AARCH64_ALLOCATION_TEST, MERGED_LIFETIME_TEST, STACK_CARRIER_TEST, STACK_LOCAL_TEST, INDIRECT_METADATA_TEST, REGISTER_PROFILE_TEST, DYNAMIC_STORAGE_TEST, CALL_EVIDENCE_TEST, ALLOCATION_OVERRIDE_TEST, CLOSED_FLOW_TEST, COMPOSITE_FLOW_TEST, MIXED_PREFIX_TEST, BACKUP_READBACK_TEST, REPORT_TEXT_TEST, BUILD_ID_HELPER_TEST, LINUX_METADATA_TEST, LINUX_APPLICATION_TEST, LINUX_CANARY_TEST, LINUX_MOUNT_TEST, STACK_SPILL_TEST, TRUNCATED_DEPTH_TEST, LOCAL_OWNERSHIP_TEST, LOCAL_PREFIX_TEST, ATTACHMENT_PREVIEW_TEST) else []
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
            if test in (GDB_COMPANION_TEST, FORMATTER_SELECTION_TEST):
                # Rendering requires the same checked-in runtime resources packaged by CI.
                classpath += os.pathsep + str(REPO / "src/main/resources")
            test_args = [args.ghidra.resolve()] if test in (DELAY_CONTRACT_TEST,COPY_CHAIN_IDENTITY_TEST,TRUNCATED_AFFINE_TEST, REGISTER_CONTROL_TEST, STACK_TRANSFER_TEST, INHERITANCE_BUDGET_TEST, OMISSION_AUTHORITY_TEST, INTRA_RAW_TEST, CUSTOM_SCALAR_TEST, FIRMWARE_CAPTURE_TEST, ARM_HFA_TEST, ARM_COMPOSITE_TEST, UNWIND_CAPTURE_TEST, ARM_SECTION_EVIDENCE_TEST, ARM_SAVED_MODES_TEST, LOCAL_MAPPING_TEST, PROTECT_TEST, MIPS_ALLOCATION_TEST, STACK_FLOW_TEST, VTABLE_BINDINGS_TEST, STATIC_RECOVERY_TEST, STATIC_BINDING_TEST, LEXICAL_RECORD_TEST, BOUNDED_SWITCH_TEST, CURATED_TYPES_TEST, CALL_MEMORY_TEST, CALL_PARAMETERS_TEST, CXX_PROFILE_TEST, I386_ALLOCATION_TEST, AARCH64_ALLOCATION_TEST, MERGED_LIFETIME_TEST, STACK_CARRIER_TEST, STACK_LOCAL_TEST, INDIRECT_METADATA_TEST, REGISTER_PROFILE_TEST, DYNAMIC_STORAGE_TEST, CALL_EVIDENCE_TEST, ALLOCATION_OVERRIDE_TEST, CLOSED_FLOW_TEST, COMPOSITE_FLOW_TEST, MIXED_PREFIX_TEST, STACK_SPILL_TEST, TRUNCATED_DEPTH_TEST, LOCAL_OWNERSHIP_TEST, LOCAL_PREFIX_TEST) else []
            if test == CALL_EVIDENCE_TEST:
                test_args.append(root / "call-fixtures")
            if test == VALIDATOR_PROVENANCE_TEST:
                test_args.append(root / "provenance-fixtures")
            if test == BUILD_ID_LOCK_TEST:
                test_args.extend(["exercise", root / "owned-lock"])
            if test == STRICT_REPORT_TEST:
                test_args.append(REPO / "src/test/fixtures/dwarfdump")
            if test == LINUX_MOUNT_TEST:
                test_args.append("--parser-only")
            if test == LINUX_CANARY_TEST:
                test_args.extend(["unprivileged", root / "owned-canary-tests"])
            if test == BOUNDED_SWITCH_TEST:
                test_args.append(root / "fixtures")
            if test == CALL_VALUE_TEST:
                test_args.append(root / "vectors.json")
            if test == CALL_PARAMETERS_TEST:
                test_args.append(root / "argument-vectors")
            run, run_seconds = execute([java, "-Djava.io.tmpdir=" + str(root),
                "-Dapplication.settingsdir=" + str(root / "settings"), "-Djava.awt.headless=true",
                "-cp", classpath, test, *test_args])
            oracle, oracle_evidence = None, None
            if test in (CALL_VALUE_TEST, CALL_PARAMETERS_TEST) and run.returncode == 0:
                vectors_path = root / ("argument-vectors/vectors.json" if test == CALL_PARAMETERS_TEST else "vectors.json")
                oracle_command = [sys.executable, "-B", CALL_VALUE_ORACLE, vectors_path]
                if test == CALL_PARAMETERS_TEST:
                    oracle_command.extend(["--min-count", "240"])
                oracle, oracle_seconds = execute(oracle_command)
                oracle_evidence = {"source": str(CALL_VALUE_ORACLE.relative_to(REPO)),
                    "sha256": digest(CALL_VALUE_ORACLE), "vectorsSha256": digest(vectors_path),
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

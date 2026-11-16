#!/usr/bin/env python3
"""Compile bounded, explicit mutants outside the checkout and require behavioral failures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
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
VTABLE_BINDINGS = "ghidradwarfforge/GhidraVtableBindings.java"
VTABLE_BINDINGS_TEST = "ghidradwarfforge.VtableBindingEvidenceSmoke"

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
    mutants = MUTANTS + PROGRAM_TYPE_MUTANTS + SECTIONLESS_MUTANTS + DYNAMIC_MUTANTS + (PROJECT_MUTANTS + RECORD_MUTANTS + UNWIND_REPORT_MUTANTS + MMIO_MUTANTS + CXX_SELECTION_MUTANTS + RECEIPT_MUTANTS + SOURCE_FILES_MUTANTS + REPORT_CLAIMS_MUTANTS + TRANSACTION_MUTANTS + MIPS_ALLOCATION_MUTANTS + STACK_FLOW_MUTANTS + VTABLE_BINDING_MUTANTS if args.ghidra else [])
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
                REPORT_CLAIMS_TEST, TYPE_CLAIMS_TEST, TRANSACTION_TEST, MIPS_ALLOCATION_TEST, STACK_FLOW_TEST, VTABLE_BINDINGS_TEST) else []
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
            compiled, compile_seconds = execute([javac, lint, "-proc:none", "-Werror", "-cp", compile_path,
                                                 "-d", root, path])
            if compiled.returncode:
                raise AssertionError(f"{label}: compilation failed, not a detected mutant\n{compiled.stdout}")
            classpath = os.pathsep.join(map(str, [root, classes, tests, *selected_dependencies]))
            test_args = [args.ghidra.resolve()] if test in (PROTECT_TEST, MIPS_ALLOCATION_TEST, STACK_FLOW_TEST, VTABLE_BINDINGS_TEST) else []
            run, run_seconds = execute([java, "-Djava.io.tmpdir=" + str(root),
                "-Dapplication.settingsdir=" + str(root / "settings"), "-Djava.awt.headless=true",
                "-cp", classpath, test, *test_args])
            (output / (label + ".log")).write_text(run.stdout)
            if mutant:
                if run.returncode == 0 or "java.lang.AssertionError:" not in run.stdout:
                    raise AssertionError(f"{label}: no behavioral assertion detected mutation\n{run.stdout}")
                if any(word in run.stdout for word in ("ClassNotFoundException", "NoClassDefFoundError", "LinkageError")):
                    raise AssertionError(f"{label}: class-loading failure is not a behavioral detection")
            elif run.returncode != 0 or "=PASS" not in run.stdout:
                raise AssertionError(f"{label}: unchanged-source baseline failed\n{run.stdout}")
            peak = max(peak, sum(p.stat().st_size for p in root.rglob("*") if p.is_file()))
            results.append({"label": label, "source": name, "test": test,
                            "status": "DETECTED" if mutant else "BASELINE_PASS",
                            "exitCode": run.returncode, "compileSeconds": compile_seconds,
                            "testSeconds": run_seconds})

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

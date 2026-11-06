// Exercise the explicit frame API with a real ELF import, decompiler and native producer.
// This test script is not a supported user-facing synthesis entry point.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidradwarfforge.*;
import ghidradwarfforge.elf.DebugSectionCompression;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.output.ArtifactPairPublisher;
import ghidradwarfforge.output.ExportReport;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.UnwindEvidenceJson;
import ghidradwarfforge.unwind.GhidraUnwindRecovery;
import ghidradwarfforge.unwind.UnwindStackSeparation;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class ExportRecoveredFrames extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 6 && args.length != 7) throw new IllegalArgumentException("libdwarf libdwarfp output compression rebase failed-source-name [external-separation-first:last]");
        Path input = Path.of(currentProgram.getExecutablePath()).toRealPath();
        Path output = Path.of(args[2]).toAbsolutePath(), sourceOutput = Path.of(output + ".c");
        long requestedRebase = Long.decode(args[4]);
        if (requestedRebase != 0) currentProgram.setImageBase(currentProgram.getImageBase().add(requestedRebase), true);
        var consistency = GhidraExportConsistency.capture(currentProgram, input, monitor::isCancelled);
        String imported = currentProgram.getExecutableSHA256();
        if (imported == null || !imported.equalsIgnoreCase(consistency.inputSha256())) throw new AssertionError("original import identity mismatch");
        var image = ElfImage.read(input);
        var target = GhidraTargetAgreement.requireAgreement(currentProgram, image);
        long delta = AddressNormalizer.rebaseDelta(currentProgram.getImageBase().getOffset(), GhidraImageBase.originalImageBase(currentProgram));
        var diagnostics = new ArrayList<String>();
        Consumer<String> diagnostic = message -> { diagnostics.add(message); printerr(message); };
        var condition = UnwindStackSeparation.NONE;
        if (args.length == 7) {
            String[] range = args[6].split(":", -1);
            if (range.length != 2) throw new IllegalArgumentException("expected original ELF hex first:last");
            long first = Long.parseUnsignedLong(range[0], 16), last = Long.parseUnsignedLong(range[1], 16);
            if (Long.compareUnsigned(first, last) > 0) throw new IllegalArgumentException("wrapping original separation range");
            condition = new UnwindStackSeparation(image.is64Bit() ? 8 : 4,
                List.of(new UnwindStackSeparation.Region(first + delta, last + delta)),
                "Explicit test assumption: this ELF range never overlaps live stack storage of this call group or its callers");
        }
        var recovered = condition.conditional() ?
            GhidraUnwindRecovery.recoverConditioned(currentProgram, image, delta, monitor, condition) :
            GhidraUnwindRecovery.recover(currentProgram, image, delta, monitor);
        if (!recovered.separation().equals(condition)) throw new AssertionError("collection lost external condition");
        Files.writeString(Path.of(output + ".recovery.txt"), recovered.toString() + "\n");
        var plan = recovered.plan().orElseThrow(() -> new AssertionError("real import produced no frame proof: " + recovered.refusals()));
        if (plan.frames().isEmpty()) throw new AssertionError("real import produced empty frame coverage");
        recovered.refusals().forEach((address, reason) -> diagnostic.accept("Unwind omitted at " + address + ": " + reason));
        var extraction = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor, diagnostic, delta);
        var functions = extraction.functions();
        var allocation = ghidradwarfforge.targets.TargetParameterAllocation.forProgram(currentProgram, image, monitor, diagnostic);
        var decompilation = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, monitor,
            (decompiler, function, timeout, taskMonitor) -> {
                if (function.getName().equals(args[5])) throw new IllegalStateException("controlled unwind source failure");
                return decompiler.decompileFunction(function, timeout, taskMonitor);
            }, allocation, diagnostic);
        var source = decompilation.source();
        if (source.mappedLines().isEmpty()) throw new AssertionError("real export has no decompiler source mapping");
        var registers = ghidradwarfforge.locations.TargetRegisterMap.forElf(target.name(), image, monitor::isCancelled);
        var types = GhidraTypeGraph.extract(currentProgram, functions, registers, delta, monitor, diagnostic,
            decompilation.recoveredReturns(), decompilation.recoveredParameters(), decompilation.recoveredStatics(), allocation);
        var model = GhidraCompilerCallPolicy.apply(currentProgram, target, image, types, monitor, diagnostic);
        var modes = GhidraArm32FunctionModes.extract(currentProgram, functions, target, delta, monitor, diagnostic);
        var aliases = GhidraFunctionAliases.extract(currentProgram, functions, delta, monitor, diagnostic);
        var aliasModes = GhidraArm32FunctionModes.extractAliases(currentProgram, aliases, target, delta, monitor, diagnostic);
        var sectionModes = GhidraArm32SectionModes.extract(currentProgram, image, functions, target, delta, monitor, diagnostic);
        consistency.requireUnchanged(monitor::isCancelled);
        var result = new MinimalDwarfSidecarExporter.ExportResult[1];
        var stagedFiles = new Path[2];
        var unwindJson = new String[1];
        ArtifactPairPublisher.stageAndPublish(output, sourceOutput,
            staged -> { stagedFiles[0] = staged; result[0] = new MinimalDwarfSidecarExporter(DebugSectionCompression.parse(args[3])).exportWithFrames(
                input, staged, Path.of(args[0]), Path.of(args[1]), functions, source, model,
                sourceOutput.getFileName().toString(), monitor::isCancelled, modes, aliases, aliasModes, sectionModes, diagnostic, plan); },
            staged -> { stagedFiles[1] = staged; source.writeAtomically(staged); },
            () -> {
                consistency.requireUnchanged(monitor::isCancelled);
                unwindJson[0] = UnwindEvidenceJson.describe(image, recovered, delta, consistency.inputSha256(),
                    FileDigests.read(stagedFiles[0]).sha256(), FileDigests.read(stagedFiles[1]).sha256(), monitor::isCancelled);
            });
        if (!result[0].sectionNames().contains(".debug_frame")) throw new AssertionError("frame section missing from exporter result");
        var report = ExportReport.completed(result[0].target(), result[0].libdwarfVersion(), input,
            consistency.inputSha256(), output, FileDigests.read(output).sha256(), sourceOutput, FileDigests.read(sourceOutput).sha256(),
            result[0].functionCount(), result[0].sectionNames(), source, model, extraction.skippedFunctions(), diagnostics);
        Files.writeString(Path.of(output + ".report.json"), report.toJson() + "\n");
        // Test-only evidence attachment. Serialize before pair publication;
        // retain it atomically after success, bound to the exact artifact hashes.
        Path evidenceStage = Files.createTempFile(output.getParent(), ".unwind-evidence-", ".tmp");
        try {
            Files.writeString(evidenceStage, unwindJson[0] + "\n");
            Files.move(evidenceStage, Path.of(output + ".unwind.json"),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        finally { Files.deleteIfExists(evidenceStage); }
        println("native-frame-export=PASS frames=" + plan.frames().size() + " observations=" + recovered.observations().size() +
            " source-lines=" + source.mappedLines().size() + " delta=" + delta);
    }
}

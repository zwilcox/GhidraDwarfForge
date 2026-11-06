// Safe GhidraDwarfForge entry point used by the GUI Script Manager and headless analyzer.
// @category DWARF

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.ExporterPreflight;
import ghidradwarfforge.GhidraArm32FunctionModes;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraFunctionAliases;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraInstructionEvidence;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraTargetAgreement;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.PackagedNativeLibraries;
import ghidradwarfforge.output.ArtifactPairPublisher;
import ghidradwarfforge.output.AttachmentPreparation;
import ghidradwarfforge.output.ExportReport;
import ghidradwarfforge.output.CoverageReportClaims;
import ghidradwarfforge.output.CoverageReportJson;
import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.OutputPathPolicy;
import ghidradwarfforge.performance.ExportPhase;
import ghidra.util.exception.CancelledException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.function.Consumer;

public class GhidraDwarfForge extends GhidraScript {

    @Override
    protected void run() throws Exception {
        try {
            ExportPhase.measure("export", () -> {
                runExport();
                return null;
            });
        }
        catch (CancelledException | CancellationException cancelled) {
            printerr("GhidraDwarfForge report: " +
                ExportReport.terminal(ExportReport.Status.CANCELLED, cancelled)
                    .toJsonWithCoverage(null, () -> false));
            throw cancelled;
        }
        catch (Exception failure) {
            printerr("GhidraDwarfForge report: " +
                ExportReport.terminal(ExportReport.Status.FATAL, failure)
                    .toJsonWithCoverage(null, () -> false));
            throw failure;
        }
    }

    private void runExport() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("GhidraDwarfForge requires an open program");
        }

        println(ExporterPreflight.describe(currentProgram));
        String[] arguments = getScriptArgs();
        if (arguments.length == 0) {
            println("Symbol export was not requested. Pass --packaged-natives or explicit " +
                "--libdwarf and --libdwarfp paths to enable the exporter.");
            return;
        }

        Map<String, String> options = parseOptions(arguments);
        var annotationLimits = ghidradwarfforge.source.AnnotationLimits.fromOptions(options);
        var sourceContextMode = ghidradwarfforge.source.SourceContextMode.parse(
            options.getOrDefault("source-context", "off"));
        var compression = ghidradwarfforge.elf.DebugSectionCompression.parse(
            options.getOrDefault("compress-debug-sections", "none"));
        boolean attachmentPreparation = options.containsKey("attachment-preparation");
        if (attachmentPreparation) {
            state.removeEnvironmentVar(AttachmentPreparation.EXPORT_REPORT_KEY);
            if (isRunningHeadless() || !options.containsKey("input") || !options.containsKey("output") ||
                    options.containsKey("gdb-loader")) {
                throw new IllegalArgumentException("attachment preparation requires GUI-selected input/output and a fresh pair");
            }
        }
        boolean packagedNatives = options.containsKey("packaged-natives");
        boolean explicitConsumer = options.containsKey("libdwarf");
        boolean explicitProducer = options.containsKey("libdwarfp");
        if (explicitConsumer != explicitProducer) {
            throw new IllegalArgumentException(
                "--libdwarf and --libdwarfp must be supplied together");
        }
        if (packagedNatives && explicitConsumer) {
            throw new IllegalArgumentException(
                "--packaged-natives cannot be combined with explicit native paths");
        }
        Path consumer;
        Path producer;
        if (packagedNatives) {
            PackagedNativeLibraries.Pair pair = PackagedNativeLibraries.resolve();
            consumer = pair.consumer();
            producer = pair.producer();
            println("  native policy: verified packaged libraries in " + pair.directory());
        }
        else if (explicitConsumer) {
            consumer = hostPath(options.get("libdwarf"));
            producer = hostPath(options.get("libdwarfp"));
            println("  native policy: explicit library paths");
        }
        else {
            throw new IllegalArgumentException(
                "pass --packaged-natives or both --libdwarf and --libdwarfp");
        }
        String executablePath = options.getOrDefault("input",
            currentProgram.getExecutablePath());
        if (executablePath == null || executablePath.isBlank()) {
            throw new IllegalStateException(
                "The current program has no executable path; supply --input=<original-ELF>");
        }
        Path requestedInput = hostPath(executablePath);
        Path requestedOutput = options.containsKey("output")
                ? hostPath(options.get("output")) : null;
        OutputPathPolicy.ExportPaths paths;
        boolean guiFallback = false;
        try {
            paths = OutputPathPolicy.resolve(requestedInput, requestedOutput);
        }
        catch (IOException defaultFailure) {
            if (requestedOutput != null || isRunningHeadless() ||
                    !Files.isRegularFile(requestedInput) ||
                    !Files.isReadable(requestedInput)) {
                String hint = isRunningHeadless() && requestedOutput == null &&
                        Files.isRegularFile(requestedInput) && Files.isReadable(requestedInput)
                        ? "; supply --output=<writable-sidecar-path>" : "";
                throw new IOException(defaultFailure.getMessage() + hint, defaultFailure);
            }
            Path selectedDirectory = askDirectory(
                "Select GhidraDwarfForge output directory", "Select").toPath();
            Path selectedOutput = selectedDirectory.resolve(
                requestedInput.getFileName() + ".dbg");
            paths = OutputPathPolicy.resolve(requestedInput, selectedOutput);
            guiFallback = true;
        }
        Path input = paths.input();
        Path output = paths.artifact();
        Path sourceOutput = paths.source();
        boolean gdbLoader = options.containsKey("gdb-loader");
        Path companionOutput = output.resolveSibling(output.getFileName() + ".gdb.py");
        if (gdbLoader) {
            ghidradwarfforge.output.CompanionArtifactPublisher.validate(
                input, output, sourceOutput, companionOutput, consumer, producer);
        }
        var consistency = ghidradwarfforge.GhidraExportConsistency.capture(
            currentProgram, input, monitor::isCancelled);
        String inputHash = consistency.inputSha256();
        String importedHash = currentProgram.getExecutableSHA256();
        if (importedHash != null && !importedHash.isBlank() &&
                !importedHash.equalsIgnoreCase(inputHash)) {
            throw new IllegalStateException("selected original ELF does not match Ghidra's " +
                "imported executable SHA-256: " + input);
        }
        println("  input: " + input);
        println("  output policy: " + (guiFallback ? "GUI fallback" :
            (paths.defaultOutput() ? "default beside executable" : "explicit")));

        ElfImage originalElf = ElfImage.read(input);
        DwarfTarget target = GhidraTargetAgreement.requireAgreement(currentProgram, originalElf);
        long elfLoadBase = originalElf.preferredImageBase();
        long importedImageBase = GhidraImageBase.originalImageBase(currentProgram);
        long rebaseDelta = AddressNormalizer.rebaseDelta(
            currentProgram.getImageBase().getOffset(), importedImageBase);
        println("  ELF minimum PT_LOAD VA: 0x" + Long.toHexString(elfLoadBase));
        println("  Ghidra original ELF image base: 0x" + Long.toHexString(importedImageBase));
        println("  Ghidra-to-ELF address delta: 0x" + Long.toHexString(rebaseDelta));
        List<String> diagnostics = new ArrayList<>();
        Consumer<String> diagnostic = message -> {
            diagnostics.add(message);
            printerr("GhidraDwarfForge: " + message);
        };
        var extraction = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor,
            diagnostic, rebaseDelta);
        var functions = extraction.functions();
        var decoded = ExportPhase.measure("coverage-instruction-capture", () ->
            GhidraInstructionEvidence.capture(currentProgram, functions,
                rebaseDelta, monitor, diagnostic));
        var aliases = GhidraFunctionAliases.extract(currentProgram, functions,
            rebaseDelta, monitor, diagnostic);
        var sectionModes = ghidradwarfforge.GhidraArm32SectionModes.extract(currentProgram,
            originalElf, functions, target, rebaseDelta, monitor, diagnostic);
        var modeCues = GhidraArm32FunctionModes.extract(currentProgram, functions,
            target, rebaseDelta, monitor, diagnostic);
        var aliasModeCues = GhidraArm32FunctionModes.extractAliases(currentProgram, aliases,
            target, rebaseDelta, monitor, diagnostic);
        monitor.checkCancelled();
        var allocation = ghidradwarfforge.targets.TargetParameterAllocation.forProgram(
            currentProgram, originalElf, monitor, diagnostic);
        var inventory = ExportPhase.measure("annotation-inventory", () ->
            ghidradwarfforge.GhidraAnnotationInventory.read(currentProgram,
                new ghidradwarfforge.GhidraAnnotationInventory.Limits(
                    annotationLimits.records(), annotationLimits.textUnits()), monitor));
        var dynamicEquates = new ghidradwarfforge.GhidraEquateEvidence.DynamicCollector(currentProgram, inventory, monitor);
        var sourceContext = new ghidradwarfforge.GhidraSourceContext(currentProgram, sourceContextMode,
            ghidradwarfforge.GhidraSourceContext.Limits.DEFAULT);
        var decompilation = ExportPhase.measure("decompilation-and-source", () ->
            GhidraSyntheticSource.decompileDetailed(currentProgram, functions,
                rebaseDelta, monitor, (decompiler, function, timeout, taskMonitor) -> {
                    var result = decompiler.decompileFunction(function, timeout, taskMonitor);
                    sourceContext.accept(function, result, taskMonitor);
                    if (result != null && result.decompileCompleted() && result.getHighFunction() != null) {
                        dynamicEquates.accept(result.getHighFunction(), taskMonitor);
                    }
                    return result;
                }, allocation, diagnostic));
        monitor.checkCancelled();
        var registers = ghidradwarfforge.locations.TargetRegisterMap.forElf(
            target.name(), originalElf, monitor::isCancelled);
        var typeModel = ExportPhase.measure("types-and-storage", () -> {
            var extractedTypes = GhidraTypeGraph.extract(currentProgram, functions, registers,
                rebaseDelta, monitor, diagnostic, decompilation.recoveredReturns(),
                decompilation.recoveredParameters(), decompilation.recoveredStatics(),
                allocation);
            return ghidradwarfforge.GhidraCompilerCallPolicy.apply(currentProgram,
                target, originalElf, extractedTypes, monitor, diagnostic);
        });
        monitor.checkCancelled();
        var annotated = ExportPhase.measure("source-annotations", () -> {
            var contextualSource = sourceContext.compose(decompilation.source(), rebaseDelta,
                annotationLimits.sourceBytes(), monitor);
            var evidence = ghidradwarfforge.GhidraEquateEvidence.interpret(currentProgram, inventory,
                dynamicEquates.snapshot(monitor), monitor);
            if (evidence.isEmpty()) {
                var comments = ghidradwarfforge.GhidraListingAnnotationSource.compose(currentProgram,
                    inventory, contextualSource, rebaseDelta, annotationLimits.sourceBytes(), monitor).source();
                return new PreparedSource(comments,
                    new ghidradwarfforge.annotations.SyntheticConstants(List.of(), java.util.Set.of()));
            }
            var reserved = ghidradwarfforge.elf.EquateNameReservations.read(originalElf, typeModel,
                functions, aliases, monitor::isCancelled, diagnostic);
            reserved = ghidradwarfforge.GhidraEquateNames.extend(currentProgram, reserved, monitor);
            var catalog = ghidradwarfforge.annotations.EquateCatalog.plan(evidence, reserved, reserved.size(), monitor::isCancelled);
            var constants = catalog.entries().stream().flatMap(entry -> entry.constants().stream())
                .map(constant -> new ghidradwarfforge.annotations.SyntheticConstant(constant.name(),
                    constant.value().bits(), constant.value().signed(), constant.value().value())).toList();
            try {
                var comments = ghidradwarfforge.GhidraListingAnnotationSource.compose(currentProgram,
                    inventory, contextualSource, rebaseDelta, annotationLimits.sourceBytes(), monitor).source();
                var source = ghidradwarfforge.GhidraEquateSource.compose(comments, catalog, annotationLimits.sourceBytes(), monitor);
                return new PreparedSource(source, new ghidradwarfforge.annotations.SyntheticConstants(constants,
                    reserved.namedReservations()));
            }
            catch (IllegalArgumentException limit) {
                throw new IllegalArgumentException(limit.getMessage() +
                    "; raise --annotation-source-limit to preserve the full source; outputs were not published", limit);
            }
        });
        var source = annotated.source();
        var resultHolder = new MinimalDwarfSidecarExporter.ExportResult[1];
        var stagedSidecarHolder = new Path[1];
        var reportHolder = new PreparedReport[1];
        consistency.requireUnchanged(monitor::isCancelled);
        ArtifactPairPublisher.PrePublishCheck prePublishCheck = () ->
            consistency.requireUnchanged(monitor::isCancelled);
        ArtifactPairPublisher.StagedWriter sidecarWriter = stagedOutput -> {
            resultHolder[0] = new MinimalDwarfSidecarExporter(compression).export(
                input, stagedOutput,
                consumer, producer, functions, source, typeModel,
                sourceOutput.getFileName().toString(), monitor::isCancelled,
                modeCues, aliases, aliasModeCues, sectionModes, annotated.constants(), diagnostic);
            stagedSidecarHolder[0] = stagedOutput;
        };
        ArtifactPairPublisher.StagedWriter sourceWriter = stagedSource -> {
            source.writeAtomically(stagedSource);
            // Validate the complete report while both files are still staged. Report
            // paths describe the final generation; digests describe its staged bytes.
            var result = resultHolder[0];
            var coverage = ExportPhase.measure("coverage-assembly", () ->
                ExportCoverage.build(typeModel, source, decoded, result.emission(),
                    monitor::isCancelled));
            var profile = new CoverageReportJson.Profile(
                currentProgram.getLanguageID().getIdAsString(),
                currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
            String outputHash = FileDigests.read(stagedSidecarHolder[0], monitor::isCancelled).sha256();
            String sourceHash = FileDigests.read(stagedSource, monitor::isCancelled).sha256();
            ExportReport report = ExportReport.completed(result.target(), result.libdwarfVersion(),
                input, inputHash, output, outputHash, sourceOutput, sourceHash,
                result.functionCount(), result.sectionNames(), source, typeModel,
                extraction.skippedFunctions(), diagnostics);
            var typeEvidence = ExportPhase.measure("coverage-type-evidence", () ->
                ghidradwarfforge.output.CoverageTypeEvidence.capture(typeModel, result.emission(), coverage,
                    monitor::isCancelled));
            var claims = new CoverageReportClaims(profile, coverage, typeEvidence);
            String json = ExportPhase.measure("coverage-report-preflight", () ->
                report.toJsonWithCoverage(claims,
                    monitor::isCancelled));
            reportHolder[0] = new PreparedReport(json, outputHash, sourceHash, claims, report.status().name());
        };
        if (gdbLoader) {
            ghidradwarfforge.output.CompanionArtifactPublisher.stageAndPublish(
                input, output, sourceOutput, companionOutput, (stagedSidecar, stagedSource, stagedCompanion) -> {
                    sidecarWriter.write(stagedSidecar);
                    sourceWriter.write(stagedSource);
                    String companion = ghidradwarfforge.elf.GdbCompanion.render(input,
                        stagedSidecar, stagedSource, output, sourceOutput, monitor::isCancelled);
                    Files.writeString(stagedCompanion, companion, java.nio.charset.StandardCharsets.UTF_8);
                }, prePublishCheck::check);
        }
        else if (attachmentPreparation) {
            ArtifactPairPublisher.stageAndPublishNew(output, sourceOutput,
                sidecarWriter, sourceWriter, prePublishCheck);
        }
        else {
            ArtifactPairPublisher.stageAndPublish(output, sourceOutput,
                sidecarWriter, sourceWriter, prePublishCheck);
        }
        MinimalDwarfSidecarExporter.ExportResult result = resultHolder[0];
        PreparedReport prepared = reportHolder[0];
        println("GhidraDwarfForge symbol export PASS");
        println("  output: " + output);
        println("  output SHA-256: " + prepared.outputHash());
        println("  input SHA-256: " + inputHash);
        println("  target: " + result.target().name());
        println("  functions: " + result.functionCount());
        println("  sections: " + result.sectionNames());
        println("  source: " + sourceOutput);
        println("  source SHA-256: " + prepared.sourceHash());
        if (gdbLoader) {
            println("  GDB companion: " + companionOutput);
            println("  GDB companion SHA-256: " + sha256(companionOutput));
            println("  Load explicitly in GDB with: source " + companionOutput);
        }
        println("  decompiled functions: " + source.functions().stream()
            .filter(function -> function.decompiled()).count());
        println("  mapped source lines: " + source.mappedLines().size());
        println("  function signatures: " + typeModel.functions().size());
        println("  local variables: " + typeModel.functions().stream()
            .mapToInt(function -> function.locals().size()).sum());
        println("  defensible variable locations: " + typeModel.variableStorage().variables()
            .stream().filter(variable -> variable.hasDefensibleLocation()).count());
        println("  omitted variable locations: " + typeModel.variableStorage().variables()
            .stream().filter(variable -> !variable.hasDefensibleLocation()).count());
        println("  canonical types: " + typeModel.types().nodes().size());
        println("  global variables: " + typeModel.globals().size());
        println("  function-owned static variables: " +
            ghidradwarfforge.source.FunctionStaticPolicy.select(typeModel, source)
                .exported().size());
        if (attachmentPreparation) state.addEnvironmentVar(AttachmentPreparation.EXPORT_REPORT_KEY, prepared.json());
        if (isRunningHeadless()) {
            println("GhidraDwarfForge report: " + prepared.json());
        }
        else {
            println("GhidraDwarfForge report: schema 2; " +
                ghidradwarfforge.output.CoveragePresentation.summary(prepared.coverage(), prepared.status()));
            if (!attachmentPreparation) {
                // Publication is already complete. A presentation failure must not
                // change the export outcome or masquerade as an artifact failure.
                javax.swing.SwingUtilities.invokeLater(() -> {
                    try {
                        ghidradwarfforge.output.CoverageReportGui.show(state.getTool().getToolFrame(),
                            prepared.coverage(), prepared.status(), prepared.json(),
                            output.resolveSibling(output.getFileName() + ".report.json"));
                    }
                    catch (RuntimeException failure) {
                        printerr("Coverage window could not open; artifacts were exported: " + failure);
                    }
                });
            }
        }
    }

    private record PreparedSource(ghidradwarfforge.source.SyntheticSourceFile source,
            ghidradwarfforge.annotations.SyntheticConstants constants) { }

    private record PreparedReport(String json, String outputHash, String sourceHash,
            CoverageReportClaims coverage, String status) { }

    private static Map<String, String> parseOptions(String[] arguments) {
        Map<String, String> result = new LinkedHashMap<>();
        for (int index = 0; index < arguments.length; index++) {
            String argument = arguments[index];
            if (!argument.startsWith("--")) {
                throw new IllegalArgumentException(
                    "expected --name=value or --name value script argument, found " + argument);
            }
            int separator = argument.indexOf('=');
            String name;
            String value;
            if (separator >= 0) {
                name = argument.substring(2, separator);
                value = argument.substring(separator + 1);
            }
            else {
                name = argument.substring(2);
                if (name.equals("packaged-natives") || name.equals("gdb-loader") || name.equals("attachment-preparation")) {
                    value = "true";
                }
                else {
                    if (++index >= arguments.length || arguments[index].startsWith("--")) {
                        throw new IllegalArgumentException("missing value for option " + argument);
                    }
                    value = arguments[index];
                }
            }
            if (name.isBlank() || value.isBlank() || result.put(name, value) != null) {
                throw new IllegalArgumentException("invalid/duplicate option " + argument);
            }
        }
        for (String name : result.keySet()) {
            if (!name.equals("libdwarf") && !name.equals("libdwarfp") &&
                    !name.equals("input") && !name.equals("output") &&
                    !name.equals("packaged-natives") && !name.equals("gdb-loader") && !name.equals("attachment-preparation") &&
                    !name.equals("compress-debug-sections") && !name.equals("source-context") &&
                    !name.equals("annotation-record-limit") && !name.equals("annotation-text-limit") &&
                    !name.equals("annotation-source-limit")) {
                throw new IllegalArgumentException("unknown option --" + name);
            }
            if ((name.equals("packaged-natives") || name.equals("gdb-loader") || name.equals("attachment-preparation")) &&
                    !result.get(name).equals("true")) {
                throw new IllegalArgumentException("--" + name + " does not take a value");
            }
        }
        return result;
    }

    private static Path hostPath(String value) {
        String normalized = value;
        if (File.separatorChar == '\\' && value.length() >= 4 && value.charAt(0) == '/' &&
                Character.isLetter(value.charAt(1)) && value.charAt(2) == ':' &&
                (value.charAt(3) == '/' || value.charAt(3) == '\\')) {
            normalized = value.substring(1);
        }
        return Path.of(normalized);
    }

    private static String sha256(Path path) throws IOException {
        // Preserve caller behavior, including hashing after pair publication:
        // this existing path does not introduce a new cancellation point.
        return FileDigests.read(path).sha256();
    }
}

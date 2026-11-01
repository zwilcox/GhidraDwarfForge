// Safe GhidraDwarfForge entry point used by the GUI Script Manager and headless analyzer.
// @category DWARF

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.ExporterPreflight;
import ghidradwarfforge.GhidraArm32FunctionModes;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraFunctionAliases;
import ghidradwarfforge.GhidraImageBase;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraTargetAgreement;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.PackagedNativeLibraries;
import ghidradwarfforge.output.ArtifactPairPublisher;
import ghidradwarfforge.output.ExportReport;
import ghidradwarfforge.output.FileDigests;
import ghidradwarfforge.output.OutputPathPolicy;
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
            runExport();
        }
        catch (CancelledException | CancellationException cancelled) {
            printerr("GhidraDwarfForge report: " +
                ExportReport.terminal(ExportReport.Status.CANCELLED, cancelled).toJson());
            throw cancelled;
        }
        catch (Exception failure) {
            printerr("GhidraDwarfForge report: " +
                ExportReport.terminal(ExportReport.Status.FATAL, failure).toJson());
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
        String inputHash = sha256(input);
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
        var aliases = GhidraFunctionAliases.extract(currentProgram, functions,
            rebaseDelta, monitor, diagnostic);
        var modeCues = GhidraArm32FunctionModes.extract(currentProgram, functions,
            target, rebaseDelta, monitor, diagnostic);
        var aliasModeCues = GhidraArm32FunctionModes.extractAliases(currentProgram, aliases,
            target, rebaseDelta, monitor, diagnostic);
        monitor.checkCancelled();
        var decompilation = GhidraSyntheticSource.decompileDetailed(currentProgram, functions,
            rebaseDelta, monitor);
        var source = decompilation.source();
        monitor.checkCancelled();
        var registers = ghidradwarfforge.locations.TargetRegisterMap.forElf(
            target.name(), originalElf, monitor::isCancelled);
        var extractedTypes = GhidraTypeGraph.extract(currentProgram, functions, registers,
            rebaseDelta, monitor, diagnostic, decompilation.recoveredReturns(),
            decompilation.recoveredParameters(), decompilation.recoveredStatics(),
            ghidradwarfforge.targets.Aarch64ParameterAllocation.forProgram(currentProgram, originalElf, monitor, diagnostic));
        var typeModel = ghidradwarfforge.GhidraCompilerCallPolicy.apply(currentProgram,
            target, extractedTypes, monitor, diagnostic);
        monitor.checkCancelled();
        var resultHolder = new MinimalDwarfSidecarExporter.ExportResult[1];
        ArtifactPairPublisher.stageAndPublish(output, sourceOutput,
            stagedOutput -> resultHolder[0] = new MinimalDwarfSidecarExporter().export(
                input, stagedOutput,
                consumer, producer, functions, source, typeModel,
                sourceOutput.getFileName().toString(), monitor::isCancelled,
                modeCues, aliases, aliasModeCues, diagnostic),
            source::writeAtomically, monitor::checkCancelled);
        MinimalDwarfSidecarExporter.ExportResult result = resultHolder[0];
        String outputHash = sha256(output);
        String sourceHash = sha256(sourceOutput);
        ExportReport report = ExportReport.completed(result.target(), result.libdwarfVersion(),
            input, inputHash, output, outputHash, sourceOutput, sourceHash,
            result.functionCount(), result.sectionNames(), source, typeModel,
            extraction.skippedFunctions(), diagnostics);
        println("GhidraDwarfForge symbol export PASS");
        println("  output: " + output);
        println("  output SHA-256: " + outputHash);
        println("  input SHA-256: " + inputHash);
        println("  target: " + result.target().name());
        println("  functions: " + result.functionCount());
        println("  sections: " + result.sectionNames());
        println("  source: " + sourceOutput);
        println("  source SHA-256: " + sourceHash);
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
        println("GhidraDwarfForge report: " + report.toJson());
    }

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
                if (name.equals("packaged-natives")) {
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
                    !name.equals("packaged-natives")) {
                throw new IllegalArgumentException("unknown option --" + name);
            }
            if (name.equals("packaged-natives") && !result.get(name).equals("true")) {
                throw new IllegalArgumentException("--packaged-natives does not take a value");
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

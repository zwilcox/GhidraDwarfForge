// Safe GhidraDwarfForge entry point used by the GUI Script Manager and headless analyzer.
// @category DWARF

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.ExporterPreflight;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.output.ArtifactPairPublisher;
import ghidradwarfforge.output.ExportReport;
import ghidradwarfforge.output.OutputPathPolicy;
import ghidra.util.exception.CancelledException;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

public class GhidraDwarfForge extends GhidraScript {

    @Override
    protected void run() throws Exception {
        try {
            runExport();
        }
        catch (CancelledException cancelled) {
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
            println("Symbol export was not requested. Pass explicit --libdwarf and " +
                "--libdwarfp paths to enable the isolated P0 exporter.");
            return;
        }

        Map<String, String> options = parseOptions(arguments);
        String consumer = requireOption(options, "libdwarf");
        String producer = requireOption(options, "libdwarfp");
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
                String hint = isRunningHeadless() && requestedOutput == null
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
        int elfPointerSize = originalElf.is64Bit() ? 8 : 4;
        boolean elfBigEndian = originalElf.byteOrder() == java.nio.ByteOrder.BIG_ENDIAN;
        if (currentProgram.getDefaultPointerSize() != elfPointerSize ||
                currentProgram.getLanguage().isBigEndian() != elfBigEndian) {
            throw new IllegalStateException(
                "Ghidra program language does not match the original ELF class/byte order");
        }
        long rebaseDelta = AddressNormalizer.rebaseDelta(
            currentProgram.getImageBase().getOffset(), originalElf.preferredImageBase());
        DwarfTarget target = DwarfTarget.fromElf(originalElf);
        println("  Ghidra-to-ELF address delta: 0x" + Long.toHexString(rebaseDelta));
        List<String> diagnostics = new ArrayList<>();
        Consumer<String> diagnostic = message -> {
            diagnostics.add(message);
            printerr("GhidraDwarfForge: " + message);
        };
        var extraction = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor,
            diagnostic, rebaseDelta);
        var functions = extraction.functions();
        monitor.checkCancelled();
        var source = GhidraSyntheticSource.decompile(currentProgram, functions,
            rebaseDelta, monitor);
        monitor.checkCancelled();
        var typeModel = GhidraTypeGraph.extract(currentProgram, functions, target.name(),
            rebaseDelta, monitor, diagnostic);
        monitor.checkCancelled();
        var resultHolder = new MinimalDwarfSidecarExporter.ExportResult[1];
        ArtifactPairPublisher.stageAndPublish(output, sourceOutput,
            stagedOutput -> resultHolder[0] = new MinimalDwarfSidecarExporter().export(
                input, stagedOutput,
                hostPath(consumer), hostPath(producer), functions, source, typeModel,
                sourceOutput.getFileName().toString()),
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
                if (++index >= arguments.length || arguments[index].startsWith("--")) {
                    throw new IllegalArgumentException("missing value for option " + argument);
                }
                value = arguments[index];
            }
            if (name.isBlank() || value.isBlank() || result.put(name, value) != null) {
                throw new IllegalArgumentException("invalid/duplicate option " + argument);
            }
        }
        for (String name : result.keySet()) {
            if (!name.equals("libdwarf") && !name.equals("libdwarfp") &&
                    !name.equals("input") && !name.equals("output")) {
                throw new IllegalArgumentException("unknown option --" + name);
            }
        }
        return result;
    }

    private static String requireOption(Map<String, String> options, String name) {
        String value = options.get(name);
        if (value == null) {
            throw new IllegalArgumentException("missing required option --" + name);
        }
        return value;
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

    private static String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) >= 0;) {
                digest.update(buffer, 0, count);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}

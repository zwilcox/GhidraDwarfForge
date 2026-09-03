// Runs the production exporter with one deterministic decompilation failure.
// @category DWARF.Tests

import ghidra.app.script.GhidraScript;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.AddressNormalizer;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.output.ArtifactPairPublisher;
import ghidradwarfforge.output.ExportReport;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.function.Consumer;

public class ControlledDecompilerFailureExport extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length != 4) {
            throw new IllegalArgumentException(
                "usage: ControlledDecompilerFailureExport <libdwarf> <libdwarfp> " +
                    "<output> <failed-function>");
        }
        Path consumer = Path.of(arguments[0]).toAbsolutePath().normalize();
        Path producer = Path.of(arguments[1]).toAbsolutePath().normalize();
        Path output = Path.of(arguments[2]).toAbsolutePath().normalize();
        String failedName = arguments[3];
        Path input = Path.of(currentProgram.getExecutablePath()).toAbsolutePath().normalize();
        ElfImage elf = ElfImage.read(input);
        long rebaseDelta = AddressNormalizer.rebaseDelta(
            currentProgram.getImageBase().getOffset(), elf.preferredImageBase());
        DwarfTarget target = DwarfTarget.fromElf(elf);
        List<String> diagnostics = new ArrayList<>();
        Consumer<String> diagnostic = message -> {
            diagnostics.add(message);
            printerr("controlled-failure: " + message);
        };
        var extraction = GhidraFunctionSymbols.extractDetailed(currentProgram, monitor,
            diagnostic, rebaseDelta);
        var functions = extraction.functions();
        var source = GhidraSyntheticSource.decompile(currentProgram, functions,
            rebaseDelta, monitor, (decompiler, function, timeoutSeconds, taskMonitor) -> {
                if (function.getName().equals(failedName)) {
                    throw new IllegalStateException("controlled integration failure");
                }
                return decompiler.decompileFunction(function, timeoutSeconds, taskMonitor);
            });
        var failedFunction = source.functions().stream()
            .filter(function -> function.name().equals(failedName)).findFirst().orElseThrow();
        long failures = source.functions().stream().filter(function -> !function.decompiled())
            .count();
        boolean laterSuccess = source.functions().stream()
            .anyMatch(function -> function.address() > failedFunction.address() &&
                function.decompiled());
        if (failedFunction.decompiled() || failures != 1 || !laterSuccess) {
            throw new AssertionError("controlled failure was not isolated");
        }
        var typeModel = GhidraTypeGraph.extract(currentProgram, functions, target.name(),
            rebaseDelta, monitor, diagnostic);
        Path sourceOutput = Path.of(output + ".c");
        var resultHolder = new MinimalDwarfSidecarExporter.ExportResult[1];
        ArtifactPairPublisher.stageAndPublish(output, sourceOutput,
            stagedOutput -> resultHolder[0] = new MinimalDwarfSidecarExporter().export(
                input, stagedOutput,
                consumer, producer, functions, source, typeModel,
                sourceOutput.getFileName().toString()),
            source::writeAtomically, monitor::checkCancelled);
        var result = resultHolder[0];
        var report = ExportReport.completed(result.target(), result.libdwarfVersion(), input,
            sha256(input), output, sha256(output), sourceOutput, sha256(sourceOutput),
            result.functionCount(), result.sectionNames(), source, typeModel,
            extraction.skippedFunctions(), diagnostics);
        println("GhidraDwarfForge report: " + report.toJson());
        println("controlled-decompiler-failure-export=PASS");
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

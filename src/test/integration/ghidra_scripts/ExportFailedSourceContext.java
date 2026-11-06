// Exercise real native decompilation failures through production source/type/DWARF components.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompileOptions;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.GhidraSourceContext;
import ghidradwarfforge.GhidraTypeGraph;
import ghidradwarfforge.GhidraTargetAgreement;
import ghidradwarfforge.GhidraAnnotationInventory;
import ghidradwarfforge.GhidraListingAnnotationSource;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.source.SourceContextMode;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

public class ExportFailedSourceContext extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("labels input output-directory consumer producer");
        var labels = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        long delta = Math.subtractExact(currentProgram.getImageBase().getOffset(), labels.getAsJsonObject("_imageBase").get("address").getAsLong());
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, ignored -> {}, delta).stream()
            .filter(function -> List.of("annotation_probe", "annotation_conflicts", "annotation_failure").contains(function.name())).toList();
        if (functions.size() != 3) throw new AssertionError("selected function set missing");
        var target = GhidraTargetAgreement.requireAgreement(currentProgram, ElfImage.read(Path.of(args[1])));
        var decoded = ghidradwarfforge.GhidraInstructionEvidence.capture(currentProgram, functions, delta, monitor, ignored -> {});
        var inventory = GhidraAnnotationInventory.read(currentProgram, new GhidraAnnotationInventory.Limits(10000, 1000000), monitor);
        Path directory = Path.of(args[2]);
        Files.createDirectories(directory);
        for (String mode : List.of("all", "mixed")) {
            var context = new GhidraSourceContext(currentProgram, SourceContextMode.BOTH, GhidraSourceContext.Limits.DEFAULT);
            var failures = new ArrayList<String>();
            var decompiled = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, monitor,
                (decompiler, function, timeout, taskMonitor) -> {
                    var options = new DecompileOptions();
                    options.setPRECommentIncluded(false); options.setPLATECommentIncluded(false);
                    options.setPOSTCommentIncluded(false); options.setEOLCommentIncluded(false);
                    options.setHeadCommentIncluded(false); options.setWARNCommentIncluded(true);
                    boolean fail = mode.equals("all") || function.getName().equals("annotation_probe");
                    if (fail) options.setMaxInstructions(1);
                    if (!decompiler.setOptions(options)) throw new AssertionError("native options rejected");
                    var result = decompiler.decompileFunction(function, timeout, taskMonitor);
                    if (fail) {
                        if (result.decompileCompleted() || !result.getErrorMessage().contains("maximum allowable instructions"))
                            throw new AssertionError("expected genuine native instruction-limit failure");
                        failures.add(function.getName());
                    }
                    else if (!result.decompileCompleted()) throw new AssertionError("subsequent native function did not recover");
                    context.accept(function, result, taskMonitor);
                    return result;
                });
            if (failures.size() != (mode.equals("all") ? 3 : 1)) throw new AssertionError("failure count differs");
            var types = GhidraTypeGraph.extract(currentProgram, functions, target.name(), delta, monitor,
                ignored -> {}, decompiled.recoveredReturns(), decompiled.recoveredParameters());
            var contextual = context.compose(decompiled.source(), delta, 4 * 1024 * 1024, monitor);
            var annotated = GhidraListingAnnotationSource.compose(currentProgram, inventory, contextual, delta,
                4 * 1024 * 1024, monitor);
            if (mode.equals("all") && (!annotated.source().mappedLines().isEmpty() ||
                    annotated.source().functions().stream().anyMatch(function -> function.decompiled())))
                throw new AssertionError("all-failed source acquired executable evidence");
            Path output = directory.resolve(mode + ".dbg");
            annotated.source().writeAtomically(Path.of(output + ".c"));
            var emitted = new MinimalDwarfSidecarExporter().export(Path.of(args[1]), output, Path.of(args[3]), Path.of(args[4]),
                functions, annotated.source(), types);
            if (!emitted.sectionNames().contains(".debug_line")) throw new AssertionError("source-file table is missing");
            var receipt = new TreeMap<String, Object>();
            receipt.put("mode", mode); receipt.put("nativeFailures", failures);
            receipt.put("sourceFunctions", annotated.source().functions());
            receipt.put("mappedLines", annotated.source().mappedLines());
            receipt.put("emittedLines", emitted.emission().lines());
            var coverage = ghidradwarfforge.coverage.ExportCoverage.build(types, annotated.source(), decoded,
                emitted.emission(), monitor::isCancelled);
            receipt.put("sourceCoverage", coverage.functions().stream().map(function -> function.source()).toList());
            for (var function : coverage.functions()) {
                if (failures.contains(function.function().name()) &&
                        (function.source().lineVisibleInstructions() != 0 || function.signature().emitted())) {
                    throw new AssertionError("failed function acquired emitted coverage or signature");
                }
            }
            receipt.put("functions", functions); receipt.put("recoveredSignatures", types.functions().size());
            receipt.put("origin", MinimalDwarfSidecarExporter.class.getProtectionDomain().getCodeSource().getLocation().toString());
            Files.writeString(directory.resolve(mode + ".json"), new GsonBuilder().setPrettyPrinting().create().toJson(receipt) + "\n");
        }
        println("failed-source-context=PASS");
    }
}

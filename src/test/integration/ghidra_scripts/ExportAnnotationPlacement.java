// Compose saved comments with actual native decompiler evidence and export a controlled sidecar.
// @category DWARF.Tests
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraAnnotationInventory;
import ghidradwarfforge.GhidraFunctionSymbols;
import ghidradwarfforge.GhidraListingAnnotationSource;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.TreeMap;

public class ExportAnnotationPlacement extends GhidraScript {
    private static final class ProbeMonitor extends TaskMonitorAdapter {
        private final int cancelAt;
        private int checks;
        private ProbeMonitor(int cancelAt) { super(true); this.cancelAt = cancelAt; }
        @Override public boolean isCancelled() { return ++checks == cancelAt || super.isCancelled(); }
        @Override public void checkCancelled() throws CancelledException {
            if (++checks == cancelAt) throw new CancelledException();
            super.checkCancelled();
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5) throw new IllegalArgumentException("labels input output consumer producer");
        var labels = JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        long delta = Math.subtractExact(currentProgram.getImageBase().getOffset(),
            labels.getAsJsonObject("_imageBase").get("address").getAsLong());
        var diagnostics = new ArrayList<String>();
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, diagnostics::add, delta)
            .stream().filter(function -> List.of("annotation_probe", "annotation_conflicts", "annotation_failure")
                .contains(function.name())).toList();
        if (functions.size() != 3) throw new AssertionError("missing selected fixture functions");
        var inventory = GhidraAnnotationInventory.read(currentProgram,
            new GhidraAnnotationInventory.Limits(10000, 1000000), monitor);
        var failures = new ArrayList<String>();
        var decompiled = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, monitor,
            (decompiler, function, timeout, taskMonitor) -> {
                var options = new DecompileOptions();
                options.setPRECommentIncluded(false);
                options.setPLATECommentIncluded(false);
                options.setPOSTCommentIncluded(false);
                options.setEOLCommentIncluded(false);
                options.setHeadCommentIncluded(false);
                options.setWARNCommentIncluded(true);
                boolean fail = function.getName().equals("annotation_failure");
                if (fail) options.setMaxInstructions(1);
                if (!decompiler.setOptions(options)) throw new AssertionError("native options rejected");
                var result = decompiler.decompileFunction(function, timeout, taskMonitor);
                if (fail) {
                    if (result.decompileCompleted() || !result.getErrorMessage().contains("maximum allowable instructions")) {
                        throw new AssertionError("expected genuine instruction-limit failure");
                    }
                    failures.add(result.getErrorMessage());
                }
                return result;
            }, GhidraParameterAllocation.UNCHANGED, diagnostics::add);
        var baseline = decompiled.source();
        if (failures.size() != 1 || new String(baseline.utf8(), StandardCharsets.UTF_8).contains("FORGE_ANNOTATION:")) {
            throw new AssertionError("failure missing or incidental listing comments were not suppressed");
        }
        var counting = new ProbeMonitor(-1);
        var composed = GhidraListingAnnotationSource.compose(currentProgram, inventory, baseline, delta, 1000000, counting);
        int checks = counting.checks;
        var reversed = new ArrayList<>(inventory.comments());
        Collections.reverse(reversed);
        var permuted = new GhidraAnnotationInventory.Snapshot(reversed, inventory.equates(),
            inventory.commentAddresses(), inventory.records(), inventory.textUnits());
        var repeated = GhidraListingAnnotationSource.compose(currentProgram, permuted, baseline, delta,
            composed.source().utf8().length, monitor);
        if (!Arrays.equals(composed.source().utf8(), repeated.source().utf8())) {
            throw new AssertionError("input order changed annotation source");
        }
        try {
            GhidraListingAnnotationSource.compose(currentProgram, inventory, baseline, delta,
                composed.source().utf8().length - 1, monitor);
            throw new AssertionError("short final source budget accepted");
        }
        catch (IllegalArgumentException expected) {
            if (!expected.getMessage().contains("budget")) throw expected;
        }
        for (int point : List.of(1, checks / 2, checks)) {
            try {
                GhidraListingAnnotationSource.compose(currentProgram, inventory, baseline, delta, 1000000, new ProbeMonitor(point));
                throw new AssertionError("composition cancellation ignored at " + point);
            }
            catch (CancelledException expected) { }
        }
        var placements = new ArrayList<TreeMap<String, Object>>();
        for (var placement : composed.placements()) {
            var row = new TreeMap<String, Object>();
            var comment = placement.comment();
            row.put("space", comment.address().getAddressSpace().getName());
            row.put("offset", Long.toUnsignedString(comment.address().getOffset(), 16));
            row.put("category", comment.category().name());
            row.put("text", comment.text());
            row.put("reason", placement.reason().name());
            row.put("beforeLine", placement.beforeLine());
            row.put("instruction", placement.instruction() == null ? null : placement.instruction().toString());
            row.put("elfInstruction", placement.elfInstruction());
            placements.add(row);
        }
        Path output = Path.of(args[2]);
        var exporter = new MinimalDwarfSidecarExporter();
        Path baselineOutput = output.resolveSibling("baseline.dbg");
        Files.write(Path.of(baselineOutput + ".c"), baseline.utf8());
        exporter.export(Path.of(args[1]), baselineOutput, Path.of(args[3]), Path.of(args[4]), functions, baseline);
        Files.write(Path.of(output + ".c"), composed.source().utf8());
        var emitted = exporter.export(Path.of(args[1]), output, Path.of(args[3]), Path.of(args[4]), functions, composed.source());
        var observation = new TreeMap<String, Object>();
        observation.put("baseline", baseline);
        observation.put("composed", composed.source());
        observation.put("annotationLines", composed.annotationLines());
        observation.put("placements", placements);
        observation.put("nativeFailures", failures);
        observation.put("diagnostics", diagnostics);
        observation.put("cancellationCheckpoints", List.of(1, checks / 2, checks));
        observation.put("emittedLines", emitted.emission().lines());
        observation.put("functions", functions);
        Files.writeString(Path.of(output + ".placement.json"), new GsonBuilder().serializeNulls().setPrettyPrinting()
            .create().toJson(observation) + "\n");
        println("annotation-placement=PASS comments=" + placements.size());
    }
}

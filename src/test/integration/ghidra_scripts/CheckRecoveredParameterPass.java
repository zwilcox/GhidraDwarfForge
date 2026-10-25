// Verify actual decompiler pass isolation and cancellation without program mutation.
// @category DWARF.Tests
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraSyntheticSource;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

public class CheckRecoveredParameterPass extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var names = List.of("inferred_scalar", "inferred_pointer", "inferred_floating", "unresolved_pair", "curated_scalar");
        var symbols = new ArrayList<FunctionSymbol>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (names.contains(function.getName())) {
                symbols.add(new FunctionSymbol(function.getName(), function.getEntryPoint().getOffset(),
                    function.getBody().getNumAddresses()));
            }
        }
        if (symbols.size() != 5) { throw new AssertionError("missing pass controls"); }
        var attempts = new HashMap<String, Integer>();
        var isolated = GhidraSyntheticSource.decompileDetailed(currentProgram, symbols, 0, monitor,
            (decompiler, function, seconds, taskMonitor) -> {
                attempts.merge(function.getName(), 1, Integer::sum);
                if (function.getName().equals("inferred_scalar")) {
                    throw new IllegalStateException("controlled per-function decompile failure");
                }
                return decompiler.decompileFunction(function, seconds, taskMonitor);
            });
        if (attempts.size() != 5 || attempts.values().stream().anyMatch(count -> count != 1)) {
            throw new AssertionError("repeated or lost function decompilation");
        }
        if (isolated.source().functions().stream().filter(f -> !f.decompiled()).count() != 1 ||
                isolated.recoveredParameters().size() != 3) {
            throw new AssertionError("decompiler failure erased other source or parameter evidence");
        }
        long failed = symbols.stream().filter(s -> s.name().equals("inferred_scalar")).findFirst().orElseThrow().address();
        if (isolated.recoveredParameters().containsKey(failed)) { throw new AssertionError("failed function fabricated parameters"); }
        long unsupported = symbols.stream().filter(s -> s.name().equals("unresolved_pair")).findFirst().orElseThrow().address();
        var omission = isolated.recoveredParameters().get(unsupported);
        if (omission == null || !omission.parameters().isEmpty() || omission.omission() == null) {
            throw new AssertionError("unsupported parameter list emitted partially");
        }
        try {
            isolated.recoveredParameters().clear();
            throw new AssertionError("mutable parameter evidence map");
        }
        catch (UnsupportedOperationException expected) { }
        var cancelled = new TaskMonitorAdapter(true);
        try {
            GhidraSyntheticSource.decompileDetailed(currentProgram, symbols, 0, cancelled,
                (decompiler, function, seconds, taskMonitor) -> {
                    taskMonitor.cancel();
                    return null;
                });
            throw new AssertionError("ignored in-flight cancellation");
        }
        catch (CancelledException expected) { }
        println("recovered-parameter-pass=PASS one-attempt isolation cancellation immutable-evidence");
    }
}

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

public class CheckRecoveredReturnPass extends GhidraScript {
    @Override
    protected void run() throws Exception {
        var names = List.of("recovered_signed", "recovered_unsigned", "recovered_double", "curated_pointer", "curated_void");
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
                if (function.getName().equals("recovered_signed")) {
                    throw new IllegalStateException("controlled per-function decompile failure");
                }
                return decompiler.decompileFunction(function, seconds, taskMonitor);
            });
        if (attempts.size() != 5 || attempts.values().stream().anyMatch(count -> count != 1)) {
            throw new AssertionError("repeated or lost function decompilation");
        }
        if (isolated.source().functions().stream().filter(f -> !f.decompiled()).count() != 1 ||
                isolated.recoveredReturns().size() != 2) {
            throw new AssertionError("decompiler failure erased other source or return evidence");
        }
        long failed = symbols.stream().filter(s -> s.name().equals("recovered_signed")).findFirst().orElseThrow().address();
        if (isolated.recoveredReturns().containsKey(failed)) { throw new AssertionError("failed function fabricated return"); }
        try {
            isolated.recoveredReturns().clear();
            throw new AssertionError("mutable return evidence map");
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
        println("recovered-return-pass=PASS one-attempt isolation cancellation immutable-evidence");
    }
}

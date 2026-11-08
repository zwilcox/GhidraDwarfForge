// @category DWARF.Tests
import java.nio.file.*;
import java.util.*;
import java.util.function.Consumer;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.*;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.TargetParameterAllocation;
import com.google.gson.GsonBuilder;

public class CheckI386SourceView extends GhidraScript {
    protected void run() throws Exception {
        long delta = currentProgram.getImageBase().getOffset() - GhidraImageBase.originalImageBase(currentProgram);
        var selected = Set.of("scalar_float", "scalar_double", "source_helper", "scalar_extended");
        var functions = GhidraFunctionSymbols.extract(currentProgram, monitor, ignored -> { }, delta).stream()
            .filter(f -> selected.contains(f.name())).toList();
        if (functions.size() != 4) throw new AssertionError("missing source controls");
        var policy = TargetParameterAllocation.forProgram(currentProgram,
            ElfImage.read(Path.of(currentProgram.getExecutablePath())), monitor, this::println);
        if (!policy.hasReturnCorrections()) throw new AssertionError("wrong target policy");
        var nativeFailures = new ArrayList<String>();
        var diagnostics = new ArrayList<String>();
        var source = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, monitor,
            (decompiler, function, timeout, task) -> {
                if (!function.getName().equals("source_helper")) return decompiler.decompileFunction(function, timeout, task);
                var limited = new DecompileOptions();
                limited.setMaxInstructions(1);
                if (!decompiler.setOptions(limited)) throw new AssertionError("instruction limit rejected");
                try {
                    var result = decompiler.decompileFunction(function, timeout, task);
                    if (result == null || result.decompileCompleted() || result.getErrorMessage().isBlank()) {
                        throw new AssertionError("native failure was not exercised");
                    }
                    nativeFailures.add(result.getErrorMessage());
                    return result;
                }
                finally {
                    if (!decompiler.setOptions(new DecompileOptions())) throw new AssertionError("restore failed");
                }
            }, policy, diagnostics::add).source();
        if (nativeFailures.size() != 1 || source.functions().stream().filter(f -> !f.decompiled()).count() != 1 ||
                source.functions().stream().noneMatch(f -> f.name().equals("scalar_extended") && f.decompiled())) {
            throw new AssertionError("native failure erased neighboring corrected source");
        }
        String code = new String(source.utf8(), java.nio.charset.StandardCharsets.UTF_8);
        if (!code.contains("Decompilation unavailable for source_helper") || code.contains("__return_storage_ptr__")) {
            throw new AssertionError("incorrect isolated failure source");
        }
        var cancelled = new TaskMonitorAdapter(true);
        int[] callbacks = {0};
        var cancelling = new GhidraParameterAllocation() {
            public boolean hasReturnCorrections() { return true; }
            public Map<Integer, VariableStorage> corrections(Function f, TaskMonitor task, Consumer<String> log)
                    throws CancelledException { return resolve(f, task, log).storage(); }
            public Resolution resolve(Function f, TaskMonitor task, Consumer<String> log) throws CancelledException {
                callbacks[0]++;
                task.cancel();
                return policy.resolve(f, task, log);
            }
        };
        try {
            GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, cancelled, cancelling, diagnostics::add);
            throw new AssertionError("callback cancellation returned partial source");
        }
        catch (CancelledException expected) {
            if (callbacks[0] == 0) throw new AssertionError("cancellation did not reach native callback");
        }
        var restored = GhidraSyntheticSource.decompileDetailed(currentProgram, functions, delta, monitor, policy, diagnostics::add);
        if (restored.source().functions().stream().anyMatch(f -> !f.decompiled())) {
            throw new AssertionError("fresh pass after cancellation failed");
        }
        Files.writeString(Path.of(getScriptArgs()[0]), new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("status", "PASS", "nativeFailures", nativeFailures, "cancellationCallbacks", callbacks[0],
                "restoredFunctions", restored.source().functions().size(), "diagnostics", diagnostics)));
        println("i386-source-view-controls=PASS");
    }
}

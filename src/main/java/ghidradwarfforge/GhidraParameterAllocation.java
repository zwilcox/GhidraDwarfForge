package ghidradwarfforge;

import java.util.Map;
import java.util.function.Consumer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Read-only corrections to computed storage; explicit analyst storage is authoritative. */
@FunctionalInterface
public interface GhidraParameterAllocation {
    GhidraParameterAllocation UNCHANGED = (function, monitor, diagnostic) -> Map.of();

    Map<Integer, VariableStorage> corrections(Function function, TaskMonitor monitor,
        Consumer<String> diagnostic) throws CancelledException;
}

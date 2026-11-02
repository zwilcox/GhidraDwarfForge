package ghidradwarfforge;

import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Read-only corrections to computed storage; explicit analyst storage is authoritative. */
@FunctionalInterface
public interface GhidraParameterAllocation {
    GhidraParameterAllocation UNCHANGED = (function, monitor, diagnostic) -> Map.of();

    /** Resolve both storage and compiler-generated parameters without editing the program. */
    default Resolution resolve(Function function, TaskMonitor monitor,
            Consumer<String> diagnostic) throws CancelledException {
        return new Resolution(corrections(function, monitor, diagnostic), Set.of());
    }

    /** Declarations normally need no storage resolution. */
    default Resolution resolveDeclaration(Function function, TaskMonitor monitor,
            Consumer<String> diagnostic) throws CancelledException {
        return new Resolution(Map.of(), Set.of());
    }

    record Resolution(Map<Integer, VariableStorage> storage, Set<Integer> omittedAutomaticParameters) {
        public Resolution {
            storage = Map.copyOf(storage);
            omittedAutomaticParameters = Set.copyOf(omittedAutomaticParameters);
            if (storage.keySet().stream().anyMatch(omittedAutomaticParameters::contains)) {
                throw new IllegalArgumentException("Omitted automatic parameter also has replacement storage");
            }
        }
    }

    Map<Integer, VariableStorage> corrections(Function function, TaskMonitor monitor,
        Consumer<String> diagnostic) throws CancelledException;
}

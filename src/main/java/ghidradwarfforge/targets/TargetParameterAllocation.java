package ghidradwarfforge.targets;

import java.io.IOException;
import java.util.function.Consumer;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraParameterAllocation;
import ghidradwarfforge.elf.ElfImage;

/** Select isolated allocation policies before entering the shared location analysis. */
public final class TargetParameterAllocation {
    private TargetParameterAllocation() {
    }

    public static GhidraParameterAllocation forProgram(Program program, ElfImage image,
            TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException, IOException {
        var policy = Aarch64ParameterAllocation.forProgram(program, image, monitor, diagnostic);
        if (policy != GhidraParameterAllocation.UNCHANGED) return policy;
        policy = MipsWideParameterAllocation.forProgram(program, image, monitor, diagnostic);
        if (policy != GhidraParameterAllocation.UNCHANGED) return policy;
        var floating = ArmHfaParameterAllocation.forProgram(program, image, monitor, diagnostic);
        var composite = ArmCompositeParameterAllocation.forProgram(program, image, monitor, diagnostic);
        return (function, task, report) -> {
            var corrections = new java.util.LinkedHashMap<>(floating.corrections(function, task, report));
            for (var entry : composite.corrections(function, task, report).entrySet()) {
                if (corrections.putIfAbsent(entry.getKey(), entry.getValue()) != null) {
                    throw new IllegalStateException("Overlapping target allocation corrections");
                }
            }
            return java.util.Map.copyOf(corrections);
        };
    }
}

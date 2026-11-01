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
        return policy != GhidraParameterAllocation.UNCHANGED ? policy :
            MipsWideParameterAllocation.forProgram(program, image, monitor, diagnostic);
    }
}

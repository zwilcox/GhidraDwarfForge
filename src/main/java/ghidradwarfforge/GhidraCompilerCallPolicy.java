package ghidradwarfforge;

import java.io.IOException;
import java.util.concurrent.CancellationException;
import java.util.function.Consumer;

import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.elf.MipsWideCallPolicy;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.types.DebuggerCallRestrictions;
import ghidradwarfforge.types.ProgramTypeModel;

/** Preserve curated knowledge while restricting an unverified language/compiler call ABI. */
public final class GhidraCompilerCallPolicy {
    private GhidraCompilerCallPolicy() {
    }

    /** Wide MIPS calls require the original ELF as well as the selected Ghidra ABI. */
    public static ProgramTypeModel apply(Program program, DwarfTarget target, ElfImage image,
            ProgramTypeModel model, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException, IOException {
        monitor.checkCancelled();
        if (!target.equals(DwarfTarget.fromElf(image))) {
            throw new IllegalArgumentException("compiler call target disagrees with ELF");
        }
        if (!MipsWideCallPolicy.isWideCandidate(image)) {
            return apply(program, target, model, monitor, diagnostic);
        }
        try {
            String restriction = MipsWideCallPolicy.programRestriction(image,
                program.getLanguageID().toString(), program.getCompilerSpec().getCompilerSpecID().toString(),
                monitor::isCancelled);
            return DebuggerCallRestrictions.applyAll(model, restriction, monitor::isCancelled, diagnostic);
        }
        catch (CancellationException cancelled) {
            throw new CancelledException(cancelled.getMessage());
        }
    }

    /** The caller supplies the target already checked against the original ELF and Program. */
    public static ProgramTypeModel apply(Program program, DwarfTarget target,
            ProgramTypeModel model, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        monitor.checkCancelled();
        String restriction = target.compilerSpecCallRestriction(program.getLanguageID().toString(),
            program.getCompilerSpec().getCompilerSpecID().toString());
        try {
            return DebuggerCallRestrictions.applyAll(model, restriction, monitor::isCancelled, diagnostic);
        }
        catch (CancellationException cancelled) {
            // Preserve the Ghidra API's checked cancellation contract, including
            // cancellation that occurs during traversal of the type graph.
            throw new CancelledException(cancelled.getMessage());
        }
    }
}

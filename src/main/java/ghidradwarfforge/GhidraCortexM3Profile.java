package ghidradwarfforge;

import java.io.IOException;
import java.math.BigInteger;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.CortexM3Profile;
import ghidradwarfforge.elf.ElfImage;

/** Checks an explicitly selected Cortex-M3 profile without changing program context. */
public final class GhidraCortexM3Profile {
    private GhidraCortexM3Profile() { }

    public static void requireAgreement(Program program, ElfImage image, TaskMonitor monitor)
            throws IOException, CancelledException {
        monitor.checkCancelled();
        if (!program.getLanguageID().toString().equals("ARM:LE:32:Cortex") ||
                !program.getCompilerSpec().getCompilerSpecID().toString().equals("default")) {
            throw new IllegalArgumentException("Cortex-M3 profile requires ARM:LE:32:Cortex/default");
        }
        GhidraTargetAgreement.requireAgreement(program, image);
        CortexM3Profile.requireImage(image, monitor::isCancelled);
        requireThumbCode(program, monitor);
    }

    /** Shared decoded-code check; raw firmware supplies target identity separately. */
    public static void requireThumbCode(Program program, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        Register mode = program.getRegister("TMode");
        if (mode == null) throw new IllegalArgumentException("Cortex-M3 profile requires TMode context");
        var functions = program.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            monitor.checkCancelled();
            requireThumb(program, mode, functions.next().getEntryPoint());
        }
        var instructions = program.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            requireThumb(program, mode, instructions.next().getAddress());
        }
    }

    private static void requireThumb(Program program, Register mode, Address address) {
        if ((address.getOffset() & 1) != 0 ||
                !BigInteger.ONE.equals(program.getProgramContext().getValue(mode, address, false))) {
            throw new IllegalArgumentException("Cortex-M3 profile requires even code addresses and " +
                "known Thumb context at " + address + "; no address or context repair was performed");
        }
    }
}

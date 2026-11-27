package ghidradwarfforge.targets;

import java.util.Set;

import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;

/** Recognizes the mode notification in the Ghidra 12.2 MIPS delayed return. */
public final class MipsReturnMode {
    private static final Set<String> LANGUAGES = Set.of(
        "MIPS:BE:32:default", "MIPS:LE:32:default", "MIPS:BE:64:default", "MIPS:LE:64:default",
        "MIPS:BE:64:64-32addr", "MIPS:LE:64:64-32addr");

    private MipsReturnMode() {
    }

    public static boolean isNotification(Instruction instruction, PcodeOp op) {
        if (op.getOpcode() != PcodeOp.CALLOTHER || op.getOutput() != null || op.getNumInputs() != 2 ||
                op.getInput(0) == null || !op.getInput(0).isConstant() ||
                op.getInput(1) == null || !op.getInput(1).isRegister() ||
                instruction.getFlowOverride() != FlowOverride.NONE || instruction.isInDelaySlot() ||
                instruction.getDelaySlotDepth() != 1 || !instruction.getFlowType().isTerminal()) return false;
        var program = instruction.getProgram();
        if (program == null || !LANGUAGES.contains(program.getLanguageID().toString())) return false;
        var language = program.getLanguage();
        long selector = op.getInput(0).getOffset();
        if (selector < 0 || selector >= language.getNumberOfUserDefinedOpNames() ||
                !"setISAMode".equals(language.getUserDefinedOpName((int) selector))) return false;
        // JXWritePC explicitly writes the mode register before notifying the emulator.
        // Its compiler-spec fixup is a self-copy. The other operations, including
        // the return address calculation and the delay slot, still need separate proof.
        var mode = language.getRegister("ISAModeSwitch");
        return mode != null && op.getInput(1).getSize() == mode.getMinimumByteSize() &&
            op.getInput(1).getAddress().equals(mode.getAddress());
    }
}

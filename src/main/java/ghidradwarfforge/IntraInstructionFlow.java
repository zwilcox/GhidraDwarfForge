package ghidradwarfforge;

import java.util.Arrays;

import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Forward raw p-code branches within, or to the end of, one fallthrough instruction. */
final class IntraInstructionFlow {
    private IntraInstructionFlow() {
    }

    /** Null rejects the instruction; -1 marks an ordinary operation. */
    static int[] targets(Instruction instruction, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        var flow = instruction.getFlowType();
        if (!flow.isFallthrough() || !flow.hasFallthrough() || flow.isConditional() ||
                flow.isCall() || flow.isJump() || flow.isTerminal() || flow.isComputed() ||
                flow.isOverride() || instruction.getFlowOverride() != FlowOverride.NONE ||
                instruction.isFallThroughOverridden() || instruction.isInDelaySlot() ||
                instruction.getDelaySlotDepth() != 0 || instruction.getFallThrough() == null ||
                !instruction.getFallThrough().equals(instruction.getMaxAddress().next())) return null;
        for (var addresses : new ghidra.program.model.address.Address[][] {
                instruction.getDefaultFlows(), instruction.getFlows() }) {
            if (addresses != null && addresses.length != 0) return null;
        }
        return targets(instruction.getPcode(), instruction.getFallThrough(), monitor);
    }

    static int[] targets(PcodeOp[] operations, TaskMonitor monitor) throws CancelledException {
        return targets(operations, null, monitor);
    }

    private static int[] targets(PcodeOp[] operations, ghidra.program.model.address.Address exit,
            TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        // Bound transient path states. Larger instructions remain unproven.
        if (operations == null || operations.length == 0 || operations.length > 4096) return null;
        int[] targets = new int[operations.length];
        Arrays.fill(targets, -1);
        boolean branched = false;
        for (int index = 0; index < operations.length; index++) {
            monitor.checkCancelled();
            PcodeOp operation = operations[index];
            if (operation == null) return null;
            switch (operation.getOpcode()) {
                case PcodeOp.BRANCH, PcodeOp.CBRANCH -> {
                    boolean conditional = operation.getOpcode() == PcodeOp.CBRANCH;
                    if (operation.getOutput() != null || operation.getNumInputs() != (conditional ? 2 : 1) ||
                            operation.getInput(0) == null ||
                            (conditional && (operation.getInput(1) == null || operation.getInput(1).getSize() != 1))) {
                        return null;
                    }
                    if (operation.getInput(0).isConstant()) {
                        // Relative to this operation, not the next operation.
                        long distance = operation.getInput(0).getOffset();
                        if (distance <= 0 || distance > operations.length - index) return null;
                        targets[index] = index + (int) distance;
                    }
                    else {
                        // Sleigh may encode a predicate's skipped effects as
                        // a branch to inst_next. Only the checked fallthrough
                        // is an instruction exit; no other machine target is safe.
                        if (exit == null || !exit.equals(operation.getInput(0).getAddress())) return null;
                        targets[index] = operations.length;
                    }
                    branched = true;
                }
                case PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER,
                    PcodeOp.RETURN, PcodeOp.BRANCHIND, PcodeOp.UNIMPLEMENTED -> { return null; }
                default -> { }
            }
        }
        return branched ? targets : null;
    }
}

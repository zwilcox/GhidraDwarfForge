package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Bounded call evidence: an ordinary direct call to a decoded straight-line leaf. */
final class DirectLeafCalls {
    record Leaf(List<Instruction> instructions, List<Varnode> unaffected) {
        Leaf {
            instructions = List.copyOf(instructions);
            unaffected = List.copyOf(unaffected);
        }

        boolean preserves(Register register, TaskMonitor monitor) throws CancelledException {
            Register base = register.getBaseRegister();
            boolean declared = false;
            for (Varnode node : unaffected) {
                monitor.checkCancelled();
                if (node.isRegister() && node.getAddress().equals(base.getAddress()) &&
                        node.getSize() == base.getMinimumByteSize()) {
                    declared = true;
                }
            }
            if (!declared) {
                return false;
            }
            for (Instruction instruction : instructions) {
                monitor.checkCancelled();
                if (GhidraVariableStorage.writesRegister(instruction, base)) {
                    return false;
                }
            }
            return true;
        }
    }

    private DirectLeafCalls() {
    }

    /** Null rejects the caller; an empty map means it contains no calls. */
    static Map<Address, Leaf> inspect(Program program, List<Instruction> caller,
            TaskMonitor monitor) throws CancelledException {
        Map<Address, Leaf> result = new HashMap<>();
        for (Instruction instruction : caller) {
            monitor.checkCancelled();
            int calls = 0;
            PcodeOp direct = null;
            for (PcodeOp operation : instruction.getPcode()) {
                monitor.checkCancelled();
                if (operation.getOpcode() == PcodeOp.CALL) {
                    calls++;
                    direct = operation;
                }
                if (operation.getOpcode() == PcodeOp.CALLIND) {
                    return null;
                }
            }
            if (calls == 0 && !instruction.getFlowType().isCall()) {
                continue;
            }
            var flows = instruction.getFlows();
            var flow = instruction.getFlowType();
            if (calls != 1 || !flow.isCall() || flow.isComputed() || flow.isConditional() ||
                    flow.isOverride() || !flow.hasFallthrough() || !exact(instruction) ||
                    flows.length != 1 || direct.getOutput() != null ||
                    direct.getNumInputs() != 1 || direct.getInput(0) == null ||
                    !flows[0].equals(direct.getInput(0).getAddress()) ||
                    !flows[0].getAddressSpace().equals(instruction.getAddress().getAddressSpace())) {
                return null;
            }
            var function = program.getFunctionManager().getFunctionAt(flows[0]);
            if (function == null || function.isExternal() || function.isThunk() ||
                    function.hasNoReturn() || function.getCallFixup() != null ||
                    function.getCallingConvention() == null ||
                    function.getBody().getNumAddressRanges() != 1 ||
                    !function.getEntryPoint().equals(function.getBody().getMinAddress())) {
                return null;
            }
            List<Instruction> decoded = new ArrayList<>();
            Address expected = function.getEntryPoint();
            Address last = function.getBody().getMaxAddress();
            if (last.next() == null) {
                return null;
            }
            boolean returned = false;
            for (Instruction body : program.getListing().getInstructions(function.getBody(), true)) {
                monitor.checkCancelled();
                if (returned || !body.getAddress().equals(expected) || !exact(body) ||
                        !body.getMaxAddress().getAddressSpace().equals(last.getAddressSpace()) ||
                        body.getMaxAddress().compareTo(last) > 0) {
                    return null;
                }
                PcodeOp[] operations = body.getPcode();
                for (int index = 0; index < operations.length; index++) {
                    monitor.checkCancelled();
                    PcodeOp operation = operations[index];
                    if (GhidraVariableStorage.unprovenStore(program, operation)) {
                        return null;
                    }
                    switch (operation.getOpcode()) {
                        case PcodeOp.BRANCH, PcodeOp.CBRANCH, PcodeOp.BRANCHIND,
                            PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.CALLOTHER,
                            PcodeOp.UNIMPLEMENTED -> { return null; }
                        case PcodeOp.RETURN -> {
                            if (index != operations.length - 1 || operation.getOutput() != null ||
                                    operation.getNumInputs() != 1 || operation.getInput(0) == null ||
                                    operation.getInput(0).getSize() != expected.getAddressSpace().getPointerSize()) {
                                return null;
                            }
                            returned = true;
                        }
                        default -> { }
                    }
                }
                var bodyFlow = body.getFlowType();
                if (bodyFlow.isCall() || bodyFlow.isConditional() || bodyFlow.isJump() ||
                        bodyFlow.isOverride() || (returned
                            ? !bodyFlow.isTerminal() || body.getFallThrough() != null ||
                                !body.getMaxAddress().equals(last)
                            : !bodyFlow.isFallthrough() ||
                                !body.getMaxAddress().next().equals(body.getFallThrough()))) {
                    return null;
                }
                decoded.add(body);
                expected = body.getMaxAddress().next();
            }
            if (!returned || !last.next().equals(expected)) {
                return null;
            }
            result.put(instruction.getAddress(), new Leaf(decoded,
                List.of(function.getCallingConvention().getUnaffectedList())));
        }
        return Map.copyOf(result);
    }

    private static boolean exact(Instruction instruction) {
        return instruction.getFlowOverride() == FlowOverride.NONE &&
            !instruction.isInDelaySlot() && instruction.getDelaySlotDepth() == 0 &&
            !instruction.isLengthOverridden() && !instruction.isFallThroughOverridden() &&
            instruction.getLength() > 0 && instruction.getLength() == instruction.getParsedLength() &&
            instruction.getAddress().getAddressSpace().equals(instruction.getMaxAddress().getAddressSpace()) &&
            instruction.getMaxAddress().subtract(instruction.getAddress()) == instruction.getLength() - 1L;
    }
}

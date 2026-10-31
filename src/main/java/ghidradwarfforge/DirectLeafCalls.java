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

/** Register preservation through fully decoded direct-call graphs and selected ABI contracts. */
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
        Map<Address, Address> roots = new java.util.LinkedHashMap<>();
        for (Instruction instruction : caller) {
            monitor.checkCancelled();
            boolean rawCall = false;
            for (PcodeOp operation : instruction.getPcode()) {
                monitor.checkCancelled();
                if (GhidraVariableStorage.unprovenStore(program, operation) ||
                        operation.getOpcode() == PcodeOp.CALLIND) return null;
                rawCall |= operation.getOpcode() == PcodeOp.CALL;
            }
            if (!rawCall && !instruction.getFlowType().isCall()) continue;
            if (!directCall(instruction)) return null;
            roots.put(instruction.getAddress(), instruction.getFlows()[0]);
        }
        // Inspect each saved body once. A worklist also handles recursive call
        // graphs without recursive Java calls or an arbitrary depth cutoff.
        record Body(List<Instruction> instructions, List<Varnode> unaffected, List<Address> calls) {}
        Map<Address, Body> graph = new java.util.LinkedHashMap<>();
        var work = new java.util.ArrayDeque<Address>(roots.values());
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Address entry = work.removeFirst();
            if (graph.containsKey(entry)) continue;
            var function = program.getFunctionManager().getFunctionAt(entry);
            if (function == null || function.isExternal() || function.isThunk() ||
                    function.hasNoReturn() || function.getCallFixup() != null ||
                    function.getCallingConvention() == null) return null;
            var decoded = RegisterDefinitionFlow.decodedInstructions(program, function, true, monitor);
            if (decoded.isEmpty()) return null;
            var targets = new ArrayList<Address>();
            boolean returned = false;
            for (Instruction instruction : decoded.values()) {
                monitor.checkCancelled();
                returned |= instruction.getFlowType().isTerminal();
                if (instruction.getFlowType().isCall()) targets.add(instruction.getFlows()[0]);
            }
            if (!returned) return null;
            graph.put(entry, new Body(List.copyOf(decoded.values()),
                List.of(function.getCallingConvention().getUnaffectedList()), List.copyOf(targets)));
            work.addAll(targets);
        }
        Map<Address, Leaf> summaries = new HashMap<>();
        Map<Address, Leaf> result = new HashMap<>();
        for (var root : roots.entrySet()) {
            monitor.checkCancelled();
            Leaf summary = summaries.get(root.getValue());
            if (summary == null) {
                var visited = new java.util.HashSet<Address>();
                var instructions = new ArrayList<Instruction>();
                var unaffected = new ArrayList<Varnode>(graph.get(root.getValue()).unaffected());
                work.add(root.getValue());
                while (!work.isEmpty()) {
                    monitor.checkCancelled();
                    Address entry = work.removeFirst();
                    if (!visited.add(entry)) continue;
                    Body body = graph.get(entry);
                    instructions.addAll(body.instructions());
                    unaffected.retainAll(body.unaffected());
                    work.addAll(body.calls());
                }
                summary = new Leaf(instructions, unaffected);
                summaries.put(root.getValue(), summary);
            }
            result.put(root.getKey(), summary);
        }
        return Map.copyOf(result);
    }

    /** Raw and listing evidence must describe the same ordinary direct call. */
    static boolean directCall(Instruction instruction) {
        var flow = instruction.getFlowType();
        var targets = instruction.getFlows();
        var defaults = instruction.getDefaultFlows();
        if (!exact(instruction) || !flow.isCall() || flow.isComputed() || flow.isConditional() ||
                !flow.hasFallthrough() || instruction.getFallThrough() == null ||
                !instruction.getMaxAddress().next().equals(instruction.getFallThrough()) ||
                targets == null || targets.length != 1 || defaults == null || defaults.length != 1 ||
                !targets[0].equals(defaults[0])) return false;
        PcodeOp[] operations = instruction.getPcode();
        int calls = 0;
        for (int index = 0; index < operations.length; index++) {
            PcodeOp operation = operations[index];
            if (operation.getOpcode() == PcodeOp.CALL) {
                if (++calls != 1 || index != operations.length - 1 || operation.getOutput() != null ||
                        operation.getNumInputs() != 1 || operation.getInput(0) == null ||
                        !targets[0].equals(operation.getInput(0).getAddress()) ||
                        !targets[0].getAddressSpace().equals(instruction.getAddress().getAddressSpace())) return false;
            }
            else if (operation.getOpcode() == PcodeOp.CALLIND || operation.getOpcode() == PcodeOp.CALLOTHER ||
                    operation.getOpcode() == PcodeOp.UNIMPLEMENTED || operation.getOpcode() == PcodeOp.RETURN ||
                    operation.getOpcode() == PcodeOp.BRANCH || operation.getOpcode() == PcodeOp.CBRANCH ||
                    operation.getOpcode() == PcodeOp.BRANCHIND) return false;
        }
        return calls == 1;
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

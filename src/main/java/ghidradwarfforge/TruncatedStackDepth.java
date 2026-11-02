package ghidradwarfforge;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Affine low-address bits in a language-declared truncated memory space. */
final class TruncatedStackDepth {
    private final Program program;
    private final int addressBytes;
    private final Map<Varnode, Long> facts = new HashMap<>();

    private TruncatedStackDepth(Program program, int addressBytes) {
        this.program = program;
        this.addressBytes = addressBytes;
    }

    static Map<Address, Integer> prove(Program program, Function function, Register pointer,
            TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        var memory = program.getLanguage().getDefaultDataSpace();
        if (function.getProgram() != program || pointer != pointer.getBaseRegister() ||
                memory == null || memory.getAddressableUnitSize() != 1 ||
                memory.getPointerSize() > Integer.BYTES ||
                !GhidraVariableStorage.declaredTruncatedMemory(program, memory, pointer.getMinimumByteSize()) ||
                function.getBody().getNumAddressRanges() != 1 ||
                !function.getBody().getMinAddress().equals(function.getEntryPoint())) return Map.of();
        List<Instruction> instructions = GhidraVariableStorage.prefixInstructions(program, function, monitor);
        if (instructions == null || GhidraVariableStorage.registerPrefixEnd(
                function.getEntryPoint().getOffset(), function.getBody().getMaxAddress().getOffset() + 1,
                instructions, List.of(pointer), true, monitor) < 0) return Map.of();
        var state = new TruncatedStackDepth(program, memory.getPointerSize());
        var pointerNode = new Varnode(pointer.getAddress(), pointer.getMinimumByteSize());
        state.facts.put(pointerNode, 0L);
        var result = new HashMap<Address, Integer>();
        boolean delayed = false;
        for (Instruction instruction : instructions) {
            monitor.checkCancelled();
            Long depth = delayed ? null : state.read(pointerNode);
            result.put(instruction.getAddress(), depth == null ? Function.UNKNOWN_STACK_DEPTH_CHANGE : depth.intValue());
            if (instruction.getDelaySlotDepth() > 0) {
                // The owner's p-code folds in later slot effects. Do not assign
                // that post-slot state to a separately observable slot address.
                delayed = true;
                continue;
            }
            if (delayed) continue;
            state.facts.keySet().removeIf(Varnode::isUnique);
            for (PcodeOp operation : instruction.getPcode()) {
                monitor.checkCancelled();
                Varnode output = operation.getOutput();
                if (output == null) continue;
                Long value = state.derive(operation);
                state.facts.keySet().removeIf(node -> overlaps(node, output));
                if (value != null && (output.isRegister() || output.isUnique())) state.facts.put(output, value);
            }
        }
        return Map.copyOf(result);
    }

    private Long derive(PcodeOp operation) {
        Varnode output = operation.getOutput();
        if (output.getSize() < addressBytes || output.getSize() > Long.BYTES) return null;
        int opcode = operation.getOpcode();
        if ((opcode == PcodeOp.COPY || opcode == PcodeOp.INT_SEXT || opcode == PcodeOp.INT_ZEXT) &&
                operation.getNumInputs() == 1) {
            Varnode input = operation.getInput(0);
            if (input == null || (opcode == PcodeOp.COPY ? input.getSize() != output.getSize() :
                    input.getSize() >= output.getSize())) return null;
            return read(input);
        }
        if (opcode == PcodeOp.SUBPIECE && operation.getNumInputs() == 2 &&
                operation.getInput(0) != null && operation.getInput(1) != null &&
                operation.getInput(1).isConstant() && operation.getInput(1).getOffset() == 0 &&
                operation.getInput(0).getSize() >= output.getSize()) return read(operation.getInput(0));
        if ((opcode != PcodeOp.INT_ADD && opcode != PcodeOp.INT_SUB) || operation.getNumInputs() != 2) return null;
        Varnode first = operation.getInput(0), second = operation.getInput(1);
        if (first == null || second == null || first.getSize() != output.getSize() || second.getSize() != output.getSize()) return null;
        if (opcode == PcodeOp.INT_ADD && first.isConstant()) {
            Varnode swap = first; first = second; second = swap;
        }
        Long value = read(first);
        if (value == null || !second.isConstant()) return null;
        // Only low address bits participate in the declared physical space.
        // Normalize modulo that width, including a sign-extended narrow add.
        return normalize(opcode == PcodeOp.INT_ADD ? value + second.getOffset() : value - second.getOffset());
    }

    private Long read(Varnode node) {
        if (node == null || node.getSize() < addressBytes || node.getSize() > Long.BYTES) return null;
        Long exact = facts.get(node);
        if (exact != null) return exact;
        if (!node.isRegister()) return null;
        for (var entry : facts.entrySet()) {
            Varnode known = entry.getKey();
            if (known.isRegister() && known.getSize() >= node.getSize() &&
                    lowAddress(known).equals(lowAddress(node))) return entry.getValue();
        }
        return null;
    }

    private Address lowAddress(Varnode node) {
        return node.getAddress().add(program.getLanguage().isBigEndian() ? node.getSize() - addressBytes : 0);
    }

    private long normalize(long value) {
        int shift = (Long.BYTES - addressBytes) * Byte.SIZE;
        return (value << shift) >> shift;
    }

    private static boolean overlaps(Varnode first, Varnode second) {
        return first.getAddress().getAddressSpace().equals(second.getAddress().getAddressSpace()) &&
            first.getOffset() < second.getOffset() + second.getSize() && second.getOffset() < first.getOffset() + first.getSize();
    }
}

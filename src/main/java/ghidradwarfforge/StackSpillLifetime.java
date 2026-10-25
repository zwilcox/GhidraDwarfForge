package ghidradwarfforge;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;

/** One completed stack spill; any subsequent memory or stack-pointer write ends it. */
final class StackSpillLifetime {
    record Backup(long end, RegisterRelativeStorage storage) {
    }

    private enum Kind { VALUE, STACK_ADDRESS }
    private record Fact(Kind kind, long offset) {
    }

    private StackSpillLifetime() {
    }

    static Backup prove(Program program, long start, long end, List<Instruction> instructions,
            Varnode incoming, int bytes, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        Register original = exactRegister(program, incoming);
        Register pointer = program.getCompilerSpec().getStackPointer();
        AddressSpace memory = program.getLanguage().getDefaultDataSpace();
        if (original == null || bytes <= 0 || incoming.getSize() != bytes || pointer == null ||
                pointer != pointer.getBaseRegister() || memory == null || memory.isOverlaySpace() ||
                memory.getType() != AddressSpace.TYPE_RAM || memory.getAddressableUnitSize() != 1 ||
                program.getAddressFactory().getAddressSpace(memory.getSpaceID()) != memory ||
                pointer.getBitLength() != memory.getPointerSize() * 8 ||
                memory.getPointerSize() <= 0 || memory.getPointerSize() > Long.BYTES ||
                original.getBaseRegister() == pointer) {
            return null;
        }
        long handoff = GhidraVariableStorage.registerPrefixEnd(start, end, instructions,
            original.getBaseRegister(), monitor);
        if (handoff <= start || handoff >= end) {
            return null;
        }
        var code = instructions.getFirst().getAddress().getAddressSpace();
        RegisterRelativeStorage candidate = null;
        long candidateEnd = end;
        boolean originalAlive = true;
        for (Instruction instruction : instructions) {
            monitor.checkCancelled();
            long next = Math.addExact(instruction.getMaxAddress().getOffset(), 1);
            if (instruction.isLengthOverridden() || instruction.isFallThroughOverridden() ||
                    instruction.getLength() <= 0 || instruction.getParsedLength() != instruction.getLength() ||
                    next != Math.addExact(instruction.getAddress().getOffset(), instruction.getLength()) ||
                    instruction.getAddress().getAddressSpace() != code ||
                    instruction.getMaxAddress().getAddressSpace() != code ||
                    (instruction.getFallThrough() != null &&
                        instruction.getFallThrough().getAddressSpace() != code) ||
                    instruction.getFlowType().isCall() || instruction.getFlowType().isJump() ||
                    instruction.getFlowType().isConditional() || instruction.getFlowType().isOverride()) {
                return null;
            }
            boolean writesOriginal = GhidraVariableStorage.writesRegister(instruction, original.getBaseRegister());
            boolean writesPointer = GhidraVariableStorage.writesRegister(instruction, pointer);
            PcodeOp[] operations = instruction.getPcode();
            int stores = 0;
            boolean otherMemoryWrite = false;
            for (Object result : instruction.getResultObjects()) {
                monitor.checkCancelled();
                if (result instanceof Address address && address.getAddressSpace().isMemorySpace()) {
                    otherMemoryWrite = true;
                }
            }
            for (int index = 0; index < operations.length; index++) {
                monitor.checkCancelled();
                PcodeOp operation = operations[index];
                if (GhidraVariableStorage.unprovenStore(program, operation)) {
                    return null;
                }
                if (operation.getOpcode() == PcodeOp.STORE) {
                    stores++;
                }
                if (operation.getOutput() != null &&
                        operation.getOutput().getAddress().getAddressSpace().isMemorySpace()) {
                    otherMemoryWrite = true;
                }
                if (operation.getOpcode() == PcodeOp.RETURN &&
                        (index != operations.length - 1 || operation.getOutput() != null ||
                            operation.getNumInputs() != 1 || operation.getInput(0) == null ||
                            operation.getInput(0).getSize() != code.getPointerSize())) {
                    return null;
                }
            }
            if (candidate != null && candidateEnd == end &&
                    (writesPointer || otherMemoryWrite || stores != 0)) {
                candidateEnd = next;
            }
            if (candidate == null && originalAlive && !writesOriginal && !writesPointer &&
                    !otherMemoryWrite && stores == 1) {
                Map<Varnode, Fact> facts = new HashMap<>();
                for (PcodeOp operation : operations) {
                    monitor.checkCancelled();
                    if (operation.getOpcode() == PcodeOp.STORE) {
                        Varnode address = operation.getInput(1);
                        Varnode value = operation.getInput(2);
                        Fact destination = read(address, incoming, pointer, facts);
                        Fact source = read(value, incoming, pointer, facts);
                        if ((int) operation.getInput(0).getOffset() == memory.getSpaceID() &&
                                address.getSize() == memory.getPointerSize() && value.getSize() == bytes &&
                                destination != null && destination.kind() == Kind.STACK_ADDRESS &&
                                source != null && source.kind() == Kind.VALUE) {
                            var mapped = registers.registerRelative(pointer.getName(), destination.offset());
                            if (mapped instanceof RegisterRelativeStorage relative) {
                                candidate = relative;
                            }
                        }
                    }
                    Varnode output = operation.getOutput();
                    if (output != null && output.isUnique()) {
                        Fact fact = derive(operation, incoming, pointer, facts);
                        facts.keySet().removeIf(node -> overlaps(node, output));
                        if (fact != null) {
                            facts.put(output, fact);
                        }
                    }
                }
            }
            if (writesOriginal) {
                originalAlive = false;
            }
        }
        return candidate != null && candidateEnd > handoff ? new Backup(candidateEnd, candidate) : null;
    }

    private static Fact derive(PcodeOp operation, Varnode incoming, Register pointer,
            Map<Varnode, Fact> facts) {
        Varnode output = operation.getOutput();
        if (operation.getOpcode() == PcodeOp.COPY && operation.getNumInputs() == 1 &&
                operation.getInput(0) != null && output.getSize() == operation.getInput(0).getSize()) {
            return read(operation.getInput(0), incoming, pointer, facts);
        }
        if ((operation.getOpcode() != PcodeOp.INT_ADD && operation.getOpcode() != PcodeOp.INT_SUB) ||
                operation.getNumInputs() != 2 || output.getSize() != pointer.getMinimumByteSize()) {
            return null;
        }
        Varnode first = operation.getInput(0);
        Varnode second = operation.getInput(1);
        if (first == null || second == null || first.getSize() != output.getSize() ||
                second.getSize() != output.getSize()) {
            return null;
        }
        if (operation.getOpcode() == PcodeOp.INT_ADD && first.isConstant()) {
            Varnode swap = first;
            first = second;
            second = swap;
        }
        Fact base = read(first, incoming, pointer, facts);
        if (base == null || base.kind() != Kind.STACK_ADDRESS || !second.isConstant()) {
            return null;
        }
        int shift = (Long.BYTES - second.getSize()) * Byte.SIZE;
        long delta = (second.getOffset() << shift) >> shift;
        try {
            long offset = operation.getOpcode() == PcodeOp.INT_ADD
                ? Math.addExact(base.offset(), delta) : Math.subtractExact(base.offset(), delta);
            return ((offset << shift) >> shift) == offset ? new Fact(Kind.STACK_ADDRESS, offset) : null;
        }
        catch (ArithmeticException overflow) {
            return null;
        }
    }

    private static Fact read(Varnode node, Varnode incoming, Register pointer,
            Map<Varnode, Fact> facts) {
        if (node == null) {
            return null;
        }
        if (node.equals(incoming)) {
            return new Fact(Kind.VALUE, 0);
        }
        if (node.isRegister() && node.getAddress().equals(pointer.getAddress()) &&
                node.getSize() == pointer.getMinimumByteSize()) {
            return new Fact(Kind.STACK_ADDRESS, 0);
        }
        return node.isUnique() ? facts.get(node) : null;
    }

    private static Register exactRegister(Program program, Varnode node) {
        if (node == null || !node.isRegister() || node.getSize() <= 0) {
            return null;
        }
        Register register = program.getRegister(node);
        return register != null && register.getAddress().equals(node.getAddress()) &&
            register.getBitLength() == node.getSize() * 8L &&
            register.getLeastSignificantBitInBaseRegister() == 0 ? register : null;
    }

    private static boolean overlaps(Varnode first, Varnode second) {
        return first.getAddress().getAddressSpace().equals(second.getAddress().getAddressSpace()) &&
            first.getOffset() < Math.addExact(second.getOffset(), second.getSize()) &&
            second.getOffset() < Math.addExact(first.getOffset(), first.getSize());
    }
}

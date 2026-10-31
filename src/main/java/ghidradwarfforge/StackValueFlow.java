package ghidradwarfforge;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Ordered full-value transfers through registers and proven stack slots. */
final class StackValueFlow {
    private enum Kind { VALUE, STACK_ADDRESS }
    private record Fact(Kind kind, long offset) {
    }
    private static final Fact VALUE = new Fact(Kind.VALUE, 0);
    private static final Storage UNKNOWN = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
        "no surviving register or stack slot is proven to contain the incoming value");

    private final Program program;
    private final Register pointer;
    private final AddressSpace memory;
    private final int bytes;
    private final Map<Varnode, Fact> facts = new LinkedHashMap<>();
    private final Map<Long, Boolean> slots = new LinkedHashMap<>();
    private boolean reloaded;

    private StackValueFlow(Program program, Register pointer, AddressSpace memory, int bytes) {
        this.program = program;
        this.pointer = pointer;
        this.memory = memory;
        this.bytes = bytes;
    }

    static List<StorageInterval> prove(Program program, Function function, Parameter parameter,
            TargetRegisterMap registers, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        var storage = parameter.getVariableStorage();
        Register pointer = program.getCompilerSpec().getStackPointer();
        AddressSpace memory = program.getLanguage().getDefaultDataSpace();
        int bytes = parameter.getLength();
        if (function.getProgram() != program || parameter.getFunction() != function ||
                parameter.getOrdinal() < 0 || function.getParameter(parameter.getOrdinal()) != parameter ||
                parameter.getFirstUseOffset() != 0 || parameter.getFormalDataType() == null ||
                parameter.getFormalDataType().getLength() != bytes || bytes <= 0 || storage == null ||
                storage.getProgramArchitecture() != program || !storage.isValid() || storage.isBadStorage() ||
                storage.isForcedIndirect() || !storage.isRegisterStorage() || storage.getVarnodeCount() != 1 ||
                storage.size() != bytes || pointer == null || pointer != pointer.getBaseRegister() ||
                memory == null || memory.isOverlaySpace() || memory.getType() != AddressSpace.TYPE_RAM ||
                memory.getAddressableUnitSize() != 1 || memory.getPointerSize() <= 0 ||
                memory.getPointerSize() > Long.BYTES || pointer.getBitLength() != memory.getPointerSize() * 8 ||
                program.getAddressFactory().getAddressSpace(memory.getSpaceID()) != memory ||
                function.getBody().getNumAddressRanges() != 1 ||
                !function.getEntryPoint().equals(function.getBody().getMinAddress())) return List.of();
        Varnode incoming = storage.getFirstVarnode();
        Register original = exactRegister(program, incoming);
        if (original == null || original.getLeastSignificantBitInBaseRegister() != 0 ||
                original.getBaseRegister() == pointer) return List.of();
        var decoded = RegisterDefinitionFlow.decodedBody(program, function, monitor);
        if (decoded.isEmpty()) return List.of();
        var analysis = new StackValueFlow(program, pointer, memory, bytes);
        analysis.facts.put(incoming, VALUE);
        analysis.facts.put(new Varnode(pointer.getAddress(), pointer.getMinimumByteSize()),
            new Fact(Kind.STACK_ADDRESS, 0));
        var result = new ArrayList<StorageInterval>();
        for (Instruction instruction : decoded.values()) {
            monitor.checkCancelled();
            if (instruction.getFlowType().isJump() || instruction.getFlowType().isConditional() ||
                    instruction.getFlowType().isCall()) return List.of();
            long start = instruction.getAddress().getOffset();
            long end = Math.addExact(instruction.getMaxAddress().getOffset(), 1);
            Storage location = analysis.location(registers);
            append(result, start, end, location);
            // Unique temporaries belong to one instruction. A stack-pointer
            // change conservatively retires every old slot, including released
            // frame storage. Already loaded register values can still survive.
            analysis.facts.keySet().removeIf(Varnode::isUnique);
            if (GhidraVariableStorage.writesRegister(instruction, pointer)) analysis.slots.clear();
            // Listing-only effects have no defensible ordering relative to raw
            // reads. Retire their inputs before interpreting this instruction.
            for (Varnode node : new ArrayList<>(analysis.facts.keySet())) {
                monitor.checkCancelled();
                Register register = exactRegister(program, node);
                if (node.isRegister() && (register == null ||
                        !RegisterCopyLifetime.resultsCovered(instruction, register.getBaseRegister(), monitor))) {
                    analysis.facts.remove(node);
                }
            }
            for (Object output : instruction.getResultObjects()) {
                if (output instanceof Address address && address.getAddressSpace().isMemorySpace()) analysis.slots.clear();
            }
            for (PcodeOp operation : instruction.getPcode()) {
                monitor.checkCancelled();
                if (GhidraVariableStorage.unprovenStore(program, operation)) return List.of();
                if (operation.getOpcode() == PcodeOp.STORE) analysis.store(operation);
                Varnode output = operation.getOutput();
                if (output == null) continue;
                Fact derived = analysis.derive(operation);
                analysis.facts.keySet().removeIf(node -> overlaps(node, output));
                if (output.getAddress().getAddressSpace().isMemorySpace()) analysis.slots.clear();
                if (derived != null && (output.isRegister() || output.isUnique())) analysis.facts.put(output, derived);
            }
            for (Varnode node : new ArrayList<>(analysis.facts.keySet())) {
                monitor.checkCancelled();
                Register register = exactRegister(program, node);
                if (node.isRegister() && (register == null ||
                        !RegisterCopyLifetime.resultsCovered(instruction, register.getBaseRegister(), monitor))) {
                    analysis.facts.remove(node);
                }
            }
            for (Object output : instruction.getResultObjects()) {
                if (output instanceof Address address && address.getAddressSpace().isMemorySpace()) analysis.slots.clear();
            }
        }
        return analysis.reloaded ? List.copyOf(result) : List.of();
    }

    /** Keep every established interval; refine only previously unavailable gaps. */
    static List<StorageInterval> extendUnavailable(List<StorageInterval> existing,
            List<StorageInterval> proven) {
        if (proven.isEmpty()) return List.copyOf(existing);
        var result = new ArrayList<StorageInterval>();
        for (var interval : existing) {
            if (interval.storage().available()) {
                append(result, interval.start(), interval.end(), interval.storage());
                continue;
            }
            long cursor = interval.start();
            for (var extra : proven) {
                if (!extra.storage().available() || extra.end() <= cursor || extra.start() >= interval.end()) continue;
                long low = Math.max(cursor, extra.start());
                long high = Math.min(interval.end(), extra.end());
                if (cursor < low) append(result, cursor, low, interval.storage());
                append(result, low, high, extra.storage());
                cursor = high;
            }
            if (cursor < interval.end()) append(result, cursor, interval.end(), interval.storage());
        }
        return List.copyOf(result);
    }

    private void store(PcodeOp operation) {
        Fact destination = address(operation);
        Varnode value = operation.getInput(2);
        if (destination == null) {
            slots.clear();
            return;
        }
        long offset = destination.offset();
        long end;
        try { end = Math.addExact(offset, value.getSize()); }
        catch (ArithmeticException overflow) { slots.clear(); return; }
        slots.keySet().removeIf(start -> intersects(start, bytes, offset, end));
        if (value.getSize() == bytes && VALUE.equals(read(value))) slots.put(offset, true);
    }

    private Fact address(PcodeOp operation) {
        if (operation.getNumInputs() < 2 || operation.getInput(0) == null ||
                !operation.getInput(0).isConstant() || operation.getInput(1) == null ||
                operation.getInput(1).getSize() != memory.getPointerSize()) return null;
        long id = operation.getInput(0).getOffset();
        if ((id != (int) id && id != Integer.toUnsignedLong((int) id)) ||
                (int) id != memory.getSpaceID()) return null;
        Fact address = read(operation.getInput(1));
        return address != null && address.kind() == Kind.STACK_ADDRESS ? address : null;
    }

    private Fact derive(PcodeOp operation) {
        Varnode output = operation.getOutput();
        int opcode = operation.getOpcode();
        if (opcode == PcodeOp.LOAD && operation.getNumInputs() == 2 && output.getSize() == bytes) {
            Fact source = address(operation);
            if (source != null && slots.containsKey(source.offset())) {
                reloaded = true;
                return VALUE;
            }
            return null;
        }
        if ((opcode == PcodeOp.COPY || opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) &&
                operation.getNumInputs() == 1 && operation.getInput(0) != null) {
            Varnode input = operation.getInput(0);
            if (opcode == PcodeOp.COPY ? input.getSize() != output.getSize() : input.getSize() >= output.getSize()) return null;
            Fact value = read(input);
            if (value == null) return null;
            if (value.kind() == Kind.VALUE) return input.getSize() >= bytes ? value : null;
            return opcode == PcodeOp.COPY && output.getSize() == memory.getPointerSize() ? value : null;
        }
        if (opcode == PcodeOp.SUBPIECE && operation.getNumInputs() == 2 && operation.getInput(0) != null &&
                operation.getInput(1) != null && operation.getInput(1).isConstant() &&
                operation.getInput(1).getOffset() == 0 && output.getSize() >= bytes &&
                output.getSize() <= operation.getInput(0).getSize() && VALUE.equals(read(operation.getInput(0)))) return VALUE;
        if ((opcode != PcodeOp.INT_ADD && opcode != PcodeOp.INT_SUB) || operation.getNumInputs() != 2 ||
                output.getSize() != memory.getPointerSize()) return null;
        Varnode first = operation.getInput(0), second = operation.getInput(1);
        if (first == null || second == null || first.getSize() != output.getSize() || second.getSize() != output.getSize()) return null;
        if (opcode == PcodeOp.INT_ADD && first.isConstant()) {
            Varnode swap = first; first = second; second = swap;
        }
        Fact base = read(first);
        if (base == null || base.kind() != Kind.STACK_ADDRESS || !second.isConstant()) return null;
        int shift = (Long.BYTES - second.getSize()) * 8;
        long delta = (second.getOffset() << shift) >> shift;
        try {
            long offset = opcode == PcodeOp.INT_ADD ? Math.addExact(base.offset(), delta) : Math.subtractExact(base.offset(), delta);
            return ((offset << shift) >> shift) == offset ? new Fact(Kind.STACK_ADDRESS, offset) : null;
        }
        catch (ArithmeticException overflow) { return null; }
    }

    private Fact read(Varnode node) {
        if (node == null) return null;
        Fact direct = facts.get(node);
        if (direct != null) return direct;
        if (node.getSize() < bytes) return null;
        for (var entry : facts.entrySet()) {
            Varnode known = entry.getKey();
            if (entry.getValue().kind() == Kind.VALUE && known.getSize() >= bytes &&
                    known.getAddress().getAddressSpace().equals(node.getAddress().getAddressSpace()) &&
                    lowAddress(known).equals(lowAddress(node))) return VALUE;
        }
        return null;
    }

    private Address lowAddress(Varnode node) {
        return node.getAddress().add(program.getLanguage().isBigEndian() ? node.getSize() - bytes : 0);
    }

    private Storage location(TargetRegisterMap registers) {
        var ordered = new ArrayList<>(facts.keySet());
        ordered.sort(Comparator.comparing(Varnode::getAddress).thenComparingInt(Varnode::getSize));
        for (Varnode node : ordered) {
            if (!VALUE.equals(facts.get(node))) continue;
            Register register = exactRegister(program, node);
            if (register == null || register.getLeastSignificantBitInBaseRegister() != 0) continue;
            Storage mapped = GhidraVariableStorage.mappedRegister(register, bytes, registers, "reloaded parameter");
            if (mapped instanceof RegisterStorage) return mapped;
        }
        Fact current = read(new Varnode(pointer.getAddress(), pointer.getMinimumByteSize()));
        if (current != null && current.kind() == Kind.STACK_ADDRESS) {
            for (long slot : slots.keySet().stream().sorted().toList()) {
                try {
                    Storage mapped = registers.registerRelative(pointer.getName(), Math.subtractExact(slot, current.offset()));
                    if (mapped instanceof RegisterRelativeStorage) return mapped;
                }
                catch (ArithmeticException overflow) { /* Not representable by this expression. */ }
            }
        }
        return UNKNOWN;
    }

    private static Register exactRegister(Program program, Varnode node) {
        if (node == null || !node.isRegister() || node.getSize() <= 0) return null;
        Register register = program.getRegister(node);
        return register != null && register.getAddress().equals(node.getAddress()) &&
            register.getBitLength() == node.getSize() * 8L ? register : null;
    }

    private static boolean intersects(long first, int size, long low, long high) {
        try { return first < high && Math.addExact(first, size) > low; }
        catch (ArithmeticException overflow) { return true; }
    }

    private static boolean overlaps(Varnode first, Varnode second) {
        if (!first.getAddress().getAddressSpace().equals(second.getAddress().getAddressSpace())) return false;
        return intersects(first.getOffset(), first.getSize(), second.getOffset(), Math.addExact(second.getOffset(), second.getSize()));
    }

    private static void append(List<StorageInterval> result, long start, long end, Storage storage) {
        if (!result.isEmpty() && result.getLast().end() == start && result.getLast().storage().equals(storage)) {
            var previous = result.removeLast();
            result.add(new StorageInterval(previous.start(), end, storage));
        }
        else result.add(new StorageInterval(start, end, storage));
    }
}

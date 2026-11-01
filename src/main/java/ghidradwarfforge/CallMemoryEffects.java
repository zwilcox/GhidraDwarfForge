package ghidradwarfforge;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Possible writes/releases and definite return stack pointer, relative to its callee entry value. */
final class CallMemoryEffects {
    record Range(long start, long end) {
        Range {
            if (end <= start) throw new IllegalArgumentException("empty memory effect");
        }
    }

    record Summary(long stackDelta, Set<Range> writes) {
        Summary {
            writes = Set.copyOf(writes);
        }
    }

    private record Term(boolean stack, long offset) {
    }

    private CallMemoryEffects() {
    }

    /**
     * The caller supplies fully decoded, closed bodies and inspected ABI effects.
     * Unknown stores, missing nested summaries and unequal return stack pointers fail only
     * this memory proof; they never manufacture an unaffected-memory contract.
     */
    static Summary summarize(Program program, Address entry, List<Instruction> instructions,
            Map<Address, Summary> nested, Map<Address, DirectLeafCalls.Leaf> registers,
            TaskMonitor monitor) throws CancelledException {
        Register pointer = program.getCompilerSpec().getStackPointer();
        AddressSpace memory = program.getLanguage().getDefaultDataSpace();
        if (pointer == null || pointer != pointer.getBaseRegister() || memory == null ||
                memory.isOverlaySpace() || memory.getType() != AddressSpace.TYPE_RAM ||
                memory.getAddressableUnitSize() != 1 || memory.getPointerSize() <= 0 ||
                memory.getPointerSize() > Long.BYTES || pointer.getBitLength() != memory.getPointerSize() * 8) return null;
        Varnode pointerNode = new Varnode(pointer.getAddress(), pointer.getMinimumByteSize());
        Map<Address, Instruction> decoded = new LinkedHashMap<>();
        Map<Address, Set<Address>> predecessors = new HashMap<>();
        for (Instruction instruction : instructions) {
            monitor.checkCancelled();
            if (decoded.put(instruction.getAddress(), instruction) != null) return null;
            for (Address target : RegisterDefinitionFlow.localSuccessors(instruction)) {
                predecessors.computeIfAbsent(target, unused -> new LinkedHashSet<>()).add(instruction.getAddress());
            }
        }
        if (!decoded.containsKey(entry) || !decoded.keySet().containsAll(predecessors.keySet())) return null;
        Map<Address, Map<Varnode, Term>> output = new HashMap<>();
        Map<Address, Long> returns = new HashMap<>();
        Set<Range> writes = new LinkedHashSet<>();
        var work = new ArrayDeque<Address>();
        var queued = new LinkedHashSet<Address>();
        work.add(entry);
        queued.add(entry);
        try {
            while (!work.isEmpty()) {
                monitor.checkCancelled();
                Address address = work.removeFirst();
                queued.remove(address);
                Map<Varnode, Term> state = address.equals(entry) ? new LinkedHashMap<>(Map.of(pointerNode, new Term(true, 0))) : null;
                for (Address predecessor : predecessors.getOrDefault(address, Set.of())) {
                    var incoming = output.get(predecessor);
                    if (incoming == null) continue;
                    if (state == null) state = new LinkedHashMap<>(incoming);
                    else state.entrySet().removeIf(fact -> !fact.getValue().equals(incoming.get(fact.getKey())));
                }
                if (state == null) continue;
                Instruction instruction = decoded.get(address);
                if (!covered(program, instruction, state, monitor)) return null;
                for (PcodeOp operation : instruction.getPcode()) {
                    monitor.checkCancelled();
                    if (operation.getOpcode() == PcodeOp.STORE) {
                        Long destination = memoryAddress(operation, memory, state);
                        if (destination == null || operation.getNumInputs() != 3 || operation.getInput(2) == null ||
                                operation.getInput(2).getSize() <= 0) return null;
                        writes.add(new Range(destination, Math.addExact(destination, operation.getInput(2).getSize())));
                    }
                    if (operation.getOpcode() == PcodeOp.CALL) {
                        Address target = operation.getInput(0).getAddress();
                        Summary effects = nested.get(target);
                        DirectLeafCalls.Leaf registerEffects = registers.get(target);
                        Term calledSp = state.get(pointerNode);
                        if (effects == null || registerEffects == null || calledSp == null || !calledSp.stack()) return null;
                        for (Range range : effects.writes()) {
                            writes.add(new Range(Math.addExact(calledSp.offset(), range.start()), Math.addExact(calledSp.offset(), range.end())));
                        }
                        for (Varnode node : new ArrayList<>(state.keySet())) {
                            Register register = program.getRegister(node);
                            if (!node.isRegister() || register == null || !registerEffects.preserves(register, monitor)) state.remove(node);
                        }
                        long restored = Math.addExact(calledSp.offset(), effects.stackDelta());
                        if (!fits(restored, memory.getPointerSize())) return null;
                        state.put(pointerNode, new Term(true, restored));
                    }
                    Varnode destination = operation.getOutput();
                    if (destination == null) continue;
                    if (destination.getAddress().getAddressSpace().isMemorySpace()) return null;
                    Term derived = derive(operation, state, memory.getPointerSize());
                    if (overlaps(destination, pointerNode)) {
                        Term before = state.get(pointerNode);
                        if (!destination.equals(pointerNode) || before == null || derived == null || !before.stack() || !derived.stack()) return null;
                        boolean released = program.getCompilerSpec().stackGrowsNegative() ? derived.offset() > before.offset() : derived.offset() < before.offset();
                        if (released) writes.add(new Range(Math.min(before.offset(), derived.offset()), Math.max(before.offset(), derived.offset())));
                    }
                    state.keySet().removeIf(node -> overlaps(node, destination));
                    if (derived != null && (destination.isRegister() || destination.isUnique())) state.put(destination, derived);
                }
                if (!covered(program, instruction, state, monitor)) return null;
                state.keySet().removeIf(Varnode::isUnique);
                if (instruction.getFlowType().isTerminal()) {
                    Term returnedSp = state.get(pointerNode);
                    if (returnedSp == null || !returnedSp.stack()) return null;
                    returns.put(address, returnedSp.offset());
                }
                Map<Varnode, Term> previous = output.put(address, Map.copyOf(state));
                if (!state.equals(previous)) {
                    for (Address successor : RegisterDefinitionFlow.localSuccessors(instruction)) {
                        if (queued.add(successor)) work.addLast(successor);
                    }
                }
            }
        }
        catch (ArithmeticException overflow) {
            return null;
        }
        Set<Long> deltas = new LinkedHashSet<>(returns.values());
        return deltas.size() == 1 ? new Summary(deltas.iterator().next(), writes) : null;
    }

    private static boolean covered(Program program, Instruction instruction, Map<Varnode, Term> state,
            TaskMonitor monitor) throws CancelledException {
        for (Object result : instruction.getResultObjects()) {
            if (result instanceof Address address && address.getAddressSpace().isMemorySpace()) return false;
        }
        for (Varnode node : new ArrayList<>(state.keySet())) {
            monitor.checkCancelled();
            if (!node.isRegister()) continue;
            Register register = program.getRegister(node);
            if (register == null || !RegisterCopyLifetime.resultsCovered(instruction, register.getBaseRegister(), monitor)) {
                state.remove(node);
            }
        }
        return true;
    }

    private static Long memoryAddress(PcodeOp operation, AddressSpace memory, Map<Varnode, Term> state) {
        if (operation.getNumInputs() < 2 || operation.getInput(0) == null || !operation.getInput(0).isConstant() ||
                operation.getInput(1) == null || operation.getInput(1).getSize() != memory.getPointerSize()) return null;
        long id = operation.getInput(0).getOffset();
        if ((id != (int) id && id != Integer.toUnsignedLong((int) id)) || (int) id != memory.getSpaceID()) return null;
        Term address = read(operation.getInput(1), state);
        return address != null && address.stack() ? address.offset() : null;
    }

    private static Term derive(PcodeOp operation, Map<Varnode, Term> state, int width) {
        Varnode output = operation.getOutput();
        if (output.getSize() != width) return null;
        if (operation.getOpcode() == PcodeOp.COPY && operation.getNumInputs() == 1 &&
                operation.getInput(0) != null && operation.getInput(0).getSize() == width) return read(operation.getInput(0), state);
        int opcode = operation.getOpcode();
        if ((opcode != PcodeOp.INT_ADD && opcode != PcodeOp.INT_SUB) || operation.getNumInputs() != 2) return null;
        Varnode first = operation.getInput(0), second = operation.getInput(1);
        if (first == null || second == null || first.getSize() != width || second.getSize() != width) return null;
        Term left = read(first, state), right = read(second, state);
        if (left == null || right == null) return null;
        if (opcode == PcodeOp.INT_ADD && left.stack() && right.stack()) return null;
        if (opcode == PcodeOp.INT_SUB && !left.stack() && right.stack()) return null;
        long result = opcode == PcodeOp.INT_ADD ? Math.addExact(left.offset(), right.offset()) :
            Math.subtractExact(left.offset(), right.offset());
        return fits(result, width) ? new Term(left.stack() != right.stack(), result) : null;
    }

    private static Term read(Varnode node, Map<Varnode, Term> state) {
        if (node == null || node.getSize() <= 0 || node.getSize() > Long.BYTES) return null;
        if (!node.isConstant()) return state.get(node);
        int shift = (Long.BYTES - node.getSize()) * 8;
        return new Term(false, (node.getOffset() << shift) >> shift);
    }

    private static boolean fits(long value, int width) {
        int shift = (Long.BYTES - width) * 8;
        return ((value << shift) >> shift) == value;
    }

    private static boolean overlaps(Varnode first, Varnode second) {
        return first.getAddress().getAddressSpace().equals(second.getAddress().getAddressSpace()) &&
            first.getOffset() < Math.addExact(second.getOffset(), second.getSize()) &&
            second.getOffset() < Math.addExact(first.getOffset(), first.getSize());
    }
}

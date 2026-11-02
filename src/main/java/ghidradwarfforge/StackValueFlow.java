package ghidradwarfforge;

import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Pointer;
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
import ghidradwarfforge.locations.VariableStorageModel.IndirectMemoryStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Ordered full-value transfers through registers and proven stack slots. */
final class StackValueFlow {
    private enum Kind { VALUE, STACK_ADDRESS, LITERAL }
    private record Fact(Kind kind, long offset) {
    }
    private static final Fact VALUE = new Fact(Kind.VALUE, 0);
    private static final Storage UNKNOWN = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
        "no surviving register or stack slot is proven to contain the tracked value");

    private final Program program;
    private final Register pointer;
    private final AddressSpace memory;
    private final int bytes;
    private final Map<Varnode, Fact> facts = new LinkedHashMap<>();
    private final Map<Long, Boolean> slots = new LinkedHashMap<>();
    // Instruction-local known-zero bits justify carry-free joins of unrelated pieces.
    private final Map<Varnode, Long> zeros = new LinkedHashMap<>();
    private Map<Address, DirectLeafCalls.Leaf> calls = Map.of();
    private Long localOffset;
    private boolean initializing;
    private boolean savedAssignments;
    private boolean registersBigEndian;


    private StackValueFlow(Program program, Register pointer, AddressSpace memory, int bytes) {
        this.program = program;
        this.pointer = pointer;
        this.memory = memory;
        this.bytes = bytes;
        this.registersBigEndian = program.getLanguage().isBigEndian();
    }

    static List<StorageInterval> prove(Program program, Function function, Parameter parameter,
            TargetRegisterMap registers, TaskMonitor monitor) throws CancelledException {
        return prove(program, function, parameter, parameter.getVariableStorage(), registers, monitor);
    }

    static List<StorageInterval> prove(Program program, Function function, Parameter parameter,
            ghidra.program.model.listing.VariableStorage storage, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        return proveCarrier(program, function, parameter, storage, registers, false, monitor);
    }

    /** Track the ABI pointer, then describe the formal object at its current address. */
    static List<StorageInterval> proveIndirect(Program program, Function function, Parameter parameter,
            TargetRegisterMap registers, TaskMonitor monitor) throws CancelledException {
        return proveIndirect(program, function, parameter, parameter.getVariableStorage(), registers, monitor);
    }

    static List<StorageInterval> proveIndirect(Program program, Function function, Parameter parameter,
            ghidra.program.model.listing.VariableStorage storage, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        var carrier = proveCarrier(program, function, parameter, storage, registers, true, monitor);
        var result = new ArrayList<StorageInterval>();
        for (var interval : carrier) {
            monitor.checkCancelled();
            Storage location = interval.storage();
            if (location instanceof RegisterStorage register) {
                location = register.valueBitOffset() == 0 &&
                    register.bitSize() == parameter.getLength() * Byte.SIZE
                    ? new RegisterRelativeStorage(register.register(), 0) : UNKNOWN;
            }
            else if (location instanceof RegisterRelativeStorage) {
                location = new IndirectMemoryStorage(location);
            }
            result.add(new StorageInterval(interval.start(), interval.end(), location));
        }
        return List.copyOf(result);
    }

    private static List<StorageInterval> proveCarrier(Program program, Function function,
            Parameter parameter, ghidra.program.model.listing.VariableStorage storage,
            TargetRegisterMap registers, boolean indirect, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        Register pointer = program.getCompilerSpec().getStackPointer();
        AddressSpace memory = program.getLanguage().getDefaultDataSpace();
        int bytes = parameter.getLength();
        if (function.getProgram() != program || parameter.getFunction() != function ||
                parameter.getOrdinal() < 0 || function.getParameter(parameter.getOrdinal()) != parameter ||
                parameter.getFirstUseOffset() != 0 || parameter.getFormalDataType() == null ||
                (!indirect && parameter.getFormalDataType().getLength() != bytes) ||
                bytes <= 0 || storage == null ||
                storage.getProgramArchitecture() != program || !storage.isValid() || storage.isBadStorage() ||
                storage.isForcedIndirect() != indirect ||
                !(storage.getFirstVarnode() != null && storage.getFirstVarnode().isRegister() ||
                    indirect && storage.isStackStorage()) ||
                storage.getVarnodeCount() != 1 ||
                storage.size() != bytes || pointer == null || pointer != pointer.getBaseRegister() ||
                memory == null || memory.isOverlaySpace() || memory.getType() != AddressSpace.TYPE_RAM ||
                memory.getAddressableUnitSize() != 1 || memory.getPointerSize() <= 0 ||
                memory.getPointerSize() > Long.BYTES || pointer.getBitLength() != memory.getPointerSize() * 8 ||
                program.getAddressFactory().getAddressSpace(memory.getSpaceID()) != memory) return List.of();
        if (indirect && (!(parameter.getDataType() instanceof Pointer effective) ||
                effective.getLength() != bytes || effective.getDataType() == null ||
                !effective.getDataType().isEquivalent(parameter.getFormalDataType()) ||
                parameter.getFormalDataType().getLength() <= 0 || bytes != memory.getPointerSize())) {
            return List.of();
        }
        Varnode incoming = storage.getFirstVarnode();
        Register original = RegisterByteSlice.container(program, incoming);
        // A complete logical register can occupy an upper physical slice.
        // Facts track its exact varnode bytes; overlapping outputs still kill
        // those bytes, while disjoint writes need not discard the value.
        if (incoming.isRegister() && (original == null || original.getBaseRegister() == pointer ||
                RegisterByteSlice.mapped(program, incoming, registers) == null)) return List.of();
        var decoded = RegisterDefinitionFlow.decodedInstructions(program, function, true, true, true, monitor);
        if (decoded.isEmpty()) return List.of();
        var calls = DirectLeafCalls.inspect(program, List.copyOf(decoded.values()), monitor);
        if (calls == null) return List.of();
        var analysis = new StackValueFlow(program, pointer, memory, bytes);
        analysis.calls = calls;
        if (storage.isStackStorage()) {
            analysis.slots.put((long) storage.getStackOffset(), true);
        }
        else {
            analysis.facts.put(incoming, VALUE);
        }
        analysis.facts.put(new Varnode(pointer.getAddress(), pointer.getMinimumByteSize()),
            new Fact(Kind.STACK_ADDRESS, 0));
        return analysis.acrossControlFlow(function, decoded, null, Set.of(), registers, monitor);
    }

    /**
     * Must analysis over the already checked physical CFG. An unvisited edge is
     * top, not an empty state; once visited it can only remove unsupported facts
     * at joins. Exact affine addresses form a flat lattice (different offsets
     * become unknown), so changing stack offsets on a loop cannot grow forever.
     * Value and address facts are never unioned across alternative executions.
     */
    List<StorageInterval> acrossControlFlow(Function function, Map<Address, Instruction> decoded,
            Address definition, Set<Address> owners, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        return acrossControlFlow(function, decoded, definition, owners, Map.of(), registers, monitor);
    }

    List<StorageInterval> acrossSavedAssignments(Function function, Map<Address, Instruction> decoded,
            Address definition, Map<Address, Register> assignments, TargetRegisterMap registers,
            TaskMonitor monitor) throws CancelledException {
        savedAssignments = true;
        return acrossControlFlow(function, decoded, definition, Set.of(), assignments, registers, monitor);
    }

    private List<StorageInterval> acrossControlFlow(Function function, Map<Address, Instruction> decoded,
            Address definition, Set<Address> owners, Map<Address, Register> assignments,
            TargetRegisterMap registers, TaskMonitor monitor) throws CancelledException {
        if (registers.registerStorageByteOrder() != null) {
            registersBigEndian = registers.registerStorageByteOrder() == java.nio.ByteOrder.BIG_ENDIAN;
        }
        if (!decoded.containsKey(function.getEntryPoint())) return List.of();
        Map<Address, Set<Address>> successors = new LinkedHashMap<>();
        Map<Address, Set<Address>> predecessors = new HashMap<>();
        for (var row : decoded.entrySet()) {
            monitor.checkCancelled();
            var edges = new LinkedHashSet<Address>();
            if (!row.getValue().getFlowType().isCall()) {
                for (Address[] targets : new Address[][] { row.getValue().getDefaultFlows(), row.getValue().getFlows() }) {
                    if (targets != null) edges.addAll(List.of(targets));
                }
            }
            else if (!calls.containsKey(row.getKey())) return List.of();
            if (row.getValue().getFallThrough() != null) edges.add(row.getValue().getFallThrough());
            if (!decoded.keySet().containsAll(edges)) return List.of();
            successors.put(row.getKey(), edges);
            for (Address target : edges) predecessors.computeIfAbsent(target, unused -> new LinkedHashSet<>()).add(row.getKey());
        }
        Map<Address, StackValueFlow> input = new HashMap<>();
        Map<Address, StackValueFlow> output = new HashMap<>();
        var work = new ArrayDeque<Address>();
        var queued = new LinkedHashSet<Address>();
        work.add(function.getEntryPoint());
        queued.add(function.getEntryPoint());
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Address address = work.removeFirst();
            queued.remove(address);
            StackValueFlow state = address.equals(function.getEntryPoint()) ? boundaryCopy() : null;
            for (Address predecessor : predecessors.getOrDefault(address, Set.of())) {
                monitor.checkCancelled();
                StackValueFlow incoming = output.get(predecessor);
                if (incoming == null) continue;
                if (state == null) state = incoming.boundaryCopy();
                else state.intersect(incoming);
            }
            if (state == null) continue;
            // A saved overlapping owner takes effect when its instruction is
            // reached, including a backedge to an earlier numeric address.
            if (owners.contains(address)) state.retireLocalValue();
            input.put(address, state.boundaryCopy());
            if (RegisterDefinitionFlow.opaqueTerminalBoundary(decoded.get(address))) {
                // Only the state before this instruction is observable in the
                // invocation. Never interpret an opaque return as preserving
                // its registers/memory or propagate any state after it.
                if (!successors.get(address).isEmpty()) return List.of();
                continue;
            }
            if (!state.advance(decoded.get(address), address.equals(definition), monitor)) return List.of();
            Register assignment = assignments.get(address);
            if (assignment != null) {
                // The saved mapping establishes this assignment's logical
                // identity after its complete raw definition. Old stack and
                // register copies belong to the previous value and are stale.
                state.retireLocalValue();
                Varnode destination = new Varnode(assignment.getAddress(), assignment.getMinimumByteSize());
                state.facts.keySet().removeIf(node -> overlaps(node, destination));
                state.facts.put(state.valueSpan(destination, 0), VALUE);
            }
            state = state.boundaryCopy();
            StackValueFlow previous = output.put(address, state);
            if (previous == null || !state.sameFacts(previous)) {
                for (Address next : successors.get(address)) {
                    if (queued.add(next)) work.addLast(next);
                }
            }
        }
        var result = new ArrayList<StorageInterval>();
        for (var row : decoded.entrySet()) {
            monitor.checkCancelled();
            StackValueFlow state = input.get(row.getKey());
            append(result, row.getKey().getOffset(), Math.addExact(row.getValue().getMaxAddress().getOffset(), 1),
                state == null ? UNKNOWN : state.location(registers));
        }
        return result.stream().anyMatch(interval -> interval.storage().available()) ? List.copyOf(result) : List.of();
    }

    private StackValueFlow boundaryCopy() {
        return copy(false);
    }

    private StackValueFlow copy(boolean temporaries) {
        var result = new StackValueFlow(program, pointer, memory, bytes);
        result.localOffset = localOffset;
        result.calls = calls;
        result.savedAssignments = savedAssignments;
        result.registersBigEndian = registersBigEndian;
        for (var entry : facts.entrySet()) {
            if (temporaries || !entry.getKey().isUnique()) result.facts.put(entry.getKey(), entry.getValue());
        }
        result.slots.putAll(slots);
        if (temporaries) result.zeros.putAll(zeros);
        return result;
    }

    private void intersect(StackValueFlow other) {
        facts.entrySet().removeIf(entry -> !entry.getValue().equals(other.facts.get(entry.getKey())));
        slots.keySet().retainAll(other.slots.keySet());
        zeros.replaceAll((node, mask) -> mask & other.zeros.getOrDefault(node, 0L));
        zeros.values().removeIf(mask -> mask == 0);
    }

    private boolean sameFacts(StackValueFlow other) {
        return facts.equals(other.facts) && slots.equals(other.slots);
    }

    /** Same ordered instruction engine, seeded only by a recorded full stack definition. */
    static StackValueFlow forStackLocal(Program program, int bytes, long offset) {
        Register pointer = program.getCompilerSpec().getStackPointer();
        AddressSpace memory = program.getLanguage().getDefaultDataSpace();
        if (bytes <= 0 || pointer == null || pointer != pointer.getBaseRegister() ||
                memory == null || memory.isOverlaySpace() || memory.getType() != AddressSpace.TYPE_RAM ||
                memory.getAddressableUnitSize() != 1 || memory.getPointerSize() <= 0 ||
                memory.getPointerSize() > Long.BYTES || pointer.getBitLength() != memory.getPointerSize() * 8 ||
                program.getAddressFactory().getAddressSpace(memory.getSpaceID()) != memory) return null;
        var result = new StackValueFlow(program, pointer, memory, bytes);
        result.localOffset = offset;
        result.facts.put(new Varnode(pointer.getAddress(), pointer.getMinimumByteSize()),
            new Fact(Kind.STACK_ADDRESS, 0));
        return result;
    }

    /** Caller validates the complete attached parameter before seeding any piece. */
    static StackValueFlow forIncomingPiece(Program program, Varnode incoming) {
        var state = forStackLocal(program, incoming.getSize(), 0);
        if (state == null) return null;
        state.localOffset = null;
        if (incoming.isRegister()) {
            Register register = RegisterByteSlice.container(program, incoming);
            // A complete logical piece can be an upper physical alias, just
            // like a scalar parameter. Exact varnode overlap controls kills.
            if (register == null || register.getBaseRegister() == state.pointer) return null;
            state.facts.put(incoming, VALUE);
        }
        else if (incoming.getAddress().isStackAddress()) state.slots.put(incoming.getOffset(), true);
        else return null;
        return state;
    }

    void setInspectedCalls(Map<Address, DirectLeafCalls.Leaf> inspected) {
        calls = Map.copyOf(inspected);
    }

    boolean advance(Instruction instruction, boolean initialize, TaskMonitor monitor)
            throws CancelledException {
        initializing = initialize;
        if (initialize) {
            int stores = 0;
            for (PcodeOp operation : instruction.getPcode()) {
                monitor.checkCancelled();
                if (operation.getOpcode() == PcodeOp.STORE) stores++;
            }
            if (localOffset == null || stores != 1 ||
                    GhidraVariableStorage.writesRegister(instruction, pointer)) return false;
            // Re-executing the recorded definition establishes the current
            // logical local, never a previous iteration's surviving backup.
            retireLocalValue();
        }
        // Unique temporaries belong to one instruction. For incoming values,
        // ordered affine stack-pointer changes can retain still-allocated memory. Local
        // identity continues to retire on frame changes; it needs a separate
        // ownership proof. Unmodelled stack-pointer effects cannot preserve any slot.
        facts.keySet().removeIf(Varnode::isUnique);
        zeros.clear();
        var inspectedCall = calls.get(instruction.getAddress());
        boolean memoryCall = instruction.getFlowType().isCall() && inspectedCall != null && inspectedCall.memory() != null;
        if (GhidraVariableStorage.writesRegister(instruction, pointer) &&
                ((localOffset != null && !memoryCall) ||
                !RegisterCopyLifetime.resultsCovered(instruction, pointer, monitor))) invalidateMemory();
        // Listing-only effects have no defensible ordering relative to raw
        // reads. Retire their inputs before interpreting this instruction.
        for (Varnode node : new ArrayList<>(facts.keySet())) {
            monitor.checkCancelled();
            Register register = RegisterByteSlice.container(program, node);
            if (node.isRegister() && (register == null ||
                    !RegisterCopyLifetime.resultsCovered(instruction, register.getBaseRegister(), monitor))) {
                facts.remove(node);
            }
        }
        for (Object output : instruction.getResultObjects()) {
            if (output instanceof Address address && address.getAddressSpace().isMemorySpace()) invalidateMemory();
        }
        int[] targets = IntraInstructionFlow.targets(instruction, monitor);
        if (targets != null) {
            // Local definitions and saved assignments still use their existing
            // straight instruction ownership proof. Only incoming values opt in.
            if (initialize || localOffset != null || savedAssignments ||
                    !advancePaths(instruction, targets, monitor)) return false;
        }
        else {
            for (PcodeOp operation : instruction.getPcode()) {
                if (!advanceOperation(instruction, operation, monitor)) return false;
            }
        }
        for (Varnode node : new ArrayList<>(facts.keySet())) {
            monitor.checkCancelled();
            Register register = RegisterByteSlice.container(program, node);
            if (node.isRegister() && (register == null ||
                    !RegisterCopyLifetime.resultsCovered(instruction, register.getBaseRegister(), monitor))) {
                facts.remove(node);
            }
        }
        for (Object output : instruction.getResultObjects()) {
            if (output instanceof Address address && address.getAddressSpace().isMemorySpace()) invalidateMemory();
        }
        initializing = false;
        // If the initializing address is unknown at a join, no slot was
        // generated. Keep that path unavailable rather than manufacturing a
        // fixed entry-relative address or retaining a previous local value.
        return true;
    }

    /** Forward-only control means all predecessor states arrive before a node runs. */
    private boolean advancePaths(Instruction instruction, int[] targets, TaskMonitor monitor)
            throws CancelledException {
        PcodeOp[] operations = instruction.getPcode();
        var states = new StackValueFlow[operations.length + 1];
        states[0] = copy(true);
        for (int index = 0; index < operations.length; index++) {
            monitor.checkCancelled();
            StackValueFlow state = states[index];
            states[index] = null;
            if (state == null) continue;
            if (targets[index] >= 0) {
                mergePath(states, targets[index], state);
                if (operations[index].getOpcode() == PcodeOp.CBRANCH) mergePath(states, index + 1, state);
            }
            else {
                if (!state.advanceOperation(instruction, operations[index], monitor)) return false;
                mergePath(states, index + 1, state);
            }
        }
        StackValueFlow result = states[operations.length];
        if (result == null) return false;
        facts.clear();
        facts.putAll(result.facts);
        slots.clear();
        slots.putAll(result.slots);
        zeros.clear();
        zeros.putAll(result.zeros);
        return true;
    }

    private static void mergePath(StackValueFlow[] states, int target, StackValueFlow incoming) {
        if (states[target] == null) states[target] = incoming.copy(true);
        else states[target].intersect(incoming);
    }

    private boolean advanceOperation(Instruction instruction, PcodeOp operation, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        if (GhidraVariableStorage.unprovenStore(program, operation)) return false;
        if (operation.getOpcode() == PcodeOp.STORE) store(operation);
        if (operation.getOpcode() == PcodeOp.CALL) {
            var effects = calls.get(instruction.getAddress());
            if (effects == null) return false;
            applyCall(effects, monitor);
        }
        Varnode output = operation.getOutput();
        if (output == null) return true;
        List<Fact> derived = derive(operation);
        long zeroMask = deriveZeros(operation);
        Varnode pointerNode = new Varnode(pointer.getAddress(), pointer.getMinimumByteSize());
        if (overlaps(output, pointerNode)) {
            Fact previousPointer = facts.get(pointerNode);
            Fact nextPointer = derived.size() == 1 ? derived.getFirst() : null;
            if (!output.equals(pointerNode) || previousPointer == null || nextPointer == null ||
                    previousPointer.kind() != Kind.STACK_ADDRESS || nextPointer.kind() != Kind.STACK_ADDRESS) {
                invalidateMemory();
            }
            else {
                long before = previousPointer.offset(), after = nextPointer.offset();
                boolean released = program.getCompilerSpec().stackGrowsNegative() ? after > before : after < before;
                if (released) slots.keySet().removeIf(slot -> intersects(slot, bytes,
                    Math.min(before, after), Math.max(before, after)));
            }
        }
        facts.keySet().removeIf(node -> overlaps(node, output));
        zeros.keySet().removeIf(node -> overlaps(node, output));
        if (output.isUnique() && zeroMask != 0) zeros.put(output, zeroMask);
        if (output.getAddress().getAddressSpace().isMemorySpace()) invalidateMemory();
        if (output.isRegister() || output.isUnique()) {
            for (Fact fact : derived) {
                if (fact.kind() == Kind.VALUE) facts.put(valueSpan(output, fact.offset()), VALUE);
                else facts.put(output, fact);
            }
        }
        return true;
    }

    /** Translate callee-entry-relative effects only after CALL's own raw effects. */
    private void applyCall(DirectLeafCalls.Leaf effects, TaskMonitor monitor) throws CancelledException {
        Varnode pointerNode = new Varnode(pointer.getAddress(), pointer.getMinimumByteSize());
        Fact calledSp = facts.get(pointerNode);
        Long returnedSp = null;
        var writes = new ArrayList<CallMemoryEffects.Range>();
        if (effects.memory() != null && calledSp != null && calledSp.kind() == Kind.STACK_ADDRESS) {
            try {
                long restored = Math.addExact(calledSp.offset(), effects.memory().stackDelta());
                int shift = (Long.BYTES - memory.getPointerSize()) * 8;
                if (((restored << shift) >> shift) == restored) {
                    for (var range : effects.memory().writes()) {
                        writes.add(new CallMemoryEffects.Range(Math.addExact(calledSp.offset(), range.start()),
                            Math.addExact(calledSp.offset(), range.end())));
                    }
                    returnedSp = restored;
                }
            }
            catch (ArithmeticException overflow) { /* An unrepresentable effect cannot preserve memory. */ }
        }
        if (returnedSp == null) invalidateMemory();
        else {
            for (var range : writes) {
                monitor.checkCancelled();
                if (localOffset != null && intersects(localOffset, bytes, range.start(), range.end())) retireLocalValue();
                slots.keySet().removeIf(slot -> intersects(slot, bytes, range.start(), range.end()));
            }
        }
        for (Varnode node : new ArrayList<>(facts.keySet())) {
            monitor.checkCancelled();
            Register register = RegisterByteSlice.container(program, node);
            if (register == null || !effects.preserves(register, monitor)) facts.remove(node);
        }
        if (returnedSp != null) facts.put(pointerNode, new Fact(Kind.STACK_ADDRESS, returnedSp));
    }

    /** A local assignment or reuse invalidates old copies as well as its slot. */
    void retireLocalValue() {
        facts.entrySet().removeIf(entry -> entry.getValue().kind() == Kind.VALUE);
        slots.clear();
    }

    private void invalidateMemory() {
        if (localOffset != null) retireLocalValue();
        else slots.clear();
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
            invalidateMemory();
            return;
        }
        long offset = destination.offset();
        long end;
        try { end = Math.addExact(offset, value.getSize()); }
        catch (ArithmeticException overflow) { invalidateMemory(); return; }
        boolean savedValue = savedAssignments && value.getSize() == bytes && readValues(value).contains(VALUE);
        if (localOffset != null && intersects(localOffset, bytes, offset, end) && !savedValue) retireLocalValue();
        slots.keySet().removeIf(start -> intersects(start, bytes, offset, end));
        if (initializing && localOffset != null && offset == localOffset && value.getSize() == bytes) {
            slots.put(offset, true);
        }
        else if (localOffset == null) {
            for (Fact fact : readValues(value)) {
                long displacement = program.getLanguage().isBigEndian() ? value.getSize() - bytes - fact.offset() : fact.offset();
                slots.put(Math.addExact(offset, displacement), true);
            }
        }
        else if (value.getSize() == bytes && readValues(value).contains(VALUE)) slots.put(offset, true);
    }

    private Fact address(PcodeOp operation) {
        if (operation.getNumInputs() < 2 || operation.getInput(0) == null ||
                !operation.getInput(0).isConstant() || operation.getInput(1) == null ||
                operation.getInput(1).getSize() != memory.getPointerSize()) return null;
        long id = operation.getInput(0).getOffset();
        if ((id != (int) id && id != Integer.toUnsignedLong((int) id)) ||
                (int) id != memory.getSpaceID()) return null;
        Fact address = facts.get(operation.getInput(1));
        return address != null && address.kind() == Kind.STACK_ADDRESS ? address : null;
    }

    /** VALUE offsets are transient least-significant-byte offsets within an operation value. */
    private List<Fact> derive(PcodeOp operation) {
        Varnode output = operation.getOutput();
        int opcode = operation.getOpcode();
        Long literal = instructionLiteral(operation);
        if (literal != null) return List.of(new Fact(Kind.LITERAL, literal));
        if (opcode == PcodeOp.LOAD && operation.getNumInputs() == 2 && output.getSize() >= bytes) {
            Fact source = address(operation);
            if (source == null) return List.of();
            var values = new ArrayList<Fact>();
            for (long slot : slots.keySet()) {
                long delta;
                try { delta = Math.subtractExact(slot, source.offset()); }
                catch (ArithmeticException overflow) { continue; }
                if (delta >= 0 && delta <= output.getSize() - bytes) {
                    long offset = program.getLanguage().isBigEndian() ? output.getSize() - bytes - delta : delta;
                    values.add(new Fact(Kind.VALUE, offset));
                }
            }
            return values;
        }
        if ((opcode == PcodeOp.COPY || opcode == PcodeOp.INT_ZEXT || opcode == PcodeOp.INT_SEXT) &&
                operation.getNumInputs() == 1 && operation.getInput(0) != null) {
            Varnode input = operation.getInput(0);
            if (opcode == PcodeOp.COPY ? input.getSize() != output.getSize() : input.getSize() >= output.getSize()) return List.of();
            Fact address = facts.get(input);
            if (opcode == PcodeOp.COPY && output.getSize() == memory.getPointerSize() &&
                    address != null && address.kind() == Kind.STACK_ADDRESS) return List.of(address);
            return readValues(input);
        }
        if (opcode == PcodeOp.SUBPIECE && operation.getNumInputs() == 2 && operation.getInput(0) != null &&
                operation.getInput(1) != null && operation.getInput(1).isConstant()) {
            long removed = operation.getInput(1).getOffset();
            if (removed < 0 || removed > operation.getInput(0).getSize() - output.getSize()) return List.of();
            return shiftedValues(operation.getInput(0), -removed, output.getSize());
        }
        if (opcode == PcodeOp.PIECE && operation.getNumInputs() == 2 && operation.getInput(0) != null &&
                operation.getInput(1) != null && (long) operation.getInput(0).getSize() +
                operation.getInput(1).getSize() == output.getSize()) {
            var result = new ArrayList<>(readValues(operation.getInput(1)));
            result.addAll(shiftedValues(operation.getInput(0), operation.getInput(1).getSize(), output.getSize()));
            return result;
        }
        if ((opcode == PcodeOp.INT_LEFT || opcode == PcodeOp.INT_RIGHT || opcode == PcodeOp.INT_SRIGHT) &&
                operation.getNumInputs() == 2 && operation.getInput(0) != null && operation.getInput(1) != null &&
                operation.getInput(0).getSize() == output.getSize()) {
            Long count = literal(operation.getInput(1));
            if (count == null) return List.of();
            long bits = count;
            if (bits < 0 || bits % Byte.SIZE != 0 || bits >= (long) output.getSize() * Byte.SIZE) return List.of();
            long shift = bits / Byte.SIZE;
            return shiftedValues(operation.getInput(0), opcode == PcodeOp.INT_LEFT ? shift : -shift, output.getSize());
        }
        if ((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_OR) && operation.getNumInputs() == 2 &&
                operation.getInput(0) != null && operation.getInput(1) != null && output.getSize() <= Long.BYTES &&
                operation.getInput(0).getSize() == output.getSize() && operation.getInput(1).getSize() == output.getSize()) {
            Varnode first = operation.getInput(0), second = operation.getInput(1);
            long firstZeros = zeroBits(first), secondZeros = zeroBits(second);
            boolean disjoint = (firstZeros | secondZeros) == bitMask(output.getSize());
            var values = new ArrayList<Fact>();
            if (opcode == PcodeOp.INT_OR || disjoint) {
                for (Fact value : readValues(first)) {
                    long mask = bitMask(bytes) << (value.offset() * Byte.SIZE);
                    if (disjoint || (secondZeros & mask) == mask) values.add(value);
                }
                for (Fact value : readValues(second)) {
                    long mask = bitMask(bytes) << (value.offset() * Byte.SIZE);
                    if (disjoint || (firstZeros & mask) == mask) values.add(value);
                }
            }
            if (!values.isEmpty()) return values;
        }
        if ((opcode != PcodeOp.INT_ADD && opcode != PcodeOp.INT_SUB) || operation.getNumInputs() != 2 ||
                output.getSize() != memory.getPointerSize()) return List.of();
        Varnode first = operation.getInput(0), second = operation.getInput(1);
        if (first == null || second == null || first.getSize() != output.getSize() || second.getSize() != output.getSize()) return List.of();
        if (opcode == PcodeOp.INT_ADD && first.isConstant()) {
            Varnode swap = first; first = second; second = swap;
        }
        Fact base = facts.get(first);
        Long constant = literal(second);
        if (base == null || base.kind() != Kind.STACK_ADDRESS || constant == null) return List.of();
        int shift = (Long.BYTES - second.getSize()) * 8;
        long delta = (constant << shift) >> shift;
        try {
            long offset = opcode == PcodeOp.INT_ADD ? Math.addExact(base.offset(), delta) : Math.subtractExact(base.offset(), delta);
            return ((offset << shift) >> shift) == offset ? List.of(new Fact(Kind.STACK_ADDRESS, offset)) : List.of();
        }
        catch (ArithmeticException overflow) { return List.of(); }
    }

    /** Decode literal masks used by raw p-code, never infer a runtime register value. */
    private Long instructionLiteral(PcodeOp operation) {
        Varnode output = operation.getOutput();
        if (!output.isUnique() || output.getSize() <= 0 || output.getSize() > Long.BYTES) return null;
        if (operation.getOpcode() == PcodeOp.COPY && operation.getNumInputs() == 1 &&
                operation.getInput(0) != null && operation.getInput(0).getSize() == output.getSize()) {
            return literal(operation.getInput(0));
        }
        if (operation.getNumInputs() != 2 || operation.getInput(0) == null || operation.getInput(1) == null ||
                operation.getInput(0).getSize() != output.getSize() || operation.getInput(1).getSize() != output.getSize()) return null;
        Long first = literal(operation.getInput(0)), second = literal(operation.getInput(1));
        if (first == null || second == null) return null;
        return switch (operation.getOpcode()) {
            case PcodeOp.INT_AND -> first & second;
            case PcodeOp.INT_OR -> first | second;
            case PcodeOp.INT_XOR -> first ^ second;
            case PcodeOp.INT_ADD -> (first + second) & bitMask(output.getSize());
            case PcodeOp.INT_SUB -> (first - second) & bitMask(output.getSize());
            case PcodeOp.INT_MULT -> (first * second) & bitMask(output.getSize());
            default -> null;
        };
    }

    private Long literal(Varnode node) {
        if (node == null || node.getSize() <= 0 || node.getSize() > Long.BYTES) return null;
        long mask = node.getSize() == Long.BYTES ? -1L : (1L << node.getSize() * Byte.SIZE) - 1;
        if (node.isConstant()) return node.getOffset() & mask;
        Fact fact = facts.get(node);
        return node.isUnique() && fact != null && fact.kind() == Kind.LITERAL ? fact.offset() & mask : null;
    }

    private static long bitMask(int width) {
        return width == Long.BYTES ? -1L : (1L << width * Byte.SIZE) - 1;
    }

    private long zeroBits(Varnode node) {
        if (node == null || node.getSize() <= 0 || node.getSize() > Long.BYTES) return 0;
        Long constant = literal(node);
        return constant != null ? ~constant & bitMask(node.getSize()) : zeros.getOrDefault(node, 0L);
    }

    private long deriveZeros(PcodeOp operation) {
        Varnode output = operation.getOutput();
        if (!output.isUnique() || output.getSize() <= 0 || output.getSize() > Long.BYTES) return 0;
        long mask = bitMask(output.getSize());
        Long constant = instructionLiteral(operation);
        if (constant != null) return ~constant & mask;
        if (operation.getNumInputs() == 0 || operation.getInput(0) == null) return 0;
        Varnode first = operation.getInput(0);
        long known = zeroBits(first);
        if (operation.getNumInputs() == 1) {
            if (operation.getOpcode() == PcodeOp.COPY && first.getSize() == output.getSize()) return known;
            if (first.getSize() > 0 && first.getSize() < output.getSize()) {
                long high = mask & ~bitMask(first.getSize());
                if (operation.getOpcode() == PcodeOp.INT_ZEXT) return high | known;
                if (operation.getOpcode() == PcodeOp.INT_SEXT && (known & (1L << (first.getSize() * Byte.SIZE - 1))) != 0) {
                    return high | known;
                }
            }
            return 0;
        }
        if (operation.getNumInputs() != 2 || operation.getInput(1) == null) return 0;
        Varnode second = operation.getInput(1);
        long other = zeroBits(second);
        int opcode = operation.getOpcode();
        if (opcode == PcodeOp.PIECE && first.getSize() > 0 && second.getSize() > 0 &&
                first.getSize() + second.getSize() == output.getSize()) return (known << (second.getSize() * Byte.SIZE)) | other;
        Long count = literal(second);
        if (opcode == PcodeOp.SUBPIECE && count != null && count >= 0 &&
                count <= first.getSize() - output.getSize() && first.getSize() <= Long.BYTES) return (known >>> (count * Byte.SIZE)) & mask;
        if (first.getSize() != output.getSize()) return 0;
        if ((opcode == PcodeOp.INT_LEFT || opcode == PcodeOp.INT_RIGHT || opcode == PcodeOp.INT_SRIGHT) && count != null && count >= 0) {
            int bits = output.getSize() * Byte.SIZE;
            boolean signZero = (known & (1L << (bits - 1))) != 0;
            if (count >= bits) return opcode != PcodeOp.INT_SRIGHT || signZero ? mask : 0;
            int shift = count.intValue();
            if (shift == 0) return known;
            long low = (1L << shift) - 1;
            if (opcode == PcodeOp.INT_LEFT) return ((known << shift) | low) & mask;
            long high = mask & ~((1L << (bits - shift)) - 1);
            return (known >>> shift) | (opcode == PcodeOp.INT_RIGHT || signZero ? high : 0);
        }
        if (second.getSize() != output.getSize()) return 0;
        return switch (opcode) {
            case PcodeOp.INT_AND -> known | other;
            case PcodeOp.INT_OR, PcodeOp.INT_XOR -> known & other;
            case PcodeOp.INT_ADD -> (known | other) == mask ? known & other : 0;
            default -> 0;
        };
    }

    private List<Fact> shiftedValues(Varnode input, long displacement, int outputSize) {
        var values = new ArrayList<Fact>();
        for (Fact value : readValues(input)) {
            long offset = value.offset() + displacement;
            if (offset >= 0 && offset <= outputSize - bytes) values.add(new Fact(Kind.VALUE, offset));
        }
        return values;
    }

    private List<Fact> readValues(Varnode node) {
        if (node == null || node.getSize() < bytes) return List.of();
        var values = new ArrayList<Fact>();
        for (var entry : facts.entrySet()) {
            Varnode known = entry.getKey();
            if (!VALUE.equals(entry.getValue()) || known.getSize() != bytes ||
                    !known.getAddress().getAddressSpace().equals(node.getAddress().getAddressSpace())) continue;
            long delta = known.getAddress().subtract(node.getAddress());
            if (delta >= 0 && delta <= node.getSize() - bytes) {
                values.add(new Fact(Kind.VALUE, physicalBigEndian(node) ? node.getSize() - bytes - delta : delta));
            }
        }
        return values;
    }

    private boolean physicalBigEndian(Varnode node) {
        return node.isRegister() ? registersBigEndian : program.getLanguage().isBigEndian();
    }

    private Varnode valueSpan(Varnode output, long offset) {
        long physical = physicalBigEndian(output) ? output.getSize() - bytes - offset : offset;
        return new Varnode(output.getAddress().add(physical), bytes);
    }

    Storage location(TargetRegisterMap registers) {
        var ordered = new ArrayList<>(facts.keySet());
        ordered.sort(Comparator.comparing(Varnode::getAddress).thenComparingInt(Varnode::getSize));
        for (Varnode node : ordered) {
            if (!VALUE.equals(facts.get(node))) continue;
            var view = RegisterByteSlice.mapped(program, node, registers);
            if (view != null) return view.storage();
        }
        Fact current = facts.get(new Varnode(pointer.getAddress(), pointer.getMinimumByteSize()));
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

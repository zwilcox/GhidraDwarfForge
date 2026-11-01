package ghidradwarfforge;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.LocalVariable;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Definite availability of one curated definition through a closed machine CFG. */
final class RegisterDefinitionFlow {
    private RegisterDefinitionFlow() {
    }

    static List<StorageInterval> prove(Program program, Function function, Variable variable,
            TargetRegisterMap registers, Storage rejected, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        var storage = variable.getVariableStorage();
        Register register = variable.getRegister();
        if (!(rejected instanceof UnavailableStorage unavailable) ||
                unavailable.reason() != OmissionReason.UNKNOWN_LIFETIME ||
                !(variable instanceof LocalVariable) || variable.getSource() != SourceType.USER_DEFINED ||
                variable.getProgram() != program || variable.getFunction() != function ||
                function.getProgram() != program || variable.getFirstUseOffset() <= 0 ||
                !variable.isValid() || !variable.hasAssignedStorage() || storage == null ||
                storage.getProgramArchitecture() != program || !storage.isValid() ||
                storage.isBadStorage() || storage.isForcedIndirect() || !storage.isRegisterStorage() ||
                storage.getVarnodeCount() != 1 || register == null || variable.getLength() <= 0 ||
                variable.getDataType().getLength() != variable.getLength() ||
                storage.size() != variable.getLength() || register.getBitLength() != variable.getLength() * 8L ||
                !storage.getFirstVarnode().getAddress().equals(register.getAddress()) ||
                function.getEntryPoint().getAddressSpace().isOverlaySpace()) {
            return List.of();
        }
        Register base = register.getBaseRegister();
        boolean attached = false;
        for (Variable other : function.getAllVariables()) {
            monitor.checkCancelled();
            if (other == variable) {
                attached = true;
                continue;
            }
            var otherStorage = other.getVariableStorage();
            if (!other.hasAssignedStorage() || otherStorage == null) continue;
            if (!otherStorage.isValid()) return List.of();
            for (var node : otherStorage.getVarnodes()) {
                if (node.getAddress().getAddressSpace().equals(base.getAddress().getAddressSpace()) &&
                        node.getOffset() < Math.addExact(base.getOffset(), base.getMinimumByteSize()) &&
                        Math.addExact(node.getOffset(), node.getSize()) > base.getOffset()) {
                    return List.of();
                }
            }
        }
        Storage mapped = GhidraVariableStorage.mappedRegister(register, variable.getLength(), registers, "local");
        if (!attached || !mapped.available()) return List.of();
        Address definition;
        try {
            definition = function.getEntryPoint().addNoWrap(variable.getFirstUseOffset());
        }
        catch (ghidra.program.model.address.AddressOverflowException overflow) {
            return List.of();
        }
        LocalBody inspected = inspectBody(program, function, monitor);
        Map<Address, Instruction> decoded = inspected.instructions();
        if (!decoded.containsKey(definition) || decoded.get(definition).getFlowType().isCall() ||
                !GhidraVariableStorage.completeRegisterDefinition(decoded.get(definition), register, variable.getLength())) {
            return List.of();
        }
        Map<Address, Set<Address>> successors = new LinkedHashMap<>();
        Map<Address, Set<Address>> predecessors = new HashMap<>();
        for (var entry : decoded.entrySet()) {
            monitor.checkCancelled();
            var edges = localSuccessors(entry.getValue());
            successors.put(entry.getKey(), edges);
            for (Address target : edges) predecessors.computeIfAbsent(target, unused -> new LinkedHashSet<>()).add(entry.getKey());
        }
        Address entry = function.getEntryPoint();
        Set<Address> reachable = new HashSet<>();
        var work = new ArrayDeque<Address>();
        work.add(entry);
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Address address = work.removeFirst();
            if (reachable.add(address)) work.addAll(successors.get(address));
        }
        if (!reachable.contains(definition)) return List.of();

        // Must analysis: initialize reachable facts to top and only remove
        // them. Entry has no initialized local. The recorded complete
        // definition generates a fact; every other physical write kills it.
        // The definition cannot itself be a call: its raw p-code outputs
        // precede callee execution and do not establish return-time values.
        // A join needs agreement from all executable predecessors, including
        // loop backedges. The finite lattice guarantees termination.
        Map<Address, Boolean> input = new HashMap<>();
        Map<Address, Boolean> output = new HashMap<>();
        for (Address address : decoded.keySet()) {
            if (!reachable.contains(address)) continue;
            output.put(address, true);
            work.add(address);
        }
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Address address = work.removeFirst();
            boolean available = !address.equals(entry);
            for (Address predecessor : predecessors.getOrDefault(address, Set.of())) {
                if (reachable.contains(predecessor)) available &= output.get(predecessor);
            }
            input.put(address, available);
            boolean after = address.equals(definition) ||
                (available && preserves(decoded.get(address), base, inspected.calls(), monitor));
            if (after != output.get(address)) {
                output.put(address, after);
                work.addAll(successors.get(address));
            }
        }
        Storage unknown = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
            "curated local definition and unchanged register are not established on every incoming path");
        var result = new ArrayList<StorageInterval>();
        for (var row : decoded.entrySet()) {
            monitor.checkCancelled();
            long start = row.getKey().getOffset();
            long end = Math.addExact(row.getValue().getMaxAddress().getOffset(), 1);
            Storage value = Boolean.TRUE.equals(input.get(row.getKey())) ? mapped : unknown;
            if (!result.isEmpty() && result.getLast().end() == start && result.getLast().storage().equals(value)) {
                var previous = result.removeLast();
                result.add(new StorageInterval(previous.start(), end, value));
            }
            else result.add(new StorageInterval(start, end, value));
        }
        return result.stream().anyMatch(interval -> interval.storage().available()) ? List.copyOf(result) : List.of();
    }

    record LocalBody(Map<Address, Instruction> instructions, Map<Address, DirectLeafCalls.Leaf> calls) {
    }

    /** Saved caller ownership and complete inspected call graphs are both required. */
    static LocalBody inspectBody(Program program, Function function, TaskMonitor monitor)
            throws CancelledException {
        monitor.checkCancelled();
        var rejected = new LocalBody(Map.of(), Map.of());
        if (function.getProgram() != program || function.getEntryPoint().getAddressSpace().isOverlaySpace()) return rejected;
        var decoded = decodedInstructions(program, function, true, monitor);
        if (decoded.isEmpty()) return rejected;
        var calls = DirectLeafCalls.inspect(program, List.copyOf(decoded.values()), monitor);
        return calls == null ? rejected : new LocalBody(decoded, calls);
    }

    /** Calls return to the caller successor; callee entries are not local CFG edges. */
    static Set<Address> localSuccessors(Instruction instruction) {
        var edges = new LinkedHashSet<Address>();
        if (!instruction.getFlowType().isCall()) {
            for (Address[] targets : new Address[][] {instruction.getDefaultFlows(), instruction.getFlows()}) {
                if (targets != null) edges.addAll(List.of(targets));
            }
        }
        if (instruction.getFallThrough() != null) edges.add(instruction.getFallThrough());
        return edges;
    }

    /** A physical write or a callee lacking either ABI or instruction proof retires the carrier. */
    static boolean preserves(Instruction instruction, Register register,
            Map<Address, DirectLeafCalls.Leaf> calls, TaskMonitor monitor) throws CancelledException {
        if (GhidraVariableStorage.writesRegister(instruction, register)) return false;
        if (!instruction.getFlowType().isCall()) return true;
        var callee = calls.get(instruction.getAddress());
        return callee != null && callee.preserves(register, monitor);
    }

    /** Physical decoder; the caller separately establishes saved function ownership. */
    static Map<Address, Instruction> decodedInstructions(Program program, Function function,
            boolean directCalls, TaskMonitor monitor) throws CancelledException {
        if (function.getEntryPoint().getAddressSpace().isOverlaySpace()) return Map.of();
        var body = function.getBody();
        var uncovered = new AddressSet(body);
        Map<Address, Instruction> decoded = new LinkedHashMap<>();
        for (Instruction instruction : program.getListing().getInstructions(body, true)) {
            monitor.checkCancelled();
            if (instruction.isLengthOverridden() || instruction.getLength() <= 0 ||
                    instruction.getParsedLength() != instruction.getLength() ||
                    instruction.isInDelaySlot() || instruction.getDelaySlotDepth() != 0 ||
                    !instruction.getAddress().getAddressSpace().equals(function.getEntryPoint().getAddressSpace()) ||
                    !body.contains(instruction.getAddress(), instruction.getMaxAddress()) ||
                    !uncovered.contains(instruction.getAddress(), instruction.getMaxAddress()) ||
                    GhidraVariableStorage.hasOpaqueRegisterEffects(program, instruction) ||
                    !orderedControl(instruction, directCalls)) {
                return Map.of();
            }
            uncovered.delete(instruction.getAddress(), instruction.getMaxAddress());
            decoded.put(instruction.getAddress(), instruction);
        }
        if (!uncovered.isEmpty() ||
                !GhidraVariableStorage.closedRegisterFlow(program, function, decoded, directCalls, monitor)) return Map.of();
        return java.util.Collections.unmodifiableMap(decoded);
    }

    /** No intra-instruction conditional execution or hidden control effects. */
    private static boolean orderedControl(Instruction instruction, boolean directCalls) {
        PcodeOp[] operations = instruction.getPcode();
        int branches = 0;
        int returns = 0;
        int calls = 0;
        for (int index = 0; index < operations.length; index++) {
            var operation = operations[index];
            switch (operation.getOpcode()) {
                case PcodeOp.CALL -> {
                    if (!directCalls || ++calls != 1 || index != operations.length - 1 ||
                            !DirectLeafCalls.directCall(instruction)) return false;
                }
                case PcodeOp.CALLIND, PcodeOp.CALLOTHER,
                    PcodeOp.UNIMPLEMENTED, PcodeOp.BRANCHIND -> { return false; }
                case PcodeOp.BRANCH, PcodeOp.CBRANCH -> {
                    boolean conditional = operation.getOpcode() == PcodeOp.CBRANCH;
                    Address[] defaults = instruction.getDefaultFlows();
                    if (++branches != 1 || index != operations.length - 1 || operation.getOutput() != null ||
                            operation.getNumInputs() != (conditional ? 2 : 1) || operation.getInput(0) == null ||
                            !instruction.getFlowType().isJump() || instruction.getFlowType().isConditional() != conditional ||
                            !operation.getInput(0).getAddress().getAddressSpace().equals(instruction.getAddress().getAddressSpace()) ||
                            defaults == null || defaults.length != 1 || !defaults[0].equals(operation.getInput(0).getAddress()) ||
                            (conditional && (operation.getInput(1) == null || operation.getInput(1).getSize() != 1))) {
                        return false;
                    }
                }
                case PcodeOp.RETURN -> {
                    if (++returns != 1 || index != operations.length - 1 || operation.getOutput() != null ||
                            operation.getNumInputs() != 1 || operation.getInput(0) == null ||
                            operation.getInput(0).getSize() != instruction.getAddress().getAddressSpace().getPointerSize() ||
                            !instruction.getFlowType().isTerminal()) return false;
                }
                default -> { }
            }
        }
        return calls == (instruction.getFlowType().isCall() ? 1 : 0) &&
            branches == (instruction.getFlowType().isJump() ? 1 : 0) &&
            returns == (instruction.getFlowType().isTerminal() ? 1 : 0);
    }
}

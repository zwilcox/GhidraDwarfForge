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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Latest explicitly recorded definition of one saved Ghidra merged local. */
final class MergedLocalLifetime {
    private MergedLocalLifetime() {
    }

    /** Stack-backed saved identity with explicit later register assignments. */
    private static List<StorageInterval> proveStack(Program program, Function function,
            GhidraLocalMappings.Group group, TargetRegisterMap registers, TaskMonitor monitor)
            throws CancelledException {
        Variable canonical = group.canonical();
        var storage = canonical.getVariableStorage();
        if (function.getProgram() != program || canonical.getFirstUseOffset() <= 0 ||
                !storage.isStackStorage() || storage.getVarnodeCount() != 1 ||
                storage.getProgramArchitecture() != program || !storage.isValid() ||
                storage.isForcedIndirect() || canonical.getLength() <= 0 ||
                storage.size() != canonical.getLength()) return List.of();
        var inspected = RegisterDefinitionFlow.inspectBody(program, function, monitor);
        var decoded = inspected.instructions();
        if (decoded.isEmpty()) return List.of();
        Set<Variable> members = new HashSet<>();
        Map<Address, Register> definitions = new LinkedHashMap<>();
        Address stackDefinition = null;
        for (var mapping : group.mappings()) {
            monitor.checkCancelled();
            Variable variable = mapping.variable();
            var assigned = variable.getVariableStorage();
            if (variable.getProgram() != program || variable.getFunction() != function ||
                    variable.getSource() != SourceType.USER_DEFINED || !variable.isValid() ||
                    !variable.hasAssignedStorage() || assigned == null || !assigned.isValid() ||
                    assigned.getProgramArchitecture() != program || assigned.isForcedIndirect() ||
                    assigned.getVarnodeCount() != 1 || assigned.size() != canonical.getLength() ||
                    !variable.getDataType().equals(canonical.getDataType()) ||
                    variable.getLength() != canonical.getLength() || !members.add(variable) ||
                    mapping.definition().subtract(function.getEntryPoint()) != variable.getFirstUseOffset() ||
                    !decoded.containsKey(mapping.definition()) ||
                    decoded.get(mapping.definition()).getFlowType().isCall()) return List.of();
            if (variable == canonical) {
                if (mapping.register() != null || stackDefinition != null) return List.of();
                stackDefinition = mapping.definition();
            }
            else {
                Register register = mapping.register();
                if (register == null || !assigned.isRegisterStorage() || variable.getRegister() != register ||
                        register.getBaseRegister() == program.getCompilerSpec().getStackPointer() ||
                        !GhidraVariableStorage.completeRegisterDefinition(decoded.get(mapping.definition()),
                            register, variable.getLength()) ||
                        !GhidraVariableStorage.mappedRegister(register, variable.getLength(), registers,
                            "saved stack-local assignment").available() ||
                        definitions.put(mapping.definition(), register) != null) return List.of();
            }
        }
        if (stackDefinition == null || definitions.containsKey(stackDefinition)) return List.of();
        int attached = 0;
        for (Variable other : function.getAllVariables()) {
            monitor.checkCancelled();
            if (members.contains(other)) { attached++; continue; }
            var assigned = other.getVariableStorage();
            if (!other.hasAssignedStorage() || assigned == null) continue;
            if (!assigned.isValid()) return List.of();
            // Conflicting owners need a separate ownership proof; a saved
            // identity never grants the entire frame to this one variable.
            for (Variable member : members) {
                if (member.getVariableStorage().intersects(assigned)) return List.of();
            }
        }
        if (attached != members.size()) return List.of();
        var analysis = StackValueFlow.forStackLocal(program, canonical.getLength(), canonical.getStackOffset());
        if (analysis == null) return List.of();
        analysis.setInspectedCalls(inspected.calls());
        return analysis.acrossSavedAssignments(function, decoded, stackDefinition, definitions, registers, monitor);
    }

    static List<StorageInterval> prove(Program program, Function function, GhidraLocalMappings.Group group,
            TargetRegisterMap registers, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (group.mappings().size() < 2 || group.canonical().getFunction() != function) return List.of();
        if (group.canonical().getVariableStorage().isStackStorage()) {
            return proveStack(program, function, group, registers, monitor);
        }
        if (group.mappings().stream().anyMatch(mapping -> mapping.register() == null)) return List.of();
        var inspected = RegisterDefinitionFlow.inspectBody(program, function, monitor);
        var decoded = inspected.instructions();
        if (decoded.isEmpty()) return List.of();
        Map<Address, Register> definitions = new LinkedHashMap<>();
        Map<Register, Storage> locations = new LinkedHashMap<>();
        Set<Variable> members = new HashSet<>();
        for (var mapping : group.mappings()) {
            monitor.checkCancelled();
            Variable variable = mapping.variable();
            Register register = mapping.register();
            var instruction = decoded.get(mapping.definition());
            if (variable.getProgram() != program || variable.getFunction() != function ||
                    variable.getSource() != SourceType.USER_DEFINED || !variable.isValid() ||
                    !variable.hasAssignedStorage() || variable.getRegister() != register ||
                    !variable.getDataType().equals(group.canonical().getDataType()) ||
                    variable.getLength() != group.canonical().getLength() ||
                    mapping.definition().subtract(function.getEntryPoint()) != variable.getFirstUseOffset() ||
                    instruction == null || instruction.getFlowType().isCall() || !members.add(variable) ||
                    !GhidraVariableStorage.completeRegisterDefinition(instruction, register, variable.getLength()) ||
                    definitions.put(mapping.definition(), register.getBaseRegister()) != null) return List.of();
            Storage storage = GhidraVariableStorage.mappedRegister(register, variable.getLength(), registers, "merged local");
            if (!storage.available()) return List.of();
            Storage previous = locations.putIfAbsent(register.getBaseRegister(), storage);
            if (previous != null && !previous.equals(storage)) return List.of();
        }
        if (!members.contains(group.canonical())) return List.of();
        int attached = 0;
        for (Variable other : function.getAllVariables()) {
            monitor.checkCancelled();
            if (members.contains(other)) { attached++; continue; }
            var storage = other.getVariableStorage();
            if (!other.hasAssignedStorage() || storage == null) continue;
            if (!storage.isValid()) return List.of();
            for (var node : storage.getVarnodes()) {
                for (Register base : locations.keySet()) {
                    if (node.getAddress().getAddressSpace().equals(base.getAddress().getAddressSpace()) &&
                            node.getOffset() < Math.addExact(base.getOffset(), base.getMinimumByteSize()) &&
                            Math.addExact(node.getOffset(), node.getSize()) > base.getOffset()) return List.of();
                }
            }
        }
        if (attached != members.size()) return List.of();
        Map<Address, Set<Address>> successors = new LinkedHashMap<>();
        Map<Address, Set<Address>> predecessors = new HashMap<>();
        for (var row : decoded.entrySet()) {
            monitor.checkCancelled();
            var edges = RegisterDefinitionFlow.localSuccessors(row.getValue());
            successors.put(row.getKey(), edges);
            for (Address target : edges) predecessors.computeIfAbsent(target, unused -> new LinkedHashSet<>()).add(row.getKey());
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
        Map<Address, Set<Register>> input = new HashMap<>();
        Map<Address, Set<Register>> output = new HashMap<>();
        Set<Register> universe = Set.copyOf(locations.keySet());
        for (Address address : decoded.keySet()) {
            if (!reachable.contains(address)) continue;
            output.put(address, universe);
            work.add(address);
        }
        while (!work.isEmpty()) {
            monitor.checkCancelled();
            Address address = work.removeFirst();
            var known = new HashSet<>(address.equals(entry) ? Set.<Register>of() : universe);
            for (Address predecessor : predecessors.getOrDefault(address, Set.of())) {
                if (reachable.contains(predecessor)) known.retainAll(output.get(predecessor));
            }
            input.put(address, Set.copyOf(known));
            Register definition = definitions.get(address);
            if (definition != null) {
                // A recorded assignment establishes the current logical value.
                // Every previous carrier is stale, even if it still has bits.
                // Copies, arithmetic updates and reinitializations share this
                // explicit saved identity; no identity is inferred from a COPY.
                known.clear();
                known.add(definition);
            }
            else {
                for (Register register : Set.copyOf(known)) {
                    if (!RegisterDefinitionFlow.preserves(decoded.get(address), register, inspected.calls(), monitor)) {
                        known.remove(register);
                    }
                }
            }
            if (!known.equals(output.get(address))) {
                output.put(address, Set.copyOf(known));
                work.addAll(successors.get(address));
            }
        }
        Storage unknown = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
            "latest saved merged-local definition has no common proven carrier on every incoming path");
        var result = new ArrayList<StorageInterval>();
        for (var row : decoded.entrySet()) {
            monitor.checkCancelled();
            Set<Register> known = input.getOrDefault(row.getKey(), Set.of());
            Storage storage = unknown;
            for (var location : locations.entrySet()) {
                if (known.contains(location.getKey())) { storage = location.getValue(); break; }
            }
            long start = row.getKey().getOffset();
            long end = Math.addExact(row.getValue().getMaxAddress().getOffset(), 1);
            if (!result.isEmpty() && result.getLast().end() == start && result.getLast().storage().equals(storage)) {
                var previous = result.removeLast();
                result.add(new StorageInterval(previous.start(), end, storage));
            }
            else result.add(new StorageInterval(start, end, storage));
        }
        return result.stream().anyMatch(interval -> interval.storage().available()) ? List.copyOf(result) : List.of();
    }
}

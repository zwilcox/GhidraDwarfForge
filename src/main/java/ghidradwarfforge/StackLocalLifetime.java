package ghidradwarfforge;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.LocalVariable;
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

/** Curated stack definitions, subsequent transfers and explicit storage reuse. */
final class StackLocalLifetime {
    private StackLocalLifetime() {
    }

    static List<StorageInterval> prove(Program program, Function function, Variable variable,
            TargetRegisterMap registers, Storage rejected, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        var storage = variable.getVariableStorage();
        if (!(rejected instanceof UnavailableStorage unavailable) ||
                unavailable.reason() != OmissionReason.UNKNOWN_LIFETIME ||
                !(variable instanceof LocalVariable) || variable.getSource() != SourceType.USER_DEFINED ||
                variable.getProgram() != program || variable.getFunction() != function ||
                function.getProgram() != program || variable.getFirstUseOffset() <= 0 ||
                !variable.isValid() || !variable.hasAssignedStorage() || storage == null ||
                storage.getProgramArchitecture() != program || !storage.isValid() ||
                storage.isBadStorage() || storage.isForcedIndirect() || !storage.isStackStorage() ||
                storage.getVarnodeCount() != 1 || variable.getLength() <= 0 ||
                variable.getDataType().getLength() != variable.getLength() ||
                storage.size() != variable.getLength() ||
                function.getBody().getNumAddressRanges() != 1 ||
                !function.getEntryPoint().equals(function.getBody().getMinAddress()) ||
                function.getEntryPoint().getAddressSpace().isOverlaySpace()) return List.of();
        Address definition;
        try { definition = function.getEntryPoint().addNoWrap(variable.getFirstUseOffset()); }
        catch (ghidra.program.model.address.AddressOverflowException overflow) { return List.of(); }
        var decoded = RegisterDefinitionFlow.decodedBody(program, function, monitor);
        if (!decoded.containsKey(definition)) return List.of();
        boolean attached = false;
        Address reuse = null;
        for (var other : function.getAllVariables()) {
            monitor.checkCancelled();
            if (other == variable) { attached = true; continue; }
            var otherStorage = other.getVariableStorage();
            if (!other.hasAssignedStorage() || otherStorage == null) continue;
            if (!otherStorage.isValid()) return List.of();
            if (!storage.intersects(otherStorage)) continue;
            if (!(other instanceof LocalVariable) || other.getFirstUseOffset() < 0 ||
                    other.getFirstUseOffset() == variable.getFirstUseOffset()) return List.of();
            if (other.getFirstUseOffset() < variable.getFirstUseOffset()) continue;
            Address start;
            try { start = function.getEntryPoint().addNoWrap(other.getFirstUseOffset()); }
            catch (ghidra.program.model.address.AddressOverflowException overflow) { return List.of(); }
            if (!decoded.containsKey(start)) return List.of();
            if (reuse == null || start.compareTo(reuse) < 0) reuse = start;
        }
        var analysis = StackValueFlow.forStackLocal(program, variable.getLength(), variable.getStackOffset());
        if (!attached || analysis == null) return List.of();
        var result = new ArrayList<StorageInterval>();
        for (var instruction : decoded.values()) {
            monitor.checkCancelled();
            if (instruction.getFlowType().isJump() || instruction.getFlowType().isConditional() ||
                    instruction.getFlowType().isCall()) return List.of();
            // An overlapping binding owns this instruction even if its first use
            // is a read. Do not retain a register copy of the preceding local.
            if (reuse != null && instruction.getAddress().compareTo(reuse) >= 0) analysis.retireLocalValue();
            long start = instruction.getAddress().getOffset();
            long end = Math.addExact(instruction.getMaxAddress().getOffset(), 1);
            Storage location = analysis.location(registers);
            if (!result.isEmpty() && result.getLast().end() == start && result.getLast().storage().equals(location)) {
                var previous = result.removeLast();
                result.add(new StorageInterval(previous.start(), end, location));
            }
            else result.add(new StorageInterval(start, end, location));
            if (!analysis.advance(instruction, instruction.getAddress().equals(definition), monitor)) return List.of();
        }
        return result.stream().anyMatch(interval -> interval.storage().available()) ? List.copyOf(result) : List.of();
    }
}

package ghidradwarfforge;

import java.util.LinkedHashSet;
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
                function.getEntryPoint().getAddressSpace().isOverlaySpace()) return List.of();
        Address definition;
        try { definition = function.getEntryPoint().addNoWrap(variable.getFirstUseOffset()); }
        catch (ghidra.program.model.address.AddressOverflowException overflow) { return List.of(); }
        var inspected = RegisterDefinitionFlow.inspectBody(program, function, monitor);
        var decoded = inspected.instructions();
        if (!decoded.containsKey(definition) || decoded.get(definition).getFlowType().isCall()) return List.of();
        boolean attached = false;
        var owners = new LinkedHashSet<Address>();
        for (var other : function.getAllVariables()) {
            monitor.checkCancelled();
            if (other == variable) { attached = true; continue; }
            var otherStorage = other.getVariableStorage();
            if (!other.hasAssignedStorage() || otherStorage == null) continue;
            if (!otherStorage.isValid()) return List.of();
            if (!storage.intersects(otherStorage)) continue;
            if (!(other instanceof LocalVariable) || other.getFirstUseOffset() < 0 ||
                    other.getFirstUseOffset() == variable.getFirstUseOffset()) return List.of();
            Address start;
            try { start = function.getEntryPoint().addNoWrap(other.getFirstUseOffset()); }
            catch (ghidra.program.model.address.AddressOverflowException overflow) { return List.of(); }
            if (!decoded.containsKey(start)) return List.of();
            owners.add(start);
        }
        var analysis = StackValueFlow.forStackLocal(program, variable.getLength(), variable.getStackOffset());
        if (!attached || analysis == null) return List.of();
        analysis.setInspectedCalls(inspected.calls());
        return analysis.acrossControlFlow(function, decoded, definition, owners, registers, monitor);
    }
}

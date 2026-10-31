package ghidradwarfforge;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraVariableStorage.StorageInterval;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.Piece;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;

/** Independent physical proofs for every piece of one attached incoming value. */
final class CompositeValueFlow {
    private CompositeValueFlow() {
    }

    static List<StorageInterval> prove(Program program, Function function, Parameter parameter,
            TargetRegisterMap registers, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        var storage = parameter.getVariableStorage();
        var formal = parameter.getFormalDataType();
        int bytes = parameter.getLength();
        if (function.getProgram() != program || parameter.getFunction() != function ||
                parameter.getOrdinal() < 0 || function.getParameter(parameter.getOrdinal()) != parameter ||
                parameter.getFirstUseOffset() != 0 || bytes <= 0 || formal == null || formal.getLength() != bytes ||
                storage == null || storage.getProgramArchitecture() != program || !storage.isValid() ||
                storage.isBadStorage() || storage.isUnassignedStorage() || storage.isForcedIndirect() ||
                storage.size() != bytes || storage.getVarnodeCount() < 2) return List.of();
        Varnode[] nodes = storage.getVarnodes();
        if (nodes == null || nodes.length != storage.getVarnodeCount()) return List.of();
        var ends = new ArrayList<Address>();
        long total = 0;
        boolean hasRegister = false;
        for (int index = 0; index < nodes.length; index++) {
            monitor.checkCancelled();
            Varnode node = nodes[index];
            if (node == null || node.getSize() <= 0) return List.of();
            if (node.isRegister()) {
                var register = program.getRegister(node);
                if (register == null || register != program.getLanguage().getRegister(node.getAddress(), node.getSize()) ||
                        register.getLeastSignificantBitInBaseRegister() != 0 ||
                        register.getBaseRegister() == program.getCompilerSpec().getStackPointer() ||
                        !(GhidraVariableStorage.mappedRegister(register, node.getSize(), registers,
                            "incoming composite piece") instanceof RegisterStorage)) return List.of();
                hasRegister = true;
            }
            else if (!node.getAddress().isStackAddress() ||
                    node.getAddress().getAddressSpace() != program.getAddressFactory().getStackSpace() ||
                    index != (program.getLanguage().isBigEndian() ? nodes.length - 1 : 0) ||
                    (node.getOffset() < 0 && node.getOffset() > -((long) node.getSize()))) return List.of();
            Address end;
            try { end = node.getAddress().addNoWrap(node.getSize() - 1L); }
            catch (ghidra.program.model.address.AddressOverflowException overflow) { return List.of(); }
            for (int previous = 0; previous < index; previous++) {
                monitor.checkCancelled();
                if (node.getAddress().getAddressSpace().equals(nodes[previous].getAddress().getAddressSpace()) &&
                        node.getAddress().compareTo(ends.get(previous)) <= 0 &&
                        nodes[previous].getAddress().compareTo(end) <= 0) return List.of();
            }
            ends.add(end);
            total += node.getSize();
            if (total > bytes) return List.of();
        }
        if (!hasRegister || total != bytes) return List.of();
        var decoded = RegisterDefinitionFlow.decodedInstructions(program, function, true, monitor);
        if (decoded.isEmpty()) return List.of();
        var calls = DirectLeafCalls.inspect(program, List.copyOf(decoded.values()), monitor);
        if (calls == null) return List.of();
        var proofs = new ArrayList<List<StorageInterval>>();
        var widths = new ArrayList<Integer>();
        // Ghidra joins are significance ordered; DWARF pieces are memory ordered.
        for (int order = 0; order < nodes.length; order++) {
            monitor.checkCancelled();
            Varnode node = nodes[program.getLanguage().isBigEndian() ? order : nodes.length - order - 1];
            var state = StackValueFlow.forIncomingPiece(program, node);
            if (state == null) return List.of();
            state.setInspectedCalls(calls);
            var proof = state.acrossControlFlow(function, decoded, null, Set.of(), registers, monitor);
            if (proof.isEmpty()) return List.of();
            proofs.add(proof);
            widths.add(Math.multiplyExact(node.getSize(), 8));
        }
        // Intersect availability, never union it: one lost piece makes the
        // whole value unavailable even if every other piece still survives.
        var boundaries = new TreeSet<Long>();
        for (var proof : proofs) for (var interval : proof) {
            monitor.checkCancelled();
            boundaries.add(interval.start());
            boundaries.add(interval.end());
        }
        var points = new ArrayList<>(boundaries);
        int[] cursors = new int[proofs.size()];
        var result = new ArrayList<StorageInterval>();
        for (int index = 0; index + 1 < points.size(); index++) {
            monitor.checkCancelled();
            long start = points.get(index), end = points.get(index + 1);
            var pieces = new ArrayList<Piece>();
            boolean covered = true;
            for (int piece = 0; piece < proofs.size(); piece++) {
                var proof = proofs.get(piece);
                while (cursors[piece] < proof.size() && proof.get(cursors[piece]).end() <= start) cursors[piece]++;
                if (cursors[piece] == proof.size() || proof.get(cursors[piece]).start() > start) {
                    covered = false;
                    break;
                }
                var interval = proof.get(cursors[piece]);
                if (interval.storage().available()) pieces.add(new Piece(interval.storage(), widths.get(piece)));
            }
            if (!covered) continue; // A discontiguous body hole is not executable scope.
            Storage value = pieces.size() == proofs.size() ? new CompositeStorage(pieces) :
                new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
                    "one or more pieces of the incoming value have no proven surviving storage");
            if (!result.isEmpty() && result.getLast().end() == start && result.getLast().storage().equals(value)) {
                var previous = result.removeLast();
                result.add(new StorageInterval(previous.start(), end, value));
            }
            else result.add(new StorageInterval(start, end, value));
        }
        return List.copyOf(result);
    }
}

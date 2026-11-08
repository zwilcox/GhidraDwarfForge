package ghidradwarfforge;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.calls.CallSitePlan;
import ghidradwarfforge.calls.GhidraCallArgumentFlow;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.targets.UnwindAbiProfile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Binds captured entry storage to recovered whole-register actual values, never body locations. */
public final class GhidraCallParameters {
    public record Piece(Address address, int bytes) {
        public Piece {
            Objects.requireNonNull(address);
            if (bytes <= 0) throw new IllegalArgumentException("invalid entry-storage width");
        }
    }
    public record Entry(long functionId, Address function, int ordinal, TypeGraph.Parameter formal,
            List<Piece> pieces, boolean assigned, boolean indirect) {
        public Entry {
            Objects.requireNonNull(function);
            Objects.requireNonNull(formal);
            pieces = List.copyOf(pieces);
            if (ordinal < 0) throw new IllegalArgumentException("invalid formal ordinal");
        }
    }
    public record Result(List<CallSitePlan.Argument> arguments, List<String> omissions) {
        public Result {
            arguments = List.copyOf(arguments);
            omissions = List.copyOf(omissions);
        }
    }
    private GhidraCallParameters() { }

    /** Called in the same extraction loop that reserves the canonical formal type. */
    static Entry snapshot(Function function, int ordinal, TypeGraph.Parameter formal,
            VariableStorage storage, boolean originalIndirect) {
        boolean assigned = storage != null && !storage.isBadStorage() &&
            !storage.isUnassignedStorage() && !storage.isVoidStorage();
        var pieces = new ArrayList<Piece>();
        if (assigned) for (var node : storage.getVarnodes()) pieces.add(new Piece(node.getAddress(), node.getSize()));
        return new Entry(function.getID(), function.getEntryPoint(), ordinal, formal, pieces, assigned,
            originalIndirect || storage != null && storage.isForcedIndirect());
    }

    /** The caller retains one consistent Program view from extraction through publication. */
    public static Result bind(Program program, Function callee, ProgramTypeModel.FunctionSignature signature,
            TypeGraph graph, List<Entry> entries, GhidraCallArgumentFlow.State values,
            TargetRegisterMap registers, ElfImage image, long delta, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (signature == null || values == null) return new Result(List.of(), List.of("no formal declaration or actual-value proof"));
        if (signature.address() != AddressNormalizer.toElfAddress(callee.getEntryPoint().getOffset(), delta)) {
            throw new IllegalArgumentException("callee signature address differs from entry storage");
        }
        final UnwindAbiProfile.Bound profile;
        try { profile = UnwindAbiProfile.selectForCallSites(program, callee, image, delta, monitor); }
        catch (IllegalArgumentException unavailable) { return new Result(List.of(), List.of(unavailable.getMessage())); }
        var snapshots = new HashMap<Integer, Entry>();
        for (var entry : entries) {
            monitor.checkCancelled();
            if (entry.functionId() != callee.getID() || !entry.function().equals(callee.getEntryPoint()) ||
                    snapshots.put(entry.ordinal(), entry) != null) {
                throw new IllegalArgumentException("stale or duplicate callee entry-storage identity");
            }
        }
        var arguments = new ArrayList<CallSitePlan.Argument>();
        var omissions = new ArrayList<String>();
        var nodes = graph.byKey();
        int addressBytes = image.is64Bit() ? 8 : 4;
        for (int ordinal = 0; ordinal < signature.parameters().size(); ordinal++) {
            monitor.checkCancelled();
            var formal = signature.parameters().get(ordinal);
            var entry = snapshots.get(ordinal);
            try {
                require(entry != null, "no captured entry storage (possibly decompiler-only parameter)");
                require(entry.formal().equals(formal), "formal identity changed after storage capture");
                require(!formal.returnStorage(), "hidden return carrier is not a formal argument");
                long bytes = integerBytes(nodes, formal.type());
                require(bytes > 0 && bytes <= addressBytes, "unsupported integer formal type or width");
                require(entry.assigned() && !entry.indirect() && entry.pieces().size() == 1,
                    "entry storage is unavailable, indirect or composite");
                var piece = entry.pieces().getFirst();
                require(piece.address().isRegisterAddress() && piece.bytes() == bytes, "entry storage is not one matching register value");
                var view = RegisterByteSlice.mapped(program, new Varnode(piece.address(), piece.bytes()), registers);
                require(view != null && view.storage().valueBitOffset() == 0, "unmapped or non-low register slice");
                int number = view.storage().register().dwarfNumber();
                var cell = profile.registers().get(number);
                require(cell != null && cell.bytes() <= addressBytes && piece.bytes() <= cell.bytes() &&
                    piece.address().getOffset() == cell.offset(), "DWARF mapping differs from the physical profile register");
                // Use the whole destination register. A known low word alone is
                // insufficient evidence for the upper bits of DW_OP_entry_value.
                var value = GhidraCallArgumentFlow.read(values.values(), cell);
                require(value != null && value.bytes() == cell.bytes(), "whole destination register value is unavailable");
                arguments.add(new CallSitePlan.Argument(ordinal, formal.name(), formal.type().key(), number, value));
            }
            catch (IllegalArgumentException unavailable) {
                omissions.add("parameter " + ordinal + " (" + formal.name() + "): " + unavailable.getMessage());
            }
        }
        var counts = new HashMap<Integer, Integer>();
        arguments.forEach(argument -> counts.merge(argument.dwarfRegister(), 1, Integer::sum));
        arguments.removeIf(argument -> {
            if (counts.get(argument.dwarfRegister()) == 1) return false;
            omissions.add("parameter " + argument.ordinal() + ": destination register overlaps another formal");
            return true;
        });
        monitor.checkCancelled();
        return new Result(arguments, omissions);
    }

    private static long integerBytes(Map<String, TypeGraph.TypeNode> nodes, TypeGraph.TypeRef reference) {
        var seen = new java.util.HashSet<String>();
        var node = nodes.get(reference.key());
        while (node != null && seen.add(node.key()) && seen.size() <= 64) {
            if (node instanceof TypeGraph.TypedefType alias) node = nodes.get(alias.target().key());
            else if (node instanceof TypeGraph.QualifiedType qualified) node = nodes.get(qualified.target().key());
            else if (node instanceof TypeGraph.EnumType enumeration) return enumeration.byteSize();
            else if (node instanceof TypeGraph.BaseType base) return switch (base.encoding()) {
                case SIGNED, UNSIGNED, SIGNED_CHAR, UNSIGNED_CHAR, BOOLEAN, UTF -> base.byteSize();
                default -> -1;
            };
            else return -1;
        }
        return -1;
    }

    private static void require(boolean condition, String reason) {
        if (!condition) throw new IllegalArgumentException(reason);
    }
}

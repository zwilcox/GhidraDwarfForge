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
import ghidradwarfforge.calls.GhidraCallSiteEvidence;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.unwind.UnwindFlow.Cell;
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
    private record Destination(RegisterStorage storage, Cell cell) { }

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
                var destination = destination(program, formal, entry, nodes, registers, profile, addressBytes);
                var cell = destination.cell();
                // Use the whole destination register. A known low word alone is
                // insufficient evidence for the upper bits of DW_OP_entry_value.
                var value = GhidraCallArgumentFlow.read(values.values(), cell);
                require(value != null && value.bytes() == cell.bytes(), "whole destination register value is unavailable");
                arguments.add(new CallSitePlan.Argument(ordinal, formal.name(), formal.type().key(),
                    destination.storage().register().dwarfNumber(), value));
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

    /**
     * Preserve the recorded entry-register location at the exact first PC only.
     * This describes the formal's entry storage, not its value, a new call frame,
     * or any post-instruction lifetime. Existing available locations win.
     */
    public static ProgramTypeModel withEntryLocations(Program program, ProgramTypeModel model, List<Entry> entries,
            List<GhidraCallSiteEvidence.FunctionEvidence> captures, TargetRegisterMap registers, ElfImage image,
            long delta, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (model == null) return null;
        var signatures = new HashMap<Long, ProgramTypeModel.FunctionSignature>();
        model.functions().forEach(f -> signatures.put(f.address(), f));
        var captured = new HashMap<Long, GhidraCallSiteEvidence.FunctionEvidence>();
        for (var capture : captures) {
            monitor.checkCancelled();
            captured.put(AddressNormalizer.toElfAddress(capture.function().entry().getOffset(), delta), capture);
        }
        var snapshots = new HashMap<Address, List<Entry>>();
        for (var entry : entries) {
            monitor.checkCancelled();
            snapshots.computeIfAbsent(entry.function(), ignored -> new ArrayList<>()).add(entry);
        }
        var variables = new ArrayList<VariableLocation>();
        var nodes = model.types().byKey();
        for (var variable : model.variableStorage().variables()) {
            monitor.checkCancelled();
            VariableLocation refined = variable;
            var capture = captured.get(variable.functionAddress());
            var signature = signatures.get(variable.functionAddress());
            if (variable.kind() == VariableKind.PARAMETER && capture != null && signature != null) {
                var entryAddress = capture.function().entry();
                var function = program.getFunctionManager().getFunctionAt(entryAddress);
                var instruction = capture.instructions().stream().filter(i -> i.address().equals(entryAddress)).findFirst();
                var matching = snapshots.getOrDefault(entryAddress, List.of()).stream()
                    .filter(e -> e.formal().name().equals(variable.name())).toList();
                try {
                    require(function != null && instruction.isPresent() && instruction.get().original() != null &&
                        instruction.get().transfer().kind() != GhidraCallSiteEvidence.Kind.UNAVAILABLE,
                        "no original entry instruction");
                    require(matching.size() == 1, "ambiguous or missing entry storage");
                    var entry = matching.getFirst();
                    require(entry.functionId() == function.getID() && entry.ordinal() < signature.parameters().size(),
                        "stale entry storage identity");
                    var formal = signature.parameters().get(entry.ordinal());
                    var profile = UnwindAbiProfile.selectForCallSites(program, function, image, delta, monitor);
                    var mapped = destination(program, formal, entry, nodes, registers, profile, image.is64Bit() ? 8 : 4);
                    require(variable.byteSize() == integerBytes(nodes, formal.type()), "variable/formal widths differ");
                    long pc = variable.functionAddress();
                    var ranges = new ArrayList<LocationRange>();
                    boolean changed = false;
                    for (var range : variable.locations()) {
                        monitor.checkCancelled();
                        if (!range.storage().available() && range.start() <= pc && pc < range.end()) {
                            if (range.start() < pc) ranges.add(new LocationRange(range.start(), pc, range.storage(), range.evidence()));
                            ranges.add(new LocationRange(pc, Math.addExact(pc, 1), mapped.storage(),
                                new Evidence(range.evidence().confidence(), "Ghidra formal entry storage before first instruction; no post-entry lifetime or value inferred")));
                            if (pc + 1 < range.end()) ranges.add(new LocationRange(pc + 1, range.end(), range.storage(), range.evidence()));
                            changed = true;
                        }
                        else ranges.add(range);
                    }
                    if (changed) refined = new VariableLocation(variable.functionName(), pc, variable.name(), variable.kind(),
                        variable.byteSize(), ranges);
                }
                catch (IllegalArgumentException unavailable) {
                    // Keep the existing documented omission. Do not turn missing
                    // or unsupported entry evidence into a guessed location.
                }
            }
            variables.add(refined);
        }
        monitor.checkCancelled();
        return new ProgramTypeModel(model.types(), model.functions(), model.globals(), new VariableStorageModel(variables),
            model.functionStatics(), model.functionDeclarations(), model.lexicalScopes(), model.classScopes(), model.functionRelations());
    }

    private static Destination destination(Program program, TypeGraph.Parameter formal, Entry entry,
            Map<String, TypeGraph.TypeNode> nodes, TargetRegisterMap registers, UnwindAbiProfile.Bound profile, int addressBytes) {
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
        var cell = profile.registers().get(view.storage().register().dwarfNumber());
        require(cell != null && cell.bytes() <= addressBytes && piece.bytes() <= cell.bytes() &&
            piece.address().getOffset() == cell.offset(), "DWARF mapping differs from the physical profile register");
        return new Destination(view.storage(), cell);
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

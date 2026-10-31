package ghidradwarfforge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/** Explicit saved lexical knowledge; never a proof of a variable's machine location. */
public final class GhidraLexicalScopes {
    public static final String PROPERTY_NAME = "GhidraDwarfForge.LexicalScopes.v1";
    private static final String PREFIX = "GDFLS1:";
    private static final int MAX_BLOCKS = 4096;
    private static final int MAX_BINDINGS = 16384;
    private static final int MAX_RANGES = 65536;
    private static final int MAX_BYTES = 8 * 1024 * 1024;

    /** Empty parent means the owning function. Bounds are inclusive Ghidra addresses. */
    public record Block(String id, String parent, AddressSetView body) {
        public Block {
            text(id, false);
            text(parent, true);
            if (body == null || body.isEmpty()) throw invalid("empty block body");
            body = new AddressSet(body);
        }

        @Override
        public AddressSetView body() {
            return new AddressSet(body);
        }
    }

    /** Display spelling is explicit; a saved suffix is never stripped implicitly. */
    public record Local(Variable variable, String block, String displayName) {
        public Local {
            if (variable == null) throw invalid("missing local");
            text(block, true);
            text(displayName, false);
        }
    }

    public record Snapshot(long functionId, String evidence, List<Block> blocks, List<Local> locals) {
        public Snapshot {
            text(evidence, false);
            blocks = List.copyOf(blocks);
            locals = List.copyOf(locals);
        }
    }

    private GhidraLexicalScopes() {
    }

    /**
     * Persist an explicit analyst assertion in the caller's program transaction.
     * Export only reads this map. No original executable bytes are changed.
     */
    public static void save(Function function, String evidence, List<Block> blocks,
            List<Local> locals, TaskMonitor monitor)
            throws CancelledException, DuplicateNameException {
        Snapshot snapshot = validate(function, evidence, blocks, locals, monitor);
        String encoded;
        try {
            encoded = encode(function, snapshot, monitor);
        }
        catch (IOException failure) {
            throw invalid("cannot encode lexical evidence: " + failure.getMessage());
        }
        monitor.checkCancelled();
        var manager = function.getProgram().getUsrPropertyManager();
        var existing = manager.getPropertyMap(PROPERTY_NAME);
        if (existing != null && !(existing instanceof ghidra.program.model.util.StringPropertyMap)) {
            throw invalid("lexical property map has incompatible storage type");
        }
        var properties = existing == null ? manager.createStringPropertyMap(PROPERTY_NAME)
            : (ghidra.program.model.util.StringPropertyMap) existing;
        properties.add(function.getEntryPoint(), encoded);
    }

    /** Missing evidence is normal. Stale/malformed evidence is diagnosed, never partially used. */
    public static Optional<Snapshot> read(Function function, TaskMonitor monitor,
            Consumer<String> diagnostic) throws CancelledException {
        monitor.checkCancelled();
        var properties = function.getProgram().getUsrPropertyManager().getPropertyMap(PROPERTY_NAME);
        if (properties == null) return Optional.empty();
        if (!(properties instanceof ghidra.program.model.util.StringPropertyMap strings)) {
            diagnostic.accept("Omitted saved lexical scopes for " + function.getName(true) +
                ": lexical property map has incompatible storage type");
            return Optional.empty();
        }
        String encoded = strings.getString(function.getEntryPoint());
        if (encoded == null) return Optional.empty();
        try {
            return Optional.of(decode(function, encoded, monitor));
        }
        catch (IOException | IllegalArgumentException failure) {
            diagnostic.accept("Omitted saved lexical scopes for " + function.getName(true) +
                ": " + failure.getMessage());
            return Optional.empty();
        }
    }

    private static Snapshot validate(Function function, String evidence, List<Block> blocks,
            List<Local> locals, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        text(evidence, false);
        if (function.isExternal() || function.getSymbol() == null || function.getBody().isEmpty()) {
            throw invalid("scope owner is not a saved image function");
        }
        if (blocks == null || locals == null || blocks.size() > MAX_BLOCKS || locals.size() > MAX_BINDINGS) {
            throw invalid("lexical evidence exceeds record bounds");
        }
        Map<String, Block> byId = new HashMap<>();
        int ranges = 0;
        for (Block block : blocks) {
            monitor.checkCancelled();
            if (byId.put(block.id(), block) != null) throw invalid("duplicate block identity");
            ranges = Math.addExact(ranges, block.body.getNumAddressRanges());
            if (ranges > MAX_RANGES) throw invalid("too many lexical ranges");
            if (!function.getBody().contains(block.body)) throw invalid("block lies outside function body");
            for (var range : block.body.getAddressRanges()) {
                monitor.checkCancelled();
                if (!range.getMinAddress().getAddressSpace().equals(function.getEntryPoint().getAddressSpace())) {
                    throw invalid("block crosses the function address space");
                }
                // Persist only exact, reversible offsets; never truncate address arithmetic.
                offset(function, range.getMinAddress());
                offset(function, range.getMaxAddress());
            }
        }
        Map<String, Integer> depths = new HashMap<>();
        for (Block block : blocks) {
            var path = new HashSet<String>();
            Block current = block;
            while (current != null) {
                monitor.checkCancelled();
                if (!path.add(current.id())) throw invalid("cyclic block ownership");
                if (current.parent().isEmpty()) break;
                Block parent = byId.get(current.parent());
                if (parent == null) throw invalid("missing parent block");
                if (!parent.body.contains(current.body)) throw invalid("child escapes parent block");
                current = parent;
            }
            depths.put(block.id(), path.size());
        }
        // Sibling ranges may be discontiguous, but must not make debugger lookup ambiguous.
        Map<String, AddressSet> siblings = new HashMap<>();
        for (Block block : blocks) {
            monitor.checkCancelled();
            var occupied = siblings.computeIfAbsent(block.parent(), unused -> new AddressSet());
            if (occupied.intersects(block.body)) throw invalid("overlapping sibling blocks");
            occupied.add(block.body);
        }
        Map<Long, Variable> actual = localsById(function, monitor);
        Map<Long, Local> bindings = new HashMap<>();
        Map<String, HashSet<String>> names = new HashMap<>();
        var rootNames = new HashSet<String>();
        for (var parameter : function.getParameters()) {
            monitor.checkCancelled();
            rootNames.add(parameter.getName());
        }
        names.put("", rootNames);
        for (Local local : locals) {
            monitor.checkCancelled();
            Variable variable = local.variable();
            if (variable.getSymbol() == null || actual.get(variable.getSymbol().getID()) != variable ||
                    variable.getFunction() != function || variable.getProgram() != function.getProgram()) {
                throw invalid("local does not have the recorded function identity");
            }
            if (!local.block().isEmpty() && !byId.containsKey(local.block())) throw invalid("missing local block");
            if (bindings.put(variable.getSymbol().getID(), local) != null) throw invalid("duplicate local ownership");
            if (!names.computeIfAbsent(local.block(), unused -> new HashSet<>()).add(local.displayName())) {
                throw invalid("ambiguous same-scope local spelling");
            }
        }
        for (Variable variable : actual.values()) {
            monitor.checkCancelled();
            if (!bindings.containsKey(variable.getSymbol().getID()) &&
                    !names.computeIfAbsent("", unused -> new HashSet<>()).add(variable.getName())) {
                throw invalid("scope spelling conflicts with unbound local");
            }
        }
        var orderedBlocks = blocks.stream().sorted(Comparator
            .comparingInt((Block block) -> depths.get(block.id())).thenComparing(Block::id)).toList();
        var orderedLocals = locals.stream().sorted(Comparator.comparing(Local::block)
            .thenComparing(Local::displayName).thenComparingLong(local -> local.variable().getSymbol().getID())).toList();
        return new Snapshot(function.getSymbol().getID(), evidence, orderedBlocks, orderedLocals);
    }

    private static Map<Long, Variable> localsById(Function function, TaskMonitor monitor)
            throws CancelledException {
        Map<Long, Variable> result = new HashMap<>();
        for (Variable local : function.getLocalVariables()) {
            monitor.checkCancelled();
            if (local.getSymbol() != null) result.put(local.getSymbol().getID(), local);
        }
        return result;
    }

    private static long offset(Function function, ghidra.program.model.address.Address address) {
        long delta = address.subtract(function.getEntryPoint());
        try {
            if (!function.getEntryPoint().addNoWrap(delta).equals(address)) throw invalid("unrepresentable scope offset");
        }
        catch (ghidra.program.model.address.AddressOverflowException overflow) {
            throw invalid("overflowed scope offset");
        }
        return delta;
    }

    private static String encode(Function function, Snapshot snapshot, TaskMonitor monitor)
            throws IOException, CancelledException {
        var bytes = new ByteArrayOutputStream();
        try (var output = new DataOutputStream(bytes)) {
            output.writeInt(1);
            output.writeLong(snapshot.functionId());
            output.writeUTF(snapshot.evidence());
            output.writeInt(snapshot.blocks().size());
            for (Block block : snapshot.blocks()) {
                monitor.checkCancelled();
                output.writeUTF(block.id());
                output.writeUTF(block.parent());
                output.writeInt(block.body.getNumAddressRanges());
                for (var range : block.body.getAddressRanges()) {
                    monitor.checkCancelled();
                    output.writeLong(offset(function, range.getMinAddress()));
                    output.writeLong(offset(function, range.getMaxAddress()));
                    if (bytes.size() > MAX_BYTES) throw invalid("lexical evidence exceeds byte bound");
                }
            }
            output.writeInt(snapshot.locals().size());
            for (Local local : snapshot.locals()) {
                monitor.checkCancelled();
                Variable variable = local.variable();
                output.writeLong(variable.getSymbol().getID());
                output.writeUTF(variable.getName());
                output.writeUTF(variable.getDataType().getPathName());
                output.writeLong(function.getProgram().getDataTypeManager().getID(variable.getDataType()));
                output.writeInt(variable.getLength());
                output.writeInt(variable.getFirstUseOffset());
                output.writeUTF(variable.getVariableStorage().getSerializationString());
                output.writeUTF(local.block());
                output.writeUTF(local.displayName());
                if (bytes.size() > MAX_BYTES) throw invalid("lexical evidence exceeds byte bound");
            }
        }
        if (bytes.size() > MAX_BYTES) throw invalid("lexical evidence exceeds byte bound");
        return PREFIX + Base64.getEncoder().encodeToString(bytes.toByteArray());
    }

    private static Snapshot decode(Function function, String encoded, TaskMonitor monitor)
            throws IOException, CancelledException {
        if (!encoded.startsWith(PREFIX) || encoded.length() > PREFIX.length() + ((MAX_BYTES + 2) / 3) * 4) {
            throw invalid("unsupported or oversized lexical evidence");
        }
        byte[] bytes = Base64.getDecoder().decode(encoded.substring(PREFIX.length()));
        if (bytes.length > MAX_BYTES) throw invalid("oversized lexical evidence");
        try (var input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            if (input.readInt() != 1 || input.readLong() != function.getSymbol().getID()) {
                throw invalid("version or function identity changed");
            }
            String evidence = input.readUTF();
            int blockCount = count(input.readInt(), MAX_BLOCKS);
            var blocks = new ArrayList<Block>();
            int ranges = 0;
            for (int index = 0; index < blockCount; index++) {
                monitor.checkCancelled();
                String id = input.readUTF();
                String parent = input.readUTF();
                int length = count(input.readInt(), MAX_RANGES - ranges);
                ranges += length;
                var body = new AddressSet();
                for (int range = 0; range < length; range++) {
                    monitor.checkCancelled();
                    long low = input.readLong();
                    long high = input.readLong();
                    if (low > high) throw invalid("reversed lexical range");
                    try {
                        body.add(function.getEntryPoint().addNoWrap(low), function.getEntryPoint().addNoWrap(high));
                    }
                    catch (ghidra.program.model.address.AddressOverflowException overflow) {
                        throw invalid("rebased lexical range overflow");
                    }
                }
                blocks.add(new Block(id, parent, body));
            }
            Map<Long, Variable> actual = localsById(function, monitor);
            int localCount = count(input.readInt(), MAX_BINDINGS);
            var locals = new ArrayList<Local>();
            for (int index = 0; index < localCount; index++) {
                monitor.checkCancelled();
                Variable variable = actual.get(input.readLong());
                String name = input.readUTF();
                String type = input.readUTF();
                long typeId = input.readLong();
                int size = input.readInt();
                int firstUse = input.readInt();
                String storage = input.readUTF();
                String block = input.readUTF();
                String display = input.readUTF();
                if (variable == null || !variable.getName().equals(name) ||
                        !variable.getDataType().getPathName().equals(type) ||
                        function.getProgram().getDataTypeManager().getID(variable.getDataType()) != typeId ||
                        variable.getLength() != size || variable.getFirstUseOffset() != firstUse ||
                        !variable.getVariableStorage().getSerializationString().equals(storage)) {
                    throw invalid("saved local identity, name, type or storage changed");
                }
                locals.add(new Local(variable, block, display));
            }
            if (input.read() != -1) throw invalid("trailing lexical evidence bytes");
            return validate(function, evidence, blocks, locals, monitor);
        }
    }

    private static int count(int value, int maximum) {
        if (value < 0 || value > maximum) throw invalid("invalid lexical record count");
        return value;
    }

    private static void text(String value, boolean emptyAllowed) {
        if (value == null || (!emptyAllowed && value.isBlank()) || value.length() > 1024 || value.indexOf('\0') >= 0) {
            throw invalid("invalid lexical text");
        }
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }
}

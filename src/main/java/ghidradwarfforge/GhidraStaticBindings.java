package ghidradwarfforge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.function.Consumer;

import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Explicit memory-object ownership; a namespace spelling alone never establishes a static local. */
public final class GhidraStaticBindings {
    public static final String OPTIONS_NAME = "GhidraDwarfForge Static Bindings v1";
    private static final String PREFIX = "GDFSB1:";
    private static final int MAX_BYTES = 65536;

    public enum Status { ABSENT, VALID, REJECTED }

    public record Snapshot(Symbol symbol, Function owner, Data data, String block,
            String displayName, String evidence) { }

    public record Result(Status status, Snapshot binding) {
        public Result {
            if (status == null || (status == Status.VALID) != (binding != null)) {
                throw invalid("invalid static-binding result");
            }
        }
    }

    private GhidraStaticBindings() { }

    /** One record per symbol identity, written only in an explicit caller transaction. */
    public static void save(Program program, Symbol symbol, Function owner, String block,
            String displayName, String evidence, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        Data data = validate(program, symbol, owner, block, displayName, evidence, monitor);
        String scope = scopeFingerprint(owner, block, monitor);
        String encoded;
        try {
            var bytes = new ByteArrayOutputStream();
            try (var output = new DataOutputStream(bytes)) {
                output.writeInt(1);
                output.writeLong(symbol.getID());
                output.writeLong(owner.getSymbol().getID());
                output.writeUTF(symbol.getName());
                output.writeLong(symbol.getParentNamespace().getID());
                output.writeLong(relative(symbol, owner));
                output.writeLong(program.getDataTypeManager().getID(data.getDataType()));
                output.writeUTF(data.getDataType().getPathName());
                output.writeInt(data.getLength());
                var universal = data.getDataType().getUniversalID();
                output.writeBoolean(universal != null);
                if (universal != null) output.writeLong(universal.getValue());
                output.writeUTF(block);
                output.writeUTF(scope);
                output.writeUTF(displayName);
                output.writeUTF(evidence);
            }
            if (bytes.size() > MAX_BYTES) throw invalid("oversized static binding");
            encoded = PREFIX + Base64.getEncoder().encodeToString(bytes.toByteArray());
        }
        catch (IOException failure) {
            throw invalid("cannot encode static binding: " + failure.getMessage());
        }
        monitor.checkCancelled();
        String key = key(symbol.getID());
        if (program.getOptionsNames().contains(OPTIONS_NAME)) {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.contains(key) && options.getType(key) != OptionType.STRING_TYPE) {
                throw invalid("static binding option has incompatible type");
            }
        }
        monitor.checkCancelled();
        program.getOptions(OPTIONS_NAME).setString(key, encoded);
    }

    /** No repair or inferred fallback follows a rejected explicit association. */
    public static Result read(Program program, long symbolId, TaskMonitor monitor,
            Consumer<String> diagnostic) throws CancelledException {
        monitor.checkCancelled();
        String key = key(symbolId);
        if (!program.getOptionsNames().contains(OPTIONS_NAME)) return new Result(Status.ABSENT, null);
        var options = program.getOptions(OPTIONS_NAME);
        if (!options.contains(key)) return new Result(Status.ABSENT, null);
        try {
            if (options.getType(key) != OptionType.STRING_TYPE) throw invalid("static binding option has incompatible type");
            String encoded = options.getString(key, null);
            if (encoded == null || !encoded.startsWith(PREFIX) ||
                    encoded.length() > PREFIX.length() + ((MAX_BYTES + 2) / 3) * 4) {
                throw invalid("unsupported or oversized static binding");
            }
            monitor.checkCancelled();
            byte[] bytes = Base64.getDecoder().decode(encoded.substring(PREFIX.length()));
            if (bytes.length > MAX_BYTES) throw invalid("oversized static binding");
            try (var input = new DataInputStream(new ByteArrayInputStream(bytes))) {
                if (input.readInt() != 1 || input.readLong() != symbolId) throw invalid("version or static identity changed");
                var ownerSymbol = program.getSymbolTable().getSymbol(input.readLong());
                if (ownerSymbol == null || !(ownerSymbol.getObject() instanceof Function owner)) {
                    throw invalid("saved static owner no longer exists");
                }
                String name = input.readUTF();
                long namespace = input.readLong();
                long offset = input.readLong();
                long typeId = input.readLong();
                String typePath = input.readUTF();
                int size = input.readInt();
                Long universal = input.readBoolean() ? input.readLong() : null;
                String block = input.readUTF();
                String scope = input.readUTF();
                String display = input.readUTF();
                String evidence = input.readUTF();
                if (input.read() != -1) throw invalid("trailing static binding data");
                monitor.checkCancelled();
                var symbol = program.getSymbolTable().getSymbol(symbolId);
                Data data = validate(program, symbol, owner, block, display, evidence, monitor);
                var currentUniversal = data.getDataType().getUniversalID();
                if (!symbol.getName().equals(name) || symbol.getParentNamespace().getID() != namespace ||
                        relative(symbol, owner) != offset || data.getLength() != size ||
                        program.getDataTypeManager().getID(data.getDataType()) != typeId ||
                        !data.getDataType().getPathName().equals(typePath) ||
                        !java.util.Objects.equals(universal, currentUniversal == null ? null : currentUniversal.getValue())) {
                    throw invalid("saved static name, namespace, address or type identity changed");
                }
                if (!scopeFingerprint(owner, block, monitor).equals(scope)) throw invalid("saved static lexical evidence changed");
                monitor.checkCancelled();
                return new Result(Status.VALID, new Snapshot(symbol, owner, data, block, display, evidence));
            }
        }
        catch (IOException | IllegalArgumentException failure) {
            diagnostic.accept("Omitted explicit static binding for symbol " + symbolId + ": " + failure.getMessage());
            return new Result(Status.REJECTED, null);
        }
    }

    public static void remove(Program program, long symbolId, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        String key = key(symbolId);
        if (program.getOptionsNames().contains(OPTIONS_NAME)) program.getOptions(OPTIONS_NAME).removeOption(key);
    }

    private static Data validate(Program program, Symbol symbol, Function owner, String block,
            String display, String evidence, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        text(block, true, 1024);
        text(display, false, 1024);
        text(evidence, false, 8192);
        if (owner == null || owner.getProgram() != program || owner.isExternal() || owner.getSymbol() == null ||
                program.getFunctionManager().getFunctionAt(owner.getEntryPoint()) != owner || owner.getBody().isEmpty()) {
            throw invalid("static owner is not a current image function");
        }
        if (symbol == null || symbol.getProgram() != program || symbol.getID() <= 0 ||
                program.getSymbolTable().getSymbol(symbol.getID()) != symbol ||
                symbol.getSymbolType() != SymbolType.LABEL || !symbol.isPrimary() || symbol.isExternal() ||
                symbol.getSource() == SourceType.DEFAULT || !symbol.getAddress().isMemoryAddress()) {
            throw invalid("static object is not a current named primary memory label");
        }
        if (symbol.getParentNamespace() instanceof Function actualOwner && actualOwner != owner) {
            throw invalid("static binding contradicts actual function ownership");
        }
        Data data = program.getListing().getDataAt(symbol.getAddress());
        var memory = program.getMemory().getBlock(symbol.getAddress());
        if (data == null || !data.isDefined() || data.getLength() <= 0 || memory == null ||
                !memory.isLoaded() || !memory.contains(data.getMaxAddress())) {
            throw invalid("static object has no complete defined loaded storage");
        }
        relative(symbol, owner);
        monitor.checkCancelled();
        return data;
    }

    private static long relative(Symbol symbol, Function owner) {
        try {
            if (!symbol.getAddress().getAddressSpace().equals(owner.getEntryPoint().getAddressSpace())) {
                throw invalid("static object crosses the owner address space");
            }
            long offset = symbol.getAddress().subtract(owner.getEntryPoint());
            if (!owner.getEntryPoint().addNoWrap(offset).equals(symbol.getAddress())) throw invalid("unrepresentable static offset");
            return offset;
        }
        catch (ghidra.program.model.address.AddressOverflowException overflow) {
            throw invalid("static offset overflow");
        }
    }

    private static String scopeFingerprint(Function owner, String block, TaskMonitor monitor) throws CancelledException {
        if (block.isEmpty()) return "";
        var diagnostics = new java.util.ArrayList<String>();
        var scopes = GhidraLexicalScopes.read(owner, monitor, diagnostics::add)
            .orElseThrow(() -> invalid("static lexical owner has no valid saved scope: " + diagnostics));
        if (scopes.blocks().stream().noneMatch(candidate -> candidate.id().equals(block))) {
            throw invalid("static lexical block does not exist");
        }
        // The existing payload uses entry-relative ranges and survives rebasing.
        // Any explicit tree/local update requires reconfirming this association.
        String encoded = owner.getProgram().getUsrPropertyManager()
            .getStringPropertyMap(GhidraLexicalScopes.PROPERTY_NAME).getString(owner.getEntryPoint());
        monitor.checkCancelled();
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(encoded.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }

    private static String key(long symbolId) {
        if (symbolId <= 0) throw invalid("static symbol identity must be positive");
        return "static-" + symbolId;
    }

    private static void text(String value, boolean emptyAllowed, int maximum) {
        if (value == null || (!emptyAllowed && value.isBlank()) || value.length() > maximum || value.indexOf('\0') >= 0) {
            throw invalid("invalid static binding text");
        }
    }

    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}

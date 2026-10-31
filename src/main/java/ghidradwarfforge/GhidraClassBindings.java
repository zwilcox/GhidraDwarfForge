package ghidradwarfforge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.function.Consumer;

import ghidra.framework.options.OptionType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Explicit analyst class/type identity, separate from Ghidra's fuzzy THIS lookup. */
public final class GhidraClassBindings {
    // Dots delimit nested options; getOptionsNames lists only top-level groups.
    public static final String OPTIONS_NAME = "GhidraDwarfForge Class Bindings v1";
    private static final String PREFIX = "GDFCB1:";
    private static final int MAX_BYTES = 32768;
    private static final int MAX_EVIDENCE_CHARS = 8192;

    public enum Status { ABSENT, VALID, REJECTED }

    /** The current type object is used; names, category and layout are not frozen. */
    public record Snapshot(long classId, long typeId, Structure type, String evidence) {
        public Snapshot {
            if (classId <= 0 || typeId <= 0 || type == null) throw invalid("invalid class-binding snapshot");
            GhidraClassBindings.evidence(evidence);
        }
    }

    /** Rejected explicit evidence must not be mistaken for permission to infer a replacement. */
    public record Result(Status status, Snapshot binding) {
        public Result {
            if (status == null || (status == Status.VALID) != (binding != null)) {
                throw invalid("invalid class-binding result");
            }
        }
    }

    private GhidraClassBindings() {
    }

    /** Persist in the caller's program transaction; does not change target bytes. */
    public static void save(Program program, GhidraClass owner, Structure type,
            String evidence, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (owner == null || owner.getSymbol().getProgram() != program) {
            throw invalid("class belongs to another program");
        }
        requireClass(program, owner.getID());
        if (type == null || type.getDataTypeManager() != program.getDataTypeManager()) {
            throw invalid("class type belongs to another manager");
        }
        // getID alone is insufficient: DataTypeManagerDB accepts foreign DB types.
        long typeId = program.getDataTypeManager().getID(type);
        if (typeId <= 0 || program.getDataTypeManager().getDataType(typeId) != type ||
                type.getUniversalID() == null) throw invalid("class type is not a current saved structure");
        evidence(evidence);
        String encoded;
        try {
            var bytes = new ByteArrayOutputStream();
            try (var output = new DataOutputStream(bytes)) {
                output.writeInt(1);
                output.writeLong(owner.getID());
                output.writeLong(typeId);
                output.writeLong(type.getUniversalID().getValue());
                output.writeUTF(evidence);
            }
            if (bytes.size() > MAX_BYTES) throw invalid("class binding exceeds byte bound");
            encoded = PREFIX + Base64.getEncoder().encodeToString(bytes.toByteArray());
        }
        catch (IOException failure) {
            throw invalid("cannot encode class binding: " + failure.getMessage());
        }
        monitor.checkCancelled();
        String key = key(owner.getID());
        if (program.getOptionsNames().contains(OPTIONS_NAME)) {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.contains(key) && options.getType(key) != OptionType.STRING_TYPE) {
                throw invalid("class binding option has incompatible type");
            }
        }
        monitor.checkCancelled();
        program.getOptions(OPTIONS_NAME).setString(key, encoded);
    }

    /** Read-only: absence creates no options group; rejected records remain untouched. */
    public static Result read(Program program, long classId, TaskMonitor monitor,
            Consumer<String> diagnostic) throws CancelledException {
        monitor.checkCancelled();
        String key = key(classId);
        if (!program.getOptionsNames().contains(OPTIONS_NAME)) return new Result(Status.ABSENT, null);
        var options = program.getOptions(OPTIONS_NAME);
        if (!options.contains(key)) return new Result(Status.ABSENT, null);
        try {
            if (options.getType(key) != OptionType.STRING_TYPE) throw invalid("class binding option has incompatible type");
            String encoded = options.getString(key, null);
            if (encoded == null || !encoded.startsWith(PREFIX) ||
                    encoded.length() > PREFIX.length() + ((MAX_BYTES + 2) / 3) * 4) {
                throw invalid("unsupported or oversized class binding");
            }
            monitor.checkCancelled();
            byte[] bytes = Base64.getDecoder().decode(encoded.substring(PREFIX.length()));
            if (bytes.length > MAX_BYTES) throw invalid("oversized class binding");
            try (var input = new DataInputStream(new ByteArrayInputStream(bytes))) {
                if (input.readInt() != 1 || input.readLong() != classId) throw invalid("version or class identity changed");
                long typeId = input.readLong();
                long universalId = input.readLong();
                String evidence = input.readUTF();
                evidence(evidence);
                if (input.read() != -1) throw invalid("trailing class binding data");
                monitor.checkCancelled();
                requireClass(program, classId);
                var type = program.getDataTypeManager().getDataType(typeId);
                if (!(type instanceof Structure structure) || type.getDataTypeManager() != program.getDataTypeManager() ||
                        type.getUniversalID() == null || type.getUniversalID().getValue() != universalId) {
                    throw invalid("saved class type identity is stale");
                }
                monitor.checkCancelled();
                return new Result(Status.VALID, new Snapshot(classId, typeId, structure, evidence));
            }
        }
        catch (IOException | IllegalArgumentException failure) {
            diagnostic.accept("Omitted explicit class binding for symbol " + classId + ": " + failure.getMessage());
            return new Result(Status.REJECTED, null);
        }
    }

    /** Explicitly forget a binding; ordinary export never calls this operation. */
    public static void remove(Program program, long classId, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        String key = key(classId);
        if (program.getOptionsNames().contains(OPTIONS_NAME)) program.getOptions(OPTIONS_NAME).removeOption(key);
    }

    private static void requireClass(Program program, long classId) {
        var symbol = program.getSymbolTable().getSymbol(classId);
        if (symbol == null || symbol.getSymbolType() != SymbolType.CLASS ||
                !(symbol.getObject() instanceof GhidraClass)) throw invalid("class identity is no longer present");
    }

    private static String key(long classId) {
        if (classId <= 0) throw invalid("class identity must be positive");
        return "class-" + classId;
    }

    private static void evidence(String value) {
        if (value == null || value.isBlank() || value.length() > MAX_EVIDENCE_CHARS || value.indexOf('\0') >= 0) {
            throw invalid("class binding requires bounded provenance text");
        }
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }
}

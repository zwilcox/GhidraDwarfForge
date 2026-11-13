package ghidradwarfforge;

import java.io.*;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.function.Consumer;

import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Explicit association of an existing addressless method with its canonical class. */
public final class GhidraDeclarationBindings {
    public static final String OPTIONS_NAME = "GhidraDwarfForge Method Declarations v1";
    private static final String PREFIX = "GDFMD1:";
    private static final int MAX_BYTES = 32768;
    public enum Status { ABSENT, VALID, REJECTED }
    public record Binding(long methodId, long classId, String evidence) {
        public Binding {
            if (methodId <= 0 || classId <= 0 || evidence == null || evidence.isBlank() ||
                    evidence.length() > 8192 || evidence.indexOf('\0') >= 0) {
                throw invalid("invalid addressless method identity or provenance");
            }
        }
    }
    public record Result(Status status, Binding binding) {
        public Result {
            if (status == null || (status == Status.VALID) != (binding != null)) throw invalid("invalid declaration result");
        }
    }

    private GhidraDeclarationBindings() { }

    /** Caller owns the transaction. No function, namespace, type or memory is modified. */
    public static void save(Program program, Binding binding, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (binding == null) throw invalid("missing declaration binding");
        byte[] signature = GhidraInheritanceBindings.declarationFingerprint(program, binding, monitor);
        String encoded;
        try {
            var bytes = new ByteArrayOutputStream();
            try (var output = new DataOutputStream(bytes)) {
                output.writeInt(1);
                output.writeLong(program.getUniqueProgramID());
                output.writeUTF(program.getLanguageID().toString());
                output.writeUTF(program.getCompilerSpec().getCompilerSpecID().toString());
                output.writeLong(binding.methodId()); output.writeLong(binding.classId());
                output.writeUTF(binding.evidence()); output.write(signature);
            }
            if (bytes.size() > MAX_BYTES) throw invalid("declaration binding exceeds bound");
            encoded = PREFIX + Base64.getEncoder().encodeToString(bytes.toByteArray());
        }
        catch (IOException failure) { throw invalid("cannot encode declaration: " + failure.getMessage()); }
        monitor.checkCancelled();
        String key = key(binding.methodId());
        if (program.getOptionsNames().contains(OPTIONS_NAME)) {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.contains(key) && options.getType(key) != OptionType.STRING_TYPE) {
                throw invalid("declaration option has incompatible type");
            }
        }
        monitor.checkCancelled();
        program.getOptions(OPTIONS_NAME).setString(key, encoded);
    }

    /** Absence does not create options, and rejection never repairs or infers another owner. */
    public static Result read(Program program, long methodId, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        monitor.checkCancelled();
        String key = key(methodId);
        if (!program.getOptionsNames().contains(OPTIONS_NAME) || !program.getOptions(OPTIONS_NAME).contains(key)) {
            return new Result(Status.ABSENT, null);
        }
        try {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.getType(key) != OptionType.STRING_TYPE) throw invalid("declaration option has incompatible type");
            String encoded = options.getString(key, null);
            if (encoded == null || !encoded.startsWith(PREFIX) || encoded.length() > PREFIX.length() + (MAX_BYTES + 2) / 3 * 4) {
                throw invalid("unsupported or oversized declaration binding");
            }
            byte[] bytes = Base64.getDecoder().decode(encoded.substring(PREFIX.length()));
            if (bytes.length > MAX_BYTES) throw invalid("declaration binding exceeds bound");
            try (var input = new DataInputStream(new ByteArrayInputStream(bytes))) {
                if (input.readInt() != 1 || input.readLong() != program.getUniqueProgramID() ||
                        !input.readUTF().equals(program.getLanguageID().toString()) ||
                        !input.readUTF().equals(program.getCompilerSpec().getCompilerSpecID().toString()) ||
                        input.readLong() != methodId) throw invalid("declaration program, target or method identity changed");
                var binding = new Binding(methodId, input.readLong(), input.readUTF());
                byte[] expected = input.readNBytes(32);
                if (expected.length != 32 || input.read() != -1) throw invalid("truncated or trailing declaration binding");
                if (!MessageDigest.isEqual(expected, GhidraInheritanceBindings.declarationFingerprint(program, binding, monitor))) {
                    throw invalid("declaration namespace, signature or canonical layout changed");
                }
                return new Result(Status.VALID, binding);
            }
        }
        catch (IOException | IllegalArgumentException failure) {
            diagnostic.accept("Omitted explicit method declaration " + methodId + ": " + failure.getMessage());
            return new Result(Status.REJECTED, null);
        }
    }

    public static void remove(Program program, long methodId, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (program.getOptionsNames().contains(OPTIONS_NAME)) program.getOptions(OPTIONS_NAME).removeOption(key(methodId));
    }

    /** Rejected explicit evidence must suppress ownership inference, not the independent signature. */
    static GhidraClass owner(Program program, Function function, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        var result = read(program, function.getID(), monitor, diagnostic);
        if (result.status() == Status.REJECTED) return null;
        if (result.status() == Status.VALID) {
            return (GhidraClass) program.getSymbolTable().getSymbol(result.binding().classId()).getObject();
        }
        return function.getParentNamespace() instanceof GhidraClass owner ? owner : null;
    }

    private static String key(long id) {
        if (id <= 0) throw invalid("method identity must be positive");
        return "method-" + id;
    }

    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}

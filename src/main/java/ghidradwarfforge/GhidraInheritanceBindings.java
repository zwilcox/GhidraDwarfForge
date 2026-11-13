package ghidradwarfforge;

import java.io.*;
import java.nio.ByteOrder;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Consumer;

import ghidra.framework.options.OptionType;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.targets.CxxAbiProfile;
import ghidradwarfforge.types.InheritanceModel;
import ghidradwarfforge.types.InheritanceModel.*;

/** Explicit relationship snapshot. Reads never repair rejected evidence or change the program. */
public final class GhidraInheritanceBindings {
    public static final String OPTIONS_NAME = "GhidraDwarfForge Inheritance v1";
    public static final String KEY = "relationships";
    private static final String PREFIX = "GDFIB1:";
    private static final int MAX_BYTES = 1024 * 1024;
    private static final int MAX_RECORDS = 4096;
    public enum Status { ABSENT, VALID, REJECTED }
    public record Result(Status status, InheritanceModel model) {
        public Result {
            if (status == null || (status == Status.VALID) != (model != null)) throw invalid("invalid inheritance result");
        }
    }

    private GhidraInheritanceBindings() { }

    /** Requires the caller's transaction. Saves metadata only, after complete validation. */
    public static void save(Program program, InheritanceModel model, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        byte[] fingerprint = fingerprint(program, model, monitor);
        String encoded;
        try {
            var bytes = new BoundedBytes();
            try (var out = new DataOutputStream(bytes)) {
                out.writeInt(1);
                out.writeLong(program.getUniqueProgramID());
                out.writeUTF(program.getLanguageID().toString());
                out.writeUTF(program.getCompilerSpec().getCompilerSpecID().toString());
                out.writeUTF(model.abi().name());
                out.writeInt(model.bases().size());
                for (var base : model.bases()) {
                    monitor.checkCancelled();
                    out.writeLong(base.derivedClassId());
                    out.writeLong(base.baseClassId());
                    out.writeInt(base.order());
                    out.writeUTF(base.access().name());
                    out.writeBoolean(base.location() instanceof VirtualBase);
                    if (base.location() instanceof FixedBase fixed) {
                        out.writeLong(fixed.offset()); out.writeLong(fixed.occupiedBytes());
                    }
                    else if (base.location() instanceof VirtualBase virtual) {
                        out.writeLong(virtual.vptrOffset()); out.writeLong(virtual.slotOffset());
                    }
                    out.writeUTF(base.evidence());
                }
                out.writeInt(model.virtualMethods().size());
                for (var method : model.virtualMethods()) {
                    monitor.checkCancelled();
                    out.writeLong(method.methodId()); out.writeInt(method.slot());
                    out.writeUTF(method.access().name()); out.writeUTF(method.virtuality().name());
                    out.writeUTF(method.evidence());
                }
                out.write(fingerprint);
            }
            encoded = PREFIX + Base64.getEncoder().encodeToString(bytes.toByteArray());
        }
        catch (IOException failure) { throw invalid("cannot encode inheritance: " + failure.getMessage()); }
        monitor.checkCancelled();
        if (program.getOptionsNames().contains(OPTIONS_NAME)) {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.contains(KEY) && options.getType(KEY) != OptionType.STRING_TYPE) {
                throw invalid("inheritance option has incompatible type");
            }
        }
        monitor.checkCancelled();
        program.getOptions(OPTIONS_NAME).setString(KEY, encoded);
    }

    public static Result read(Program program, TaskMonitor monitor, Consumer<String> diagnostic) throws CancelledException {
        monitor.checkCancelled();
        if (!program.getOptionsNames().contains(OPTIONS_NAME) || !program.getOptions(OPTIONS_NAME).contains(KEY)) {
            return new Result(Status.ABSENT, null);
        }
        try {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.getType(KEY) != OptionType.STRING_TYPE) throw invalid("inheritance option has incompatible type");
            String text = options.getString(KEY, null);
            if (text == null || !text.startsWith(PREFIX) || text.length() > PREFIX.length() + (MAX_BYTES + 2) / 3 * 4) {
                throw invalid("unsupported or oversized inheritance record");
            }
            byte[] bytes = Base64.getDecoder().decode(text.substring(PREFIX.length()));
            if (bytes.length > MAX_BYTES) throw invalid("oversized inheritance record");
            try (var input = new DataInputStream(new ByteArrayInputStream(bytes))) {
                if (input.readInt() != 1 || input.readLong() != program.getUniqueProgramID() ||
                        !input.readUTF().equals(program.getLanguageID().toString()) ||
                        !input.readUTF().equals(program.getCompilerSpec().getCompilerSpecID().toString())) {
                    throw invalid("inheritance version, program or target changed");
                }
                var abi = CxxAbiProfile.valueOf(input.readUTF());
                var bases = new ArrayList<Base>();
                int count = count(input.readInt());
                for (int index = 0; index < count; index++) {
                    monitor.checkCancelled();
                    long derived = input.readLong(), parent = input.readLong();
                    int order = input.readInt();
                    var access = Access.valueOf(input.readUTF());
                    boolean virtual = input.readBoolean();
                    long first = input.readLong(), second = input.readLong();
                    bases.add(new Base(derived, parent, order, access,
                        virtual ? new VirtualBase(first, second) : new FixedBase(first, second), input.readUTF()));
                }
                var methods = new ArrayList<VirtualMethod>();
                count = count(input.readInt());
                for (int index = 0; index < count; index++) {
                    monitor.checkCancelled();
                    methods.add(new VirtualMethod(input.readLong(), input.readInt(), Access.valueOf(input.readUTF()),
                        Virtuality.valueOf(input.readUTF()), input.readUTF()));
                }
                var model = new InheritanceModel(abi, bases, methods);
                byte[] expected = input.readNBytes(32);
                if (expected.length != 32 || input.read() != -1) throw invalid("truncated or trailing inheritance record");
                if (!MessageDigest.isEqual(expected, fingerprint(program, model, monitor))) {
                    throw invalid("saved inheritance identity, layout or method snapshot is stale");
                }
                return new Result(Status.VALID, model);
            }
        }
        catch (IOException | IllegalArgumentException failure) {
            diagnostic.accept("Omitted explicit inheritance: " + failure.getMessage());
            return new Result(Status.REJECTED, null);
        }
    }

    public static void remove(Program program, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (program.getOptionsNames().contains(OPTIONS_NAME)) program.getOptions(OPTIONS_NAME).removeOption(KEY);
    }

    private static byte[] fingerprint(Program program, InheritanceModel model, TaskMonitor monitor) throws CancelledException {
        if (model == null || model.abi() == CxxAbiProfile.UNSPECIFIED) throw invalid("explicit inheritance ABI required");
        count(model.bases().size()); count(model.virtualMethods().size());
        model.abi().requireProgramTarget(program.getLanguage().getProcessor().toString(), program.getDefaultPointerSize(),
            program.getLanguage().isBigEndian() ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        var classes = new TreeSet<Long>();
        for (var base : model.bases()) { classes.add(base.derivedClassId()); classes.add(base.baseClassId()); }
        var methods = new TreeMap<Long, Function>();
        for (var method : model.virtualMethods()) {
            monitor.checkCancelled();
            var symbol = program.getSymbolTable().getSymbol(method.methodId());
            if (symbol == null || !(symbol.getObject() instanceof Function function) ||
                    !(function.getParentNamespace() instanceof GhidraClass owner)) throw invalid("saved virtual method is absent or has no class");
            methods.put(method.methodId(), function); classes.add(owner.getID());
        }
        count(classes.size());
        var layouts = new TreeMap<Long, GhidraClassBindings.Snapshot>();
        var typeIds = new HashSet<Long>();
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            var budget = new TraversalBudget();
            try (var out = new DataOutputStream(new DigestOutputStream(OutputStream.nullOutputStream(), digest))) {
                out.writeInt(classes.size());
                for (long id : classes) {
                    monitor.checkCancelled();
                    var result = GhidraClassBindings.read(program, id, monitor, ignored -> { });
                    if (result.status() != GhidraClassBindings.Status.VALID || !typeIds.add(result.binding().typeId())) {
                        throw invalid("missing, stale or conflicting explicit class binding");
                    }
                    var binding = result.binding(); layouts.put(id, binding);
                    out.writeLong(id); out.writeLong(binding.typeId());
                    out.writeLong(binding.type().getUniversalID().getValue());
                    layout(out, binding.type(), monitor, budget);
                }
                for (var base : model.bases()) {
                    monitor.checkCancelled();
                    long size = layouts.get(base.derivedClassId()).type().getLength();
                    long parentSize = layouts.get(base.baseClassId()).type().getLength();
                    if (base.location() instanceof FixedBase fixed) {
                        if (fixed.offset() >= size || fixed.occupiedBytes() > parentSize || fixed.occupiedBytes() > size - fixed.offset()) {
                            throw invalid("saved base exceeds class layout");
                        }
                    }
                    else if (base.location() instanceof VirtualBase virtual) {
                        model.abi().requireVirtualBase(virtual.vptrOffset(), virtual.slotOffset(), size);
                    }
                }
                out.writeInt(methods.size());
                var slots = new HashSet<List<Long>>();
                for (var method : model.virtualMethods()) {
                    monitor.checkCancelled();
                    var function = methods.get(method.methodId());
                    long owner = function.getParentNamespace().getID();
                    if (!slots.add(List.of(owner, (long) method.slot()))) throw invalid("conflicting virtual method slot");
                    out.writeLong(method.methodId()); out.writeLong(owner);
                    out.writeUTF(function.getCallingConventionName()); out.writeBoolean(function.hasVarArgs());
                    layout(out, function.getReturnType(), monitor, budget);
                    count(function.getParameterCount());
                    var parameters = function.getParameters(); out.writeInt(parameters.length);
                    int objects = 0;
                    for (var parameter : parameters) {
                        monitor.checkCancelled();
                        boolean object = parameter.getAutoParameterType() == AutoParameterType.THIS;
                        out.writeBoolean(object); layout(out, parameter.getDataType(), monitor, budget);
                        if (object) {
                            objects++;
                            if (!(parameter.getDataType() instanceof Pointer pointer) || pointer.getDataType() == null ||
                                    program.getDataTypeManager().getID(pointer.getDataType()) != layouts.get(owner).typeId()) {
                                throw invalid("virtual method object differs from explicit class binding");
                            }
                        }
                    }
                    if (objects != 1) throw invalid("virtual method lacks one saved object parameter");
                }
            }
            return digest.digest();
        }
        catch (IOException | NoSuchAlgorithmException failure) { throw invalid("cannot fingerprint inheritance: " + failure.getMessage()); }
    }

    /** Physical type graph only: renames/categories/comments and image addresses are not geometry. */
    private static void layout(DataOutputStream out, DataType root, TaskMonitor monitor, TraversalBudget budget)
            throws IOException, CancelledException {
        var queue = new ArrayList<DataType>(); queue.add(root);
        var visited = Collections.newSetFromMap(new IdentityHashMap<DataType, Boolean>());
        for (int index = 0; index < queue.size(); index++) {
            monitor.checkCancelled();
            if (++budget.visits > 65536) throw invalid("inheritance layout traversal exceeds bound");
            var type = queue.get(index);
            identity(out, type);
            if (!visited.add(type)) { out.writeBoolean(false); continue; }
            out.writeBoolean(true);
            if (visited.size() > MAX_RECORDS) throw invalid("inheritance layout graph exceeds bound");
            if (type instanceof Composite composite) {
                int count = composite.getNumDefinedComponents();
                if (count < 0 || count > 65536 - budget.components) throw invalid("inheritance layout components exceed bound");
                budget.components += count;
                var members = composite.getDefinedComponents();
                if (members.length != count) throw invalid("inheritance layout changed during snapshot");
                out.writeInt(members.length);
                for (var member : members) {
                    monitor.checkCancelled();
                    out.writeInt(member.getOffset()); out.writeInt(member.getLength());
                    identity(out, member.getDataType()); queue.add(member.getDataType());
                }
            }
            else if (type instanceof Array array) {
                out.writeInt(array.getNumElements()); out.writeInt(array.getElementLength()); queue.add(array.getDataType());
            }
            else if (type instanceof TypeDef alias) queue.add(alias.getBaseDataType());
            else if (type instanceof BitFieldDataType field) {
                out.writeInt(field.getBitOffset()); out.writeInt(field.getBitSize()); queue.add(field.getBaseDataType());
            }
            else if (type instanceof Pointer pointer) {
                out.writeBoolean(pointer.getDataType() != null);
                if (pointer.getDataType() != null) identity(out, pointer.getDataType());
            }
        }
    }

    private static void identity(DataOutputStream out, DataType type) throws IOException {
        out.writeUTF(type.getClass().getName()); out.writeInt(type.getLength());
        out.writeLong(type.getUniversalID() == null ? 0 : type.getUniversalID().getValue());
    }

    private static int count(int value) {
        if (value < 0 || value > MAX_RECORDS) throw invalid("inheritance record count exceeds bound");
        return value;
    }

    private static final class TraversalBudget {
        int visits;
        int components;
    }

    private static final class BoundedBytes extends ByteArrayOutputStream {
        @Override public synchronized void write(int value) {
            if (count >= MAX_BYTES) throw invalid("inheritance bytes exceed bound");
            super.write(value);
        }
        @Override public synchronized void write(byte[] bytes, int offset, int length) {
            if (length > MAX_BYTES - count) throw invalid("inheritance bytes exceed bound");
            super.write(bytes, offset, length);
        }
    }

    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}

package ghidradwarfforge;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Consumer;

import ghidra.app.util.demangler.DemangledAddressTable;
import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.Demangler;
import ghidra.framework.options.OptionType;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.targets.CxxAbiProfile;

/** Explicit complete-object vtable evidence. This snapshot is not ELF export admission. */
public final class GhidraVtableBindings {
    public static final String OPTIONS_NAME = "GhidraDwarfForge Vtables v1";
    private static final String PREFIX = "GDFVT1:";
    private static final int MAX_RECORD_BYTES = 1024 * 1024;
    private static final int MAX_TABLE_BYTES = 1024 * 1024;
    private static final int MAX_POINTS = 4096;
    public enum Status { ABSENT, VALID, REJECTED }

    /** Byte offset within the table group and within the complete object respectively. */
    public record AddressPoint(int tableOffset, long subobjectOffset, String evidence) {
        public AddressPoint {
            if (tableOffset < 0 || subobjectOffset < 0) throw invalid("negative vtable address-point offset");
            text(evidence);
        }
    }

    /** The caller supplies the semantic association; a mangled spelling alone never establishes it. */
    public record Request(long symbolId, long classId, String mangledName, String lookupName,
            int byteSize, List<AddressPoint> points, String evidence) {
        public Request {
            if (symbolId <= 0 || classId <= 0 || byteSize <= 0 || byteSize > MAX_TABLE_BYTES ||
                    points == null || points.isEmpty() || points.size() > MAX_POINTS) throw invalid("invalid vtable identity or extent");
            text(mangledName); text(lookupName); text(evidence);
            if (!mangledName.startsWith("_ZTV") || mangledName.length() <= 4 ||
                    mangledName.chars().anyMatch(Character::isWhitespace)) throw invalid("explicit complete-object Itanium vtable name required");
            long encodedBound = 512L + 3L * (mangledName.length() + lookupName.length() + evidence.length());
            for (var point : points) {
                if (point == null) throw invalid("missing vtable address point");
                encodedBound += 16L + 3L * point.evidence().length();
                if (encodedBound > MAX_RECORD_BYTES) throw invalid("vtable record exceeds bound");
            }
            points = List.copyOf(points);
        }
    }

    /** Original-file and loaded-memory fingerprints differ legitimately after PIE relocation. */
    public record Snapshot(Request request, CxxAbiProfile abi, long originalAddress, long fileOffset,
            String originalSha256, String loadedSha256, String contextSha256) { }

    public record Result(Status status, Snapshot snapshot) {
        public Result {
            if (status == null || (status == Status.VALID) != (snapshot != null)) throw invalid("invalid vtable result");
        }
    }

    private GhidraVtableBindings() { }

    /** Save metadata in the caller's transaction. Never changes target bytes or symbol names. */
    public static void save(Program program, Request request, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        if (program.getCurrentTransactionInfo() == null) throw invalid("vtable save requires a program transaction");
        var snapshot = capture(program, request, monitor);
        String encoded;
        try {
            var bytes = new ByteArrayOutputStream();
            try (var out = new DataOutputStream(bytes)) {
                out.writeInt(1); writeRequest(out, request);
                out.writeUTF(snapshot.abi().name()); out.writeLong(snapshot.originalAddress()); out.writeLong(snapshot.fileOffset());
                out.writeUTF(snapshot.originalSha256()); out.writeUTF(snapshot.loadedSha256()); out.writeUTF(snapshot.contextSha256());
            }
            if (bytes.size() > MAX_RECORD_BYTES) throw invalid("vtable record exceeds bound");
            encoded = PREFIX + Base64.getEncoder().encodeToString(bytes.toByteArray());
        }
        catch (IOException failure) { throw invalid("cannot encode vtable: " + failure.getMessage()); }
        monitor.checkCancelled();
        String key = key(request.symbolId());
        if (program.getOptionsNames().contains(OPTIONS_NAME)) {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.contains(key) && options.getType(key) != OptionType.STRING_TYPE) throw invalid("vtable option has incompatible type");
        }
        monitor.checkCancelled();
        program.getOptions(OPTIONS_NAME).setString(key, encoded);
    }

    /** Read-only: never refreshes stale fingerprints or infers a replacement for rejected evidence. */
    public static Result read(Program program, long symbolId, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        return read(program, symbolId, monitor, diagnostic, ignored -> { });
    }

    private static Result read(Program program, long symbolId, TaskMonitor monitor, Consumer<String> diagnostic,
            java.util.function.IntConsumer charge) throws CancelledException {
        monitor.checkCancelled();
        String key = key(symbolId);
        if (!program.getOptionsNames().contains(OPTIONS_NAME) || !program.getOptions(OPTIONS_NAME).contains(key)) {
            return new Result(Status.ABSENT, null);
        }
        try {
            var options = program.getOptions(OPTIONS_NAME);
            if (options.getType(key) != OptionType.STRING_TYPE) throw invalid("vtable option has incompatible type");
            String value = options.getString(key, null);
            if (value == null || !value.startsWith(PREFIX) || value.length() > PREFIX.length() + (MAX_RECORD_BYTES + 2) / 3 * 4) {
                throw invalid("unsupported or oversized vtable record");
            }
            byte[] bytes = Base64.getDecoder().decode(value.substring(PREFIX.length()));
            if (bytes.length > MAX_RECORD_BYTES) throw invalid("oversized vtable record");
            try (var in = new DataInputStream(new ByteArrayInputStream(bytes))) {
                if (in.readInt() != 1) throw invalid("unsupported vtable record version");
                var request = readRequest(in);
                if (request.symbolId() != symbolId) throw invalid("vtable record belongs to another symbol");
                var expected = new Snapshot(request, CxxAbiProfile.valueOf(in.readUTF()), in.readLong(), in.readLong(),
                    in.readUTF(), in.readUTF(), in.readUTF());
                if (in.read() != -1) throw invalid("trailing vtable record bytes");
                charge.accept(request.byteSize());
                var actual = capture(program, request, monitor);
                if (!expected.equals(actual)) throw invalid("vtable identity, layout, mapping, relocation or bytes changed");
                return new Result(Status.VALID, actual);
            }
        }
        catch (IOException | IllegalArgumentException failure) {
            diagnostic.accept("Omitted explicit vtable " + symbolId + ": " + failure.getMessage());
            return new Result(Status.REJECTED, null);
        }
    }

    /** Bounded inventory including orphaned records, so deleted symbols are diagnosed. */
    public static List<ghidradwarfforge.types.VtableEvidence> extract(Program program,
            ghidradwarfforge.types.ClassScopeModel classes, TaskMonitor monitor, Consumer<String> diagnostic)
            throws CancelledException {
        monitor.checkCancelled();
        if (!program.getOptionsNames().contains(OPTIONS_NAME)) return List.of();
        var keys = program.getOptions(OPTIONS_NAME).getOptionNames();
        if (keys.size() > 4096) {
            diagnostic.accept("Omitted explicit vtables: saved inventory exceeds bound");
            return List.of();
        }
        var result = new ArrayList<ghidradwarfforge.types.VtableEvidence>();
        long[] inspectedBytes = {0};
        long encodedBytes = 0;
        for (String key : keys.stream().sorted().toList()) {
            monitor.checkCancelled();
            if (!key.startsWith("symbol-")) {
                diagnostic.accept("Omitted unknown vtable record key: " + key);
                continue;
            }
            long id;
            try { id = Long.parseLong(key.substring(7)); if (id <= 0 || !key(id).equals(key)) throw invalid("invalid key"); }
            catch (IllegalArgumentException invalid) { diagnostic.accept("Omitted invalid vtable record key: " + key); continue; }
            var options = program.getOptions(OPTIONS_NAME);
            if (options.getType(key) == OptionType.STRING_TYPE) {
                encodedBytes += Objects.toString(options.getString(key, ""), "").length();
                if (encodedBytes > 16L * 1024 * 1024) {
                    diagnostic.accept("Omitted explicit vtables: aggregate encoded record budget exceeded");
                    return List.of();
                }
            }
            var value = read(program, id, monitor, diagnostic, size -> {
                inspectedBytes[0] += size;
                if (inspectedBytes[0] > 64L * 1024 * 1024) throw invalid("aggregate byte witness budget exceeded");
            });
            if (inspectedBytes[0] > 64L * 1024 * 1024) return List.of();
            if (value.status() != Status.VALID) continue;
            var snapshot = value.snapshot(); var request = snapshot.request();
            if (snapshot.abi() != classes.inheritance().abi() || classes.bindings().stream().noneMatch(binding ->
                    binding.classId() == request.classId() && binding.source() ==
                        ghidradwarfforge.types.ClassScopeModel.BindingSource.EXPLICIT_SAVED)) {
                diagnostic.accept("Omitted explicit vtable " + id + ": canonical class/inheritance is unavailable in this export");
                continue;
            }
            result.add(new ghidradwarfforge.types.VtableEvidence(id, request.classId(), snapshot.abi(), request.mangledName(),
                request.lookupName(), snapshot.originalAddress(), request.byteSize(), snapshot.fileOffset(),
                snapshot.originalSha256(), request.evidence()));
        }
        return List.copyOf(result);
    }

    public static void remove(Program program, long symbolId, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        String key = key(symbolId);
        if (program.getOptionsNames().contains(OPTIONS_NAME)) program.getOptions(OPTIONS_NAME).removeOption(key);
    }

    private static Snapshot capture(Program program, Request request, TaskMonitor monitor) throws CancelledException {
        if (request == null) throw invalid("missing explicit vtable request");
        var relationships = GhidraInheritanceBindings.read(program, monitor, ignored -> { });
        if (relationships.status() != GhidraInheritanceBindings.Status.VALID) throw invalid("valid saved inheritance required");
        var model = relationships.model();
        boolean included = model.bases().stream().anyMatch(base -> base.derivedClassId() == request.classId() || base.baseClassId() == request.classId());
        for (var method : model.virtualMethods()) {
            monitor.checkCancelled();
            if (program.getSymbolTable().getSymbol(method.methodId()).getParentNamespace().getID() == request.classId()) included = true;
        }
        var binding = GhidraClassBindings.read(program, request.classId(), monitor, ignored -> { });
        if (!included || binding.status() != GhidraClassBindings.Status.VALID) throw invalid("vtable class is outside saved inheritance snapshot");
        var symbol = program.getSymbolTable().getSymbol(request.symbolId());
        if (symbol == null || symbol.getSymbolType() != SymbolType.LABEL || symbol.isDynamic() || symbol.isExternal()) {
            throw invalid("vtable must reference a saved memory label");
        }
        var address = symbol.getAddress();
        if (!address.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace())) throw invalid("vtable is not in the default address space");
        requireLookup(program, request, monitor);
        int pointer = model.abi().pointerBytes();
        if (request.byteSize() % pointer != 0 || address.getOffset() % pointer != 0) throw invalid("unaligned vtable extent");
        int previous = -pointer;
        var subobjects = new HashSet<Long>();
        for (var point : request.points()) {
            monitor.checkCancelled();
            if (point.tableOffset() < 2 * pointer || point.tableOffset() > request.byteSize() - pointer ||
                    point.tableOffset() % pointer != 0 || point.tableOffset() - previous < 3 * pointer ||
                    point.subobjectOffset() % pointer != 0 || point.subobjectOffset() > binding.binding().type().getLength() - pointer ||
                    !subobjects.add(point.subobjectOffset())) throw invalid("invalid or overlapping complete-object address points");
            previous = point.tableOffset();
        }
        if (request.points().getFirst().subobjectOffset() != 0) throw invalid("missing primary complete-object address point");
        try {
            var end = address.addNoWrap(request.byteSize() - 1);
            var memory = program.getMemory();
            byte[] loaded = new byte[request.byteSize()], original = new byte[request.byteSize()];
            if (memory.getBytes(address, loaded) != loaded.length) throw invalid("incomplete loaded vtable bytes");
            FileBytes first = null;
            long firstOffset = -1;
            for (int index = 0; index < original.length; index++) {
                monitor.checkCancelled();
                var at = address.addNoWrap(index);
                var info = memory.getAddressSourceInfo(at);
                if (info == null) throw invalid("vtable has no original file mapping");
                var source = info.getMemoryBlockSourceInfo();
                var file = source.getFileBytes().orElseThrow(() -> invalid("vtable has no original FileBytes"));
                long offset = source.getFileBytesOffset(at);
                if (offset < 0 || source.getMappedRange().isPresent()) throw invalid("vtable requires direct file-backed storage");
                long absolute = Math.addExact(file.getFileOffset(), offset);
                if (index == 0) { first = file; firstOffset = absolute; }
                if (file != first || absolute != Math.addExact(firstOffset, index)) throw invalid("vtable file mapping is not contiguous");
                original[index] = file.getOriginalByte(offset);
            }
            if (firstOffset < 0) throw invalid("negative vtable file offset");
            Math.addExact(firstOffset, original.length);
            var words = ByteBuffer.wrap(loaded).order(ByteOrder.LITTLE_ENDIAN);
            var originalWords = ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
            for (var point : request.points()) {
                int at = point.tableOffset() - 2 * pointer;
                if (words.getLong(at) != -point.subobjectOffset() || originalWords.getLong(at) != -point.subobjectOffset()) {
                    throw invalid("complete-object offset-to-top disagrees with saved subobject geometry");
                }
            }
            long originalAddress = Math.addExact(address.subtract(program.getImageBase()), GhidraImageBase.originalImageBase(program));
            var digest = sha256();
            try (var out = new DataOutputStream(new java.security.DigestOutputStream(OutputStream.nullOutputStream(), digest))) {
                out.writeLong(program.getUniqueProgramID()); out.writeUTF(program.getLanguageID().toString());
                out.writeUTF(program.getCompilerSpec().getCompilerSpecID().toString());
                writeRequest(out, request);
                // This record already fingerprints the physical class graph and virtual method signatures.
                byte[] inheritance = program.getOptions(GhidraInheritanceBindings.OPTIONS_NAME)
                    .getString(GhidraInheritanceBindings.KEY, "").getBytes(java.nio.charset.StandardCharsets.UTF_8);
                out.writeInt(inheritance.length); out.write(inheritance);
                out.writeLong(first.getFileOffset()); out.writeLong(first.getSize());
                var relocations = program.getRelocationTable().getRelocations(new AddressSet(address, end));
                int count = 0;
                long relocationBudget = 0;
                while (relocations.hasNext()) {
                    monitor.checkCancelled();
                    if (++count > MAX_TABLE_BYTES) throw invalid("excessive vtable relocation records");
                    var relocation = relocations.next();
                    out.writeLong(relocation.getAddress().subtract(address)); out.writeInt(relocation.getType());
                    out.writeUTF(relocation.getStatus().name());
                    var values = relocation.getValues();
                    if (values != null && values.length > 4096) throw invalid("excessive vtable relocation values");
                    out.writeInt(values == null ? -1 : values.length);
                    if (values != null) for (long value : values) out.writeLong(value);
                    var bytes = relocation.getBytes();
                    if (bytes != null && bytes.length > MAX_TABLE_BYTES) throw invalid("excessive vtable relocation bytes");
                    out.writeInt(bytes == null ? -1 : bytes.length);
                    if (bytes != null) out.write(bytes);
                    String name = Objects.toString(relocation.getSymbolName(), "");
                    relocationBudget += 32L + (values == null ? 0 : 8L * values.length) +
                        (bytes == null ? 0 : bytes.length) + 3L * name.length();
                    if (relocationBudget > 4L * MAX_TABLE_BYTES) throw invalid("vtable relocation data exceeds bound");
                    out.writeUTF(name);
                }
                out.writeInt(count);
            }
            return new Snapshot(request, model.abi(), originalAddress, firstOffset, hexHash(original), hexHash(loaded),
                HexFormat.of().formatHex(digest.digest()));
        }
        catch (IOException | MemoryAccessException | ghidra.program.model.address.AddressOverflowException |
                ArithmeticException | IllegalStateException failure) {
            throw invalid("cannot capture vtable witness: " + failure.getMessage());
        }
    }

    /** Checks spelling only. The explicit saved class ID, not this demangler, establishes ownership. */
    private static void requireLookup(Program program, Request request, TaskMonitor monitor) throws CancelledException {
        for (var demangler : ClassSearcher.getInstances(Demangler.class).stream()
                .filter(d -> d.canDemangle(program)).sorted(Comparator.comparing(d -> d.getClass().getName())).toList()) {
            monitor.checkCancelled();
            try {
                var value = demangler.demangle(demangler.createMangledContext(request.mangledName(),
                    demangler.createDefaultOptions(), program, null));
                if (value instanceof DemangledAddressTable && ("vtable for " + request.lookupName()).equals(value.getOriginalDemangled())) return;
            }
            catch (DemangledException failure) {
                if (!failure.isInvalidMangledName()) throw invalid("cannot validate vtable lookup spelling: " + failure.getMessage());
            }
        }
        throw invalid("vtable mangled identity does not match explicit lookup name");
    }

    private static void writeRequest(DataOutputStream out, Request request) throws IOException {
        out.writeLong(request.symbolId()); out.writeLong(request.classId()); out.writeUTF(request.mangledName());
        out.writeUTF(request.lookupName()); out.writeInt(request.byteSize()); out.writeUTF(request.evidence());
        out.writeInt(request.points().size());
        for (var point : request.points()) {
            out.writeInt(point.tableOffset()); out.writeLong(point.subobjectOffset()); out.writeUTF(point.evidence());
        }
    }

    private static Request readRequest(DataInputStream in) throws IOException {
        long symbol = in.readLong(), owner = in.readLong();
        String name = in.readUTF(), lookup = in.readUTF();
        int size = in.readInt(); String evidence = in.readUTF();
        int count = in.readInt();
        if (count <= 0 || count > MAX_POINTS) throw invalid("invalid vtable address-point count");
        var points = new ArrayList<AddressPoint>();
        for (int index = 0; index < count; index++) points.add(new AddressPoint(in.readInt(), in.readLong(), in.readUTF()));
        return new Request(symbol, owner, name, lookup, size, points, evidence);
    }

    private static String key(long id) {
        if (id <= 0) throw invalid("invalid vtable symbol ID");
        return "symbol-" + id;
    }
    private static void text(String text) {
        if (text == null || text.isBlank() || text.length() > 8192 || text.indexOf('\0') >= 0) throw invalid("missing or oversized vtable text");
    }
    private static MessageDigest sha256() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (NoSuchAlgorithmException impossible) { throw new AssertionError(impossible); }
    }
    private static String hexHash(byte[] bytes) { return HexFormat.of().formatHex(sha256().digest(bytes)); }
    private static IllegalArgumentException invalid(String message) { return new IllegalArgumentException(message); }
}

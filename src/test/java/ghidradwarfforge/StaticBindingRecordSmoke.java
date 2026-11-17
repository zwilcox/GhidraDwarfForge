package ghidradwarfforge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraStaticBindings.Status;

/** Independent v1 record edits must not weaken the saved binding's exact identity. */
final class StaticBindingRecordSmoke {
    private static int checks;

    static void check(Program program, Symbol symbol, Function owner, String original) throws Exception {
        checks = 0;
        var options = program.getOptions(GhidraStaticBindings.OPTIONS_NAME);
        String key = "static-" + symbol.getID();
        var record = decode(original);
        require(encode(record, "unchanged").equals(original), "reference codec must reproduce saved bytes");
        for (String field : List.of("owner-kind", "namespace", "offset", "type-id", "type-path", "size", "universal", "scope")) {
            String corrupt = encode(record, field);
            options.setString(key, corrupt);
            long modification = program.getModificationNumber();
            var diagnostics = new ArrayList<String>();
            var result = GhidraStaticBindings.read(program, symbol.getID(), TaskMonitor.DUMMY, diagnostics::add);
            require(result.status() == Status.REJECTED && result.binding() == null && diagnostics.size() == 1,
                "stale field must be rejected: " + field + " " + diagnostics);
            require(corrupt.equals(options.getString(key, null)) && program.getModificationNumber() == modification,
                "read must not repair stale field: " + field);
        }
        // 65,537 bytes fits the encoded-length ceiling because base64 rounds
        // in groups of three. The decoded-length bound remains necessary.
        String oversized = "GDFSB1:" + Base64.getEncoder().encodeToString(new byte[65537]);
        options.setString(key, oversized);
        var diagnostics = new ArrayList<String>();
        require(GhidraStaticBindings.read(program, symbol.getID(), TaskMonitor.DUMMY, diagnostics::add).status() == Status.REJECTED &&
            diagnostics.size() == 1 && diagnostics.getFirst().contains("oversized static binding"), "decoded size bound");
        options.setString(key, original);
        var valid = GhidraStaticBindings.read(program, symbol.getID(), TaskMonitor.DUMMY, ignored -> { });
        require(valid.status() == Status.VALID, "restoring record restores exact association");
        for (Status status : Status.values()) {
            for (boolean present : new boolean[] {false, true}) {
                if ((status == Status.VALID) == present) {
                    var result = new GhidraStaticBindings.Result(status, present ? valid.binding() : null);
                    require(result.status() == status, "valid status/binding pair");
                }
                else reject(() -> new GhidraStaticBindings.Result(status, present ? valid.binding() : null));
            }
        }
        reject(() -> new GhidraStaticBindings.Result(null, null));
        for (long id : new long[] {0, -1, Long.MIN_VALUE}) {
            reject(() -> GhidraStaticBindings.read(program, id, TaskMonitor.DUMMY, ignored -> { }));
            reject(() -> GhidraStaticBindings.remove(program, id, TaskMonitor.DUMMY));
        }
        reject(() -> GhidraStaticBindings.save(program, null, owner, "", "display", "evidence", TaskMonitor.DUMMY));
        reject(() -> GhidraStaticBindings.save(program, symbol, null, "", "display", "evidence", TaskMonitor.DUMMY));
        for (int field = 0; field < 3; field++) {
            int limit = field == 2 ? 8192 : 1024;
            for (String invalid : new String[] {null, "bad\0text", "a".repeat(limit + 1)}) {
                String block = field == 0 ? invalid : "";
                String display = field == 1 ? invalid : "display";
                String evidence = field == 2 ? invalid : "evidence";
                reject(() -> GhidraStaticBindings.save(program, symbol, owner, block, display, evidence, TaskMonitor.DUMMY));
                require(original.equals(options.getString(key, null)), "invalid text preserves existing binding");
            }
        }
        String display = "\u03bb".repeat(1024), evidence = "\u754c".repeat(8192);
        GhidraStaticBindings.save(program, symbol, owner, "", display, evidence, TaskMonitor.DUMMY);
        var maximum = GhidraStaticBindings.read(program, symbol.getID(), TaskMonitor.DUMMY, ignored -> { });
        require(maximum.status() == Status.VALID && maximum.binding().displayName().equals(display) &&
            maximum.binding().evidence().equals(evidence), "exact text limits count characters and retain Unicode");
        options.setString(key, original);
        universalIdentity(program, owner);
        System.out.println("static-binding-record=PASS checks=" + checks);
    }

    private static void universalIdentity(Program program, Function owner) throws Exception {
        var type = new StructureDataType("RecordedStaticType", 0, program.getDataTypeManager());
        type.add(IntegerDataType.dataType, "member", null);
        var address = owner.getEntryPoint().add(300);
        var data = program.getListing().createData(address, type);
        var symbol = program.getSymbolTable().createLabel(address, "recorded_static", SourceType.USER_DEFINED);
        symbol.setPrimary();
        GhidraStaticBindings.save(program, symbol, owner, "", "recorded", "explicit structure", TaskMonitor.DUMMY);
        var options = program.getOptions(GhidraStaticBindings.OPTIONS_NAME);
        String key = "static-" + symbol.getID(), original = options.getString(key, null);
        var record = decode(original);
        require(data.getDataType().getUniversalID() != null && record.universal() != null &&
            record.universal().longValue() == data.getDataType().getUniversalID().getValue(), "record exact universal type identity");
        for (String field : List.of("universal", "missing-universal")) {
            String changed = encode(record, field);
            options.setString(key, changed);
            var diagnostics = new ArrayList<String>();
            long modification = program.getModificationNumber();
            require(GhidraStaticBindings.read(program, symbol.getID(), TaskMonitor.DUMMY, diagnostics::add).status() == Status.REJECTED &&
                diagnostics.size() == 1, "reject changed/missing universal identity");
            require(options.getString(key, null).equals(changed) && program.getModificationNumber() == modification,
                "universal identity refusal must not repair record");
        }
        options.setString(key, original);
        require(GhidraStaticBindings.read(program, symbol.getID(), TaskMonitor.DUMMY, ignored -> { }).status() == Status.VALID,
            "restoring original universal ID restores association");
    }

    private record Record(int version, long symbol, long owner, String name, long namespace,
            long offset, long typeId, String typePath, int size, Long universal,
            String block, String scope, String display, String evidence) { }

    private static Record decode(String encoded) throws Exception {
        try (var input = new DataInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(encoded.substring(7))))) {
            var record = new Record(input.readInt(), input.readLong(), input.readLong(), input.readUTF(), input.readLong(),
                input.readLong(), input.readLong(), input.readUTF(), input.readInt(), input.readBoolean() ? input.readLong() : null,
                input.readUTF(), input.readUTF(), input.readUTF(), input.readUTF());
            require(input.read() == -1, "reference record consumed exactly");
            return record;
        }
    }

    private static String encode(Record record, String field) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var output = new DataOutputStream(bytes)) {
            output.writeInt(record.version());
            output.writeLong(record.symbol());
            output.writeLong(field.equals("owner-kind") ? record.symbol() : record.owner());
            output.writeUTF(record.name());
            output.writeLong(record.namespace() + (field.equals("namespace") ? 1 : 0));
            output.writeLong(record.offset() + (field.equals("offset") ? 1 : 0));
            output.writeLong(record.typeId() + (field.equals("type-id") ? 1 : 0));
            output.writeUTF(record.typePath() + (field.equals("type-path") ? "stale" : ""));
            output.writeInt(record.size() + (field.equals("size") ? 1 : 0));
            Long universal = record.universal();
            if (field.equals("universal")) universal = universal == null ? 17L : universal + 1;
            if (field.equals("missing-universal")) universal = null;
            output.writeBoolean(universal != null);
            if (universal != null) output.writeLong(universal);
            output.writeUTF(record.block());
            output.writeUTF(record.scope() + (field.equals("scope") ? "stale" : ""));
            output.writeUTF(record.display());
            output.writeUTF(record.evidence());
        }
        return "GDFSB1:" + Base64.getEncoder().encodeToString(bytes.toByteArray());
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void reject(Action action) throws Exception {
        try { action.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("invalid static-binding input accepted");
    }
    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

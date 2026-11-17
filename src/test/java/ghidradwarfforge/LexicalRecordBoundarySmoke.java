package ghidradwarfforge;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.GhidraLexicalScopes.Block;
import ghidradwarfforge.GhidraLexicalScopes.Local;

/** Independent byte-level changes to persisted local identity and scope extents. */
final class LexicalRecordBoundarySmoke {
    private static int checks;

    static void check(Function function, String original, List<Block> blocks, List<Local> locals) throws Exception {
        checks = 0;
        var properties = function.getProgram().getUsrPropertyManager().getStringPropertyMap(GhidraLexicalScopes.PROPERTY_NAME);
        byte[] bytes = Base64.getDecoder().decode(original.substring(7));
        Map<String, Integer> offsets = offsets(bytes);
        var cases = new ArrayList<byte[]>();
        for (String name : List.of("symbol", "type-id")) {
            byte[] changed = bytes.clone();
            ByteBuffer.wrap(changed).putLong(offsets.get(name), Long.MAX_VALUE);
            cases.add(changed);
        }
        for (String name : List.of("size", "first-use")) {
            byte[] changed = bytes.clone();
            ByteBuffer.wrap(changed).putInt(offsets.get(name), Integer.MAX_VALUE);
            cases.add(changed);
        }
        for (String name : List.of("type-path", "storage", "block")) cases.add(text(bytes, offsets.get(name), "different"));
        byte[] reversed = bytes.clone();
        ByteBuffer.wrap(reversed).putLong(offsets.get("low"), 1).putLong(offsets.get("high"), 0);
        cases.add(reversed);
        byte[] overflow = bytes.clone();
        ByteBuffer.wrap(overflow).putLong(offsets.get("low"), Long.MAX_VALUE).putLong(offsets.get("high"), Long.MAX_VALUE);
        cases.add(overflow);
        for (byte[] changed : cases) {
            String encoded = "GDFLS1:" + Base64.getEncoder().encodeToString(changed);
            properties.add(function.getEntryPoint(), encoded);
            long modification = function.getProgram().getModificationNumber();
            var diagnostics = new ArrayList<String>();
            require(GhidraLexicalScopes.read(function, TaskMonitor.DUMMY, diagnostics::add).isEmpty() && diagnostics.size() == 1,
                "invalid identity/range must be omitted: " + diagnostics);
            require(properties.getString(function.getEntryPoint()).equals(encoded) &&
                function.getProgram().getModificationNumber() == modification, "read must not repair stale lexical record");
        }
        properties.add(function.getEntryPoint(), original);
        require(GhidraLexicalScopes.read(function, TaskMonitor.DUMMY, ignored -> { }).isPresent(), "restore original scope record");
        reject(() -> GhidraLexicalScopes.save(function, "record", null, locals, TaskMonitor.DUMMY));
        reject(() -> GhidraLexicalScopes.save(function, "record", blocks, null, TaskMonitor.DUMMY));
        reject(() -> GhidraLexicalScopes.save(function, "record", java.util.Collections.nCopies(4097, blocks.getFirst()), locals, TaskMonitor.DUMMY));
        reject(() -> GhidraLexicalScopes.save(function, "record", blocks, java.util.Collections.nCopies(16385, locals.getFirst()), TaskMonitor.DUMMY));
        reject(() -> new Block("missing", "", null));
        reject(() -> new Block("empty", "", new AddressSet()));
        reject(() -> new Local(null, "", "missing"));
        for (String invalid : new String[] {null, "invalid\0text", "a".repeat(1025)}) {
            reject(() -> new Block(invalid, "", function.getBody()));
            reject(() -> new Block("block", invalid, function.getBody()));
            reject(() -> new Local(locals.getFirst().variable(), invalid, "display"));
            reject(() -> new Local(locals.getFirst().variable(), "", invalid));
            reject(() -> GhidraLexicalScopes.save(function, invalid, blocks, locals, TaskMonitor.DUMMY));
        }
        require(properties.getString(function.getEntryPoint()).equals(original), "invalid save preserves prior record");
        String limit = "\u03bb".repeat(1024);
        var maximalBlock = new Block(limit, "", function.getBody());
        GhidraLexicalScopes.save(function, limit, List.of(maximalBlock),
            List.of(new Local(locals.getFirst().variable(), limit, limit)), TaskMonitor.DUMMY);
        var snapshot = GhidraLexicalScopes.read(function, TaskMonitor.DUMMY, ignored -> { }).orElseThrow();
        require(snapshot.evidence().equals(limit) && snapshot.blocks().getFirst().id().equals(limit) &&
            snapshot.locals().getFirst().displayName().equals(limit), "exact Unicode character limit retained");
        properties.add(function.getEntryPoint(), original);
        System.out.println("lexical-record-boundaries=PASS checks=" + checks);
    }

    private static Map<String, Integer> offsets(byte[] bytes) throws Exception {
        var result = new HashMap<String, Integer>();
        try (var input = new DataInputStream(new ByteArrayInputStream(bytes))) {
            require(input.readInt() == 1, "v1 reference decoder");
            input.readLong(); input.readUTF();
            int blocks = input.readInt();
            for (int index = 0; index < blocks; index++) {
                input.readUTF(); input.readUTF();
                int ranges = input.readInt();
                for (int range = 0; range < ranges; range++) {
                    result.putIfAbsent("low", bytes.length - input.available()); input.readLong();
                    result.putIfAbsent("high", bytes.length - input.available()); input.readLong();
                }
            }
            require(input.readInt() > 0, "at least one saved local");
            result.put("symbol", bytes.length - input.available()); input.readLong(); input.readUTF();
            result.put("type-path", bytes.length - input.available()); input.readUTF();
            result.put("type-id", bytes.length - input.available()); input.readLong();
            result.put("size", bytes.length - input.available()); input.readInt();
            result.put("first-use", bytes.length - input.available()); input.readInt();
            result.put("storage", bytes.length - input.available()); input.readUTF();
            result.put("block", bytes.length - input.available()); input.readUTF();
        }
        return result;
    }

    private static byte[] text(byte[] bytes, int offset, String value) throws Exception {
        int size = Short.toUnsignedInt(ByteBuffer.wrap(bytes).getShort(offset));
        var result = new ByteArrayOutputStream();
        result.write(bytes, 0, offset);
        var output = new DataOutputStream(result);
        output.writeUTF(value);
        result.write(bytes, offset + 2 + size, bytes.length - offset - 2 - size);
        return result.toByteArray();
    }

    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static void reject(Action action) throws Exception {
        try { action.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("invalid lexical input accepted");
    }
    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

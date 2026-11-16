package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonNull;
import com.google.gson.JsonArray;
import com.google.gson.JsonPrimitive;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Large source inventories must not weaken the small command/state record budgets. */
public final class BuildIdRecordsSmoke {
    public static void main(String[] args) throws Exception {
        documentBoundaries();
        fieldBoundaries();
        snapshotBoundaries();
        retainedPaths();
        Path path = Files.createTempFile("forge-build-id-record-", ".json");
        try {
            var files = new JsonObject();
            for (int index = 0; index < 5000; index++) {
                var file = new JsonObject();
                file.addProperty("sha256", "a".repeat(64));
                file.addProperty("bytes", "123456");
                file.addProperty("crc32", "123456");
                file.addProperty("identity", "test-inode-" + index);
                file.addProperty("metadataSha256", "b".repeat(64));
                files.add("source/forge-src-" + index + "-" + "c".repeat(64) + ".c", file);
            }
            var inventory = new JsonObject();
            inventory.add("files", files);
            Files.writeString(path, inventory.toString());
            if (Files.size(path) <= 1024 * 1024) throw new AssertionError("fixture does not cross old byte budget");
            var visits = new AtomicInteger();
            var actual = BuildIdRecords.readGeneration(path, () -> { visits.incrementAndGet(); return false; });
            if (!inventory.equals(actual)) throw new AssertionError("large inventory was truncated or changed");
            reject(() -> BuildIdRecords.read(path, () -> false));
            reject(() -> BuildIdRecords.read(Files.readAllBytes(path), () -> false));
            for (int stop : new int[] {1, visits.get() / 2, visits.get()}) {
                var count = new AtomicInteger();
                try {
                    BuildIdRecords.readGeneration(path, () -> count.incrementAndGet() == stop);
                    throw new AssertionError("missed generation cancellation " + stop);
                }
                catch (CancellationException expected) { }
            }
            for (String invalid : new String[] {
                    "{\"files\":{},\"files\":{}}", "{\"files\":true}",
                    "{\"identity\":\"" + "x".repeat(16385) + "\"}"}) {
                Files.writeString(path, invalid);
                reject(() -> BuildIdRecords.readGeneration(path, () -> false));
            }
            System.out.println("build-id-records-smoke=PASS files=5000 commandBudgetPreserved=true sampledCancellation=3");
        }
        finally { Files.delete(path); }
    }

    private static void documentBoundaries() throws Exception {
        String text = "{\"name\":\"analyst λ\",\"optional\":null,\"nested\":{\"value\":\"ok\"}}";
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] original = bytes.clone();
        var parsed = BuildIdRecords.read(bytes, () -> false);
        equal("analyst λ", BuildIdRecords.text(parsed, "name"));
        equal("ok", BuildIdRecords.text(BuildIdRecords.object(parsed, "nested"), "value"));
        if (!parsed.get("optional").isJsonNull() || !java.util.Arrays.equals(bytes, original)) {
            throw new AssertionError("record decoding changed optional data or input bytes");
        }
        for (String invalid : new String[] {"null", "\"text\"", "[]", "{} {}", "{} trailing",
                "{\"a\":0}", "{\"a\":[]}", "{\"a\":{\"x\":null,\"x\":\"duplicate\"}}"}) {
            reject(() -> BuildIdRecords.read(invalid.getBytes(StandardCharsets.UTF_8), () -> false));
        }
        // Root plus 19,999 child values is exactly the small record's budget.
        var limit = new StringBuilder("{");
        for (int index = 0; index < 19999; index++) {
            if (index != 0) limit.append(',');
            limit.append('"').append(index).append("\":null");
        }
        byte[] atLimit = (limit + "}").getBytes(StandardCharsets.UTF_8);
        equal(19999, BuildIdRecords.read(atLimit, () -> false).size());
        byte[] overLimit = (limit + ",\"excess\":null}").getBytes(StandardCharsets.UTF_8);
        reject(() -> BuildIdRecords.read(overLimit, () -> false));
        try {
            BuildIdRecords.read(bytes, () -> true);
            throw new AssertionError("record cancellation swallowed");
        }
        catch (CancellationException expected) { }
    }

    private static void fieldBoundaries() throws Exception {
        var record = new JsonObject();
        reject(() -> BuildIdRecords.object(record, "field"));
        reject(() -> BuildIdRecords.text(record, "field"));
        for (var value : new com.google.gson.JsonElement[] {JsonNull.INSTANCE, new JsonArray(),
                new JsonPrimitive(12), new JsonPrimitive(true)}) {
            record.add("field", value);
            reject(() -> BuildIdRecords.object(record, "field"));
            reject(() -> BuildIdRecords.text(record, "field"));
        }
        record.add("field", new JsonObject());
        equal(0, BuildIdRecords.object(record, "field").size());
        reject(() -> BuildIdRecords.text(record, "field"));
        for (String invalid : new String[] {"", "x".repeat(16385), "before\0after"}) {
            record.addProperty("field", invalid);
            reject(() -> BuildIdRecords.text(record, "field"));
        }
        for (String valid : new String[] {"x", "x".repeat(16384), "quote \" λ"}) {
            record.addProperty("field", valid);
            equal(valid, BuildIdRecords.text(record, "field"));
        }
        BuildIdRecords.keys(record, "field");
        reject(() -> BuildIdRecords.keys(record));
        reject(() -> BuildIdRecords.keys(record, "field", "missing"));
        record.addProperty("unexpected", "data");
        reject(() -> BuildIdRecords.keys(record, "field"));
    }

    private static JsonObject observation(String bytes, String crc) {
        var object = new JsonObject();
        object.addProperty("sha256", "a".repeat(64));
        object.addProperty("bytes", bytes);
        object.addProperty("crc32", crc);
        object.addProperty("identity", "test-file-identity");
        object.addProperty("metadataSha256", "b".repeat(64));
        return object;
    }

    private static void snapshotBoundaries() throws Exception {
        Path path = Path.of("record-only-fixture.dbg");
        for (String[] pair : new String[][] {{"0", "0"}, {"9223372036854775807", "4294967295"}}) {
            JsonObject record = observation(pair[0], pair[1]);
            var snapshot = BuildIdRecords.snapshot(record, path);
            equal(path, snapshot.path());
            equal(Long.parseLong(pair[0]), snapshot.digest().byteCount());
            equal(Long.parseLong(pair[1]), snapshot.digest().gnuDebuglinkCrc32());
            equal("a".repeat(64), snapshot.digest().sha256());
            equal("test-file-identity", snapshot.fingerprint().identity());
            equal("b".repeat(64), snapshot.fingerprint().metadataSha256());
            equal(1L, snapshot.fingerprint().links());
            equal(record, BuildIdRecords.snapshot(snapshot));
        }
        for (String field : new String[] {"bytes", "crc32"}) {
            for (String invalid : new String[] {"-1", "+1", "01", " 1", "1 ", "1.0", "1e2",
                    "9223372036854775808", "10000000000000000000"}) {
                JsonObject record = observation("1", "2");
                record.addProperty(field, invalid);
                reject(() -> BuildIdRecords.snapshot(record, path));
            }
        }
        reject(() -> BuildIdRecords.snapshot(observation("1", "4294967296"), path));
        for (String field : new String[] {"sha256", "metadataSha256"}) {
            for (String invalid : new String[] {"a".repeat(63), "A".repeat(64), "g".repeat(64)}) {
                JsonObject record = observation("1", "2");
                record.addProperty(field, invalid);
                reject(() -> BuildIdRecords.snapshot(record, path));
            }
        }
        JsonObject missing = observation("1", "2");
        missing.remove("identity");
        reject(() -> BuildIdRecords.snapshot(missing, path));
        JsonObject extra = observation("1", "2");
        extra.addProperty("unexpected", "data");
        reject(() -> BuildIdRecords.snapshot(extra, path));
    }

    private static void retainedPaths() throws Exception {
        Path parent = Path.of("generation").toAbsolutePath().normalize();
        for (String name : new String[] {"source.c", "source/part.c", "source λ/file with spaces.c"}) {
            equal(parent.resolve(name), BuildIdRecords.relative(parent, name));
        }
        for (String invalid : new String[] {"", ".", "..", "../outside", "source/../outside",
                "source/./file", "source/../../outside", "invalid\0name", parent.resolve("absolute.c").toString()}) {
            reject(() -> BuildIdRecords.relative(parent, invalid));
        }
        reject(() -> BuildIdRecords.relative(parent.resolve("unresolved/.."), "part.c"));
    }

    private static void equal(Object expected, Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("expected " + expected + ", got " + actual);
    }

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void reject(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected invalid record refusal"); }
        catch (IOException expected) { }
    }
}

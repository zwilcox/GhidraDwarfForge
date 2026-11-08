package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Large source inventories must not weaken the small command/state record budgets. */
public final class BuildIdRecordsSmoke {
    public static void main(String[] args) throws Exception {
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

    @FunctionalInterface private interface Checked { void run() throws Exception; }
    private static void reject(Checked action) throws Exception {
        try { action.run(); throw new AssertionError("expected invalid record refusal"); }
        catch (IOException expected) { }
    }
}

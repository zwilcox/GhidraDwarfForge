package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/** Isolated entry point; never supplies a production attachment Host. */
public final class LinuxFileMetadataProbe {
    public static void main(String[] args) throws Exception {
        var metadata = new LinuxFileMetadata();
        var gson = new Gson();
        if (args.length == 2 && args[0].equals("inspect")) {
            System.out.println(gson.toJson(metadata.inspect(Path.of(args[1]), () -> false)));
        }
        else if (args.length == 3 && args[0].equals("leak-controls")) {
            Path original = Path.of(args[1]);
            metadata.inspect(original, () -> false);
            long before = descriptors();
            for (int iteration = 0; iteration < 128; iteration++) {
                metadata.inspect(original, () -> false);
                try {
                    metadata.inspect(Path.of(args[2]), () -> false);
                    throw new AssertionError("nonregular file accepted");
                }
                catch (java.io.IOException expected) { }
                var calls = new AtomicInteger();
                try {
                    metadata.inspect(original, () -> calls.incrementAndGet() >= 2);
                    throw new AssertionError("cancelled opened file accepted");
                }
                catch (java.util.concurrent.CancellationException expected) { }
            }
            if (descriptors() != before) throw new AssertionError("native descriptors leaked");
            System.out.println("linux-metadata-descriptors=PASS iterations=128");
        }
        else if (args.length == 5 && args[0].equals("apply")) {
            var json = JsonParser.parseString(Files.readString(Path.of(args[3]))).getAsJsonObject();
            var facts = json.getAsJsonObject("facts");
            var attributes = new java.util.TreeMap<String, String>();
            json.getAsJsonObject("visibleAttributes").entrySet().forEach(entry ->
                attributes.put(entry.getKey(), entry.getValue().getAsString()));
            var expected = new LinuxFileMetadata.Snapshot(new LinuxFileMetadata.Facts(
                facts.get("identity").getAsString(), facts.get("links").getAsLong(), facts.get("mode").getAsInt(),
                facts.get("uid").getAsLong(), facts.get("gid").getAsLong(), facts.get("bytes").getAsLong(),
                facts.get("modifiedSeconds").getAsLong(), facts.get("modifiedNanos").getAsInt(),
                facts.get("changedSeconds").getAsLong(), facts.get("changedNanos").getAsInt(),
                facts.get("attributes").getAsLong(), facts.get("attributesMask").getAsLong()), attributes);
            int stopAt = Integer.parseInt(args[4]);
            var polls = new AtomicInteger();
            var result = metadata.applyToOwnedStage(Path.of(args[1]), expected, Path.of(args[2]),
                () -> stopAt >= 0 && polls.incrementAndGet() >= stopAt);
            System.out.println(gson.toJson(result));
        }
        else throw new IllegalArgumentException("inspect path | apply source owned-stage snapshot-json cancel-poll");
    }

    private static long descriptors() throws Exception {
        try (var files = Files.list(Path.of("/proc/self/fd"))) { return files.count(); }
    }
}

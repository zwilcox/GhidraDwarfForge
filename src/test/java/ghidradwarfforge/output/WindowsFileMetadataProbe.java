package ghidradwarfforge.output;

import com.google.gson.Gson;
import com.google.gson.JsonParser;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

/** Standalone Windows ABI/runtime probe; never installs an attachment Host. */
public final class WindowsFileMetadataProbe {
    public static void main(String[] args) throws Exception {
        var metadata = new WindowsFileMetadata();
        var gson = new Gson();
        if (args.length == 2 && args[0].equals("inspect")) {
            System.out.println(gson.toJson(metadata.inspect(Path.of(args[1]), () -> false)));
        }
        else if (args.length == 5 && args[0].equals("apply")) {
            var json = JsonParser.parseString(Files.readString(Path.of(args[3]))).getAsJsonObject();
            var facts = json.getAsJsonObject("facts");
            var security = json.getAsJsonObject("security");
            var streams = new TreeMap<String, Long>();
            json.getAsJsonObject("dataStreams").entrySet().forEach(entry -> streams.put(entry.getKey(), entry.getValue().getAsLong()));
            var dacl = security.get("dacl");
            var expected = new WindowsFileMetadata.Snapshot(new WindowsFileMetadata.Facts(
                facts.get("identity").getAsString(), facts.get("links").getAsLong(), facts.get("bytes").getAsLong(),
                facts.get("attributes").getAsInt(), facts.get("created").getAsLong(), facts.get("modified").getAsLong(),
                facts.get("changed").getAsLong()), new WindowsFileMetadata.Security(
                security.get("control").getAsInt(), security.get("owner").getAsString(), security.get("group").getAsString(),
                dacl == null || dacl.isJsonNull() ? null : dacl.getAsString(), security.get("rawDescriptor").getAsString()), streams);
            int stopAt = Integer.parseInt(args[4]);
            var polls = new AtomicInteger();
            try {
                var result = metadata.applyToOwnedStage(Path.of(args[1]), expected, Path.of(args[2]),
                    () -> stopAt >= 0 && polls.incrementAndGet() >= stopAt);
                System.out.println(gson.toJson(result));
            }
            catch (java.io.IOException failure) {
                try { System.err.println("privateStage=" + gson.toJson(metadata.inspect(Path.of(args[2]), () -> false))); }
                catch (java.io.IOException observation) { failure.addSuppressed(observation); }
                throw failure;
            }
        }
        else if (args.length == 2 && args[0].equals("leak-controls")) {
            Path source = Path.of(args[1]);
            metadata.inspect(source, () -> false);
            long before = metadata.processHandleCount();
            for (int iteration = 0; iteration < 128; iteration++) {
                metadata.inspect(source, () -> false);
                var polls = new AtomicInteger();
                try {
                    metadata.inspect(source, () -> polls.incrementAndGet() >= 2);
                    throw new AssertionError("cancelled opened handle accepted");
                }
                catch (java.util.concurrent.CancellationException expected) { }
            }
            if (metadata.processHandleCount() != before) throw new AssertionError("Windows native handles leaked");
            System.out.println("windows-metadata-handles=PASS iterations=128");
        }
        else throw new IllegalArgumentException("inspect path | apply source owned-stage snapshot cancel-poll | leak-controls path");
    }
}

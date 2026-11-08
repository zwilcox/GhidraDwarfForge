package ghidradwarfforge.output;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Set;
import java.util.function.BooleanSupplier;

/** Bounded, duplicate-rejecting installation records and explicit command requests. */
final class BuildIdRecords {
    private static final ReportJsonReader.Limits LIMITS =
        new ReportJsonReader.Limits(1024 * 1024, 16384, 8, 20000, 1);
    static final int GENERATION_MAX_BYTES = 64 * 1024 * 1024;
    private static final ReportJsonReader.Limits GENERATION_LIMITS =
        new ReportJsonReader.Limits(GENERATION_MAX_BYTES, 16384, 8, 1_000_000, 1);

    private BuildIdRecords() { }

    static JsonObject read(Path path, BooleanSupplier cancelled) throws IOException {
        return read(Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS), cancelled);
    }

    static JsonObject read(byte[] bytes, BooleanSupplier cancelled) throws IOException {
        return read(new ByteArrayInputStream(bytes), cancelled);
    }

    /** Only retained generation inventories receive the expanded source-part budget. */
    static JsonObject readGeneration(Path path, BooleanSupplier cancelled) throws IOException {
        return read(Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS), cancelled, GENERATION_LIMITS);
    }

    private static JsonObject read(InputStream input, BooleanSupplier cancelled) throws IOException {
        return read(input, cancelled, LIMITS);
    }

    private static JsonObject read(InputStream input, BooleanSupplier cancelled, ReportJsonReader.Limits limits) throws IOException {
        try (var stream = input;
                var json = new JsonReader(new ReportJsonReader(stream, cancelled, limits))) {
            json.setLenient(false);
            JsonElement value = readValue(json, new int[] { 0 }, limits.values());
            require(value.isJsonObject() && json.peek() == JsonToken.END_DOCUMENT, "invalid build-ID record document");
            return value.getAsJsonObject();
        }
        catch (java.util.concurrent.CancellationException stopped) { throw stopped; }
        catch (IllegalArgumentException | IllegalStateException invalid) {
            throw new IOException("invalid build-ID record", invalid);
        }
    }

    private static JsonElement readValue(JsonReader reader, int[] count, int maximumValues) throws IOException {
        require(++count[0] <= maximumValues, "build-ID record exceeds value limit");
        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                var value = new JsonObject();
                reader.beginObject();
                while (reader.hasNext()) {
                    String name = reader.nextName();
                    require(!value.has(name), "duplicate build-ID record member: " + name);
                    value.add(name, readValue(reader, count, maximumValues));
                }
                reader.endObject();
                yield value;
            }
            case STRING -> new JsonPrimitive(reader.nextString());
            case NULL -> { reader.nextNull(); yield JsonNull.INSTANCE; }
            default -> throw new IOException("build-ID records require string/object/null values");
        };
    }

    static JsonObject object(JsonObject parent, String key) throws IOException {
        JsonElement value = parent.get(key);
        require(value != null && value.isJsonObject(), "expected build-ID object: " + key);
        return value.getAsJsonObject();
    }

    static String text(JsonObject parent, String key) throws IOException {
        JsonElement value = parent.get(key);
        require(value != null && value.isJsonPrimitive() && value.getAsJsonPrimitive().isString(),
            "expected build-ID string: " + key);
        String text = value.getAsString();
        require(!text.isEmpty() && text.length() <= 16384 && text.indexOf('\0') < 0, "invalid build-ID string: " + key);
        return text;
    }

    static void keys(JsonObject object, String... keys) throws IOException {
        require(object.keySet().equals(Set.of(keys)), "unknown or missing build-ID record members");
    }

    static Path relative(Path parent, String name) throws IOException {
        final Path part;
        try { part = Path.of(name); }
        catch (RuntimeException invalid) { throw new IOException("invalid retained artifact path", invalid); }
        require(!part.isAbsolute() && !name.isEmpty() && !part.toString().isEmpty() &&
            part.normalize().equals(part) && !part.startsWith("..") && !part.equals(Path.of(".")),
            "retained artifact path is not a normalized relative path");
        Path result = parent.resolve(part).normalize();
        require(result.startsWith(parent) && !result.equals(parent), "retained artifact escapes generation");
        return result;
    }

    static JsonObject snapshot(AttachmentFileStore.Snapshot file) {
        var json = new JsonObject();
        json.addProperty("sha256", file.digest().sha256());
        json.addProperty("bytes", Long.toString(file.digest().byteCount()));
        json.addProperty("crc32", Long.toString(file.digest().gnuDebuglinkCrc32()));
        json.addProperty("identity", file.fingerprint().identity());
        json.addProperty("metadataSha256", file.fingerprint().metadataSha256());
        return json;
    }

    static AttachmentFileStore.Snapshot snapshot(JsonObject json, Path path) throws IOException {
        keys(json, "sha256", "bytes", "crc32", "identity", "metadataSha256");
        try {
            return new AttachmentFileStore.Snapshot(path,
                new FileDigests.Result(text(json, "sha256"), number(json, "crc32"), number(json, "bytes")),
                new AttachmentReceiptStore.Fingerprint(text(json, "identity"), text(json, "metadataSha256"), 1));
        }
        catch (IllegalArgumentException invalid) { throw new IOException("invalid retained artifact observation", invalid); }
    }

    private static long number(JsonObject json, String name) throws IOException {
        String value = text(json, name);
        require(value.matches("0|[1-9][0-9]{0,18}"), "noncanonical artifact integer");
        return Long.parseLong(value);
    }

    static void require(boolean condition, String message) throws IOException {
        if (!condition) throw new IOException(message);
    }
}

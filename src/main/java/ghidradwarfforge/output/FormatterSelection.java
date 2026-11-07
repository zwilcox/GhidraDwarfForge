package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;

/** Explicit analyst choices. Keys refer to one export's canonical recovered type graph. */
public record FormatterSelection(Map<String, String> modes) {
    private static final ReportJsonReader.Limits LIMITS =
        new ReportJsonReader.Limits(65536, 4096, 4, 2048, 128);

    public FormatterSelection {
        modes = java.util.Collections.unmodifiableMap(new TreeMap<>(modes));
        if (modes.isEmpty() || modes.size() > 128 || modes.entrySet().stream().anyMatch(entry ->
                entry.getKey().isBlank() || !Set.of("flags", "structure").contains(entry.getValue()))) {
            throw new IllegalArgumentException("select 1..128 canonical types as flags or structure");
        }
    }

    public static FormatterSelection read(Path path, BooleanSupplier cancelled) throws IOException {
        try (var input = new ReportJsonReader(Files.newInputStream(path), cancelled, LIMITS);
                var json = new JsonReader(input)) {
            return new Reader(json, cancelled).read();
        }
    }

    private static final class Reader extends ReportValueReader {
        Reader(JsonReader json, BooleanSupplier cancelled) { super(json, cancelled, LIMITS); }

        FormatterSelection read() throws IOException {
            var modes = new TreeMap<String, String>();
            object("formatter selection", Set.of("schema", "types"), field -> {
                if (field.equals("schema")) {
                    if (integer() != 1) throw invalid("unsupported formatter selection schema");
                }
                else array(() -> {
                    var row = new TreeMap<String, String>();
                    object("formatter type", Set.of("key", "mode"), name -> row.put(name, text(true)));
                    if (modes.putIfAbsent(row.get("key"), row.get("mode")) != null) {
                        throw invalid("duplicate formatter type key");
                    }
                });
            });
            value(JsonToken.END_DOCUMENT);
            try { return new FormatterSelection(modes); }
            catch (IllegalArgumentException invalid) { throw new IOException(invalid.getMessage(), invalid); }
        }
    }
}

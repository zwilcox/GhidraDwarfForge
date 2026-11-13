package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;

/** Explicit associations with the selected program's original FileBytes inventory. */
public record FirmwareInputs(List<Selection> inputs) {
    private static final ReportJsonReader.Limits LIMITS =
        new ReportJsonReader.Limits(65536, 4096, 4, 4096, 128);

    public record Selection(String id, int fileBytesIndex, String path) {
        public Selection {
            if (id == null || id.isBlank() || id.indexOf('\0') >= 0 || fileBytesIndex < 0 ||
                    path == null || path.isBlank() || path.indexOf('\0') >= 0) {
                throw new IllegalArgumentException("invalid firmware FileBytes selection");
            }
        }
    }

    public FirmwareInputs {
        inputs = List.copyOf(inputs);
        var names = new HashSet<String>();
        var indices = new HashSet<Integer>();
        if (inputs.isEmpty() || inputs.size() > 128) throw new IllegalArgumentException("select 1..128 firmware inputs");
        for (var input : inputs) {
            if (!names.add(input.id()) || !indices.add(input.fileBytesIndex())) {
                throw new IllegalArgumentException("duplicate firmware input ID or FileBytes index");
            }
        }
    }

    public static FirmwareInputs read(Path path, BooleanSupplier cancelled) throws IOException {
        try (var input = new ReportJsonReader(Files.newInputStream(path), cancelled, LIMITS);
                var json = new JsonReader(input)) {
            return new Reader(json, cancelled).read();
        }
    }

    private static final class Reader extends ReportValueReader {
        Reader(JsonReader json, BooleanSupplier cancelled) { super(json, cancelled, LIMITS); }

        FirmwareInputs read() throws IOException {
            var selections = new ArrayList<Selection>();
            object("firmware inputs", Set.of("schema", "inputs"), field -> {
                if (field.equals("schema")) {
                    if (integer() != 1) throw invalid("unsupported firmware inputs schema");
                }
                else array(() -> {
                    var strings = new TreeMap<String, String>();
                    int[] index = new int[1];
                    object("firmware input", Set.of("id", "fileBytesIndex", "path"), name -> {
                        if (name.equals("fileBytesIndex")) index[0] = integer();
                        else strings.put(name, text(true));
                    });
                    selections.add(new Selection(strings.get("id"), index[0], strings.get("path")));
                });
            });
            value(JsonToken.END_DOCUMENT);
            try { return new FirmwareInputs(selections); }
            catch (IllegalArgumentException invalid) { throw new IOException(invalid.getMessage(), invalid); }
        }
    }
}

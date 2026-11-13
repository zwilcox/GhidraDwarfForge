package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.BooleanSupplier;

/** Explicit saved analyst assertions; no peripheral semantics are inferred. */
public record MmioSelection(String language, String architecture, Transport transport, List<Register> registers) {
    private static final ReportJsonReader.Limits LIMITS = new ReportJsonReader.Limits(65536, 4096, 8, 16384, 2048);
    public record Transport(String id, String evidence) { }
    public record View(String name, String datatype, int offset, List<String> qualifiers) {
        public View { qualifiers = List.copyOf(qualifiers); }
    }
    public record Register(String name, String address, String runtimeAddress, int width, String readEffect, List<View> views) {
        public Register { views = List.copyOf(views); }
    }

    public MmioSelection {
        registers = List.copyOf(registers);
        require(language != null && !language.isBlank() && architecture != null && !architecture.isBlank() &&
            architecture.length() <= 80, "missing or oversized MMIO target identity");
        require(transport != null, "missing MMIO transport contract");
        label(transport.id());
        require(transport.evidence() != null && !transport.evidence().isBlank() && transport.evidence().length() <= 4096,
            "MMIO transport evidence is required and bounded");
        require(!registers.isEmpty() && registers.size() <= 128, "select 1..128 MMIO registers");
        var names = new HashSet<String>();
        for (var r : registers) {
            label(r.name());
            require(names.add(r.name()), "duplicate MMIO register name");
            require(r.address() != null && !r.address().isBlank(), "missing Ghidra MMIO address");
            require(r.runtimeAddress() != null && r.runtimeAddress().matches("0x[0-9a-f]{1,16}"), "invalid MMIO runtime address");
            require(Set.of(1, 2, 4, 8).contains(r.width()), "unsupported MMIO access width");
            require(Set.of("none", "read-clear", "read-increment", "unknown", "write-only").contains(r.readEffect()), "invalid MMIO read policy");
            require(!r.views().isEmpty() && r.views().size() <= 16, "select 1..16 MMIO views");
            var viewNames = new HashSet<String>();
            for (var v : r.views()) {
                label(v.name());
                require(viewNames.add(v.name()), "duplicate MMIO view name");
                require(v.datatype() != null && v.datatype().startsWith("/") && v.datatype().length() > 1, "MMIO view requires an exact data-type path");
                require(v.offset() >= 0 && v.offset() < r.width(), "MMIO view offset exceeds register");
                require(v.qualifiers().size() <= 2 && new HashSet<>(v.qualifiers()).size() == v.qualifiers().size() &&
                    v.qualifiers().stream().allMatch(q -> q.equals("const") || q.equals("volatile")), "invalid MMIO qualifiers");
            }
        }
    }

    public static MmioSelection read(String text, BooleanSupplier cancelled) throws IOException {
        if (text == null || text.length() > 65536) throw new IOException("missing or oversized saved MMIO selection");
        try (var input = new ReportJsonReader(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)), cancelled, LIMITS);
                var json = new JsonReader(input)) {
            return new Reader(json, cancelled).read();
        }
    }

    private static void label(String name) {
        require(name != null && name.matches("[A-Za-z_][A-Za-z0-9_.-]{0,79}"), "invalid MMIO selection label");
    }
    private static void require(boolean valid, String message) {
        if (!valid) throw new IllegalArgumentException(message);
    }

    private static final class Reader extends ReportValueReader {
        Reader(JsonReader json, BooleanSupplier cancelled) { super(json, cancelled, LIMITS); }
        MmioSelection read() throws IOException {
            var words = new java.util.HashMap<String, String>();
            var transport = new Transport[1];
            var registers = new ArrayList<Register>();
            object("MMIO selection", Set.of("schema", "language", "architecture", "transport", "registers"), name -> {
                switch (name) {
                    case "schema" -> { if (integer() != 1) throw invalid("unsupported saved MMIO selection schema"); }
                    case "transport" -> {
                        var fields = new java.util.HashMap<String, String>();
                        object("MMIO transport", Set.of("id", "evidence"), field -> fields.put(field, text(true)));
                        transport[0] = new Transport(fields.get("id"), fields.get("evidence"));
                    }
                    case "registers" -> array(() -> registers.add(register()));
                    default -> words.put(name, text(true));
                }
            });
            value(JsonToken.END_DOCUMENT);
            try { return new MmioSelection(words.get("language"), words.get("architecture"), transport[0], registers); }
            catch (IllegalArgumentException e) { throw new IOException(e.getMessage(), e); }
        }
        Register register() throws IOException {
            var words = new java.util.HashMap<String, String>();
            var width = new int[1];
            var views = new ArrayList<View>();
            object("MMIO register", Set.of("name", "address", "runtime_address", "width", "read_effect", "views"), name -> {
                if (name.equals("width")) width[0] = boundedInt();
                else if (name.equals("views")) array(() -> views.add(view()));
                else words.put(name, text(true));
            });
            return new Register(words.get("name"), words.get("address"), words.get("runtime_address"), width[0], words.get("read_effect"), views);
        }
        View view() throws IOException {
            var words = new java.util.HashMap<String, String>();
            var offset = new int[1];
            var qualifiers = new ArrayList<String>();
            object("MMIO view", Set.of("name", "datatype", "offset", "qualifiers"), name -> {
                if (name.equals("offset")) offset[0] = boundedInt();
                else if (name.equals("qualifiers")) array(() -> qualifiers.add(text(true)));
                else words.put(name, text(true));
            });
            return new View(words.get("name"), words.get("datatype"), offset[0], qualifiers);
        }
        int boundedInt() throws IOException {
            return integer();
        }
    }
}

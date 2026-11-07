package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.google.gson.stream.JsonWriter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.source.SourcePartitionPlan;
import ghidradwarfforge.source.SyntheticSourceFile;

/** Deterministic, data-only inventory of an optional synthetic source generation. */
public final class SourceBundle {
    public static final String INDEX_PREFIX = "/* GhidraDwarfForge multi-file synthetic source index v1.\n";
    private static final ReportJsonReader.Limits LIMITS =
        new ReportJsonReader.Limits(64L * 1024 * 1024, 65536, 8, 4_000_000, 250_000);

    public record Part(int file, String sha256, int bytes, int first, int last) {
        public Part {
            hash(sha256);
            if (file < 1 || file > 65536 || bytes < 1 || first < 1 || last < first) {
                throw new IllegalArgumentException("invalid source part inventory");
            }
        }

        public String fileName() {
            return "forge-src-" + String.format(java.util.Locale.ROOT, "%06d", file) + "-" + sha256 + ".c";
        }
    }

    public record Function(String name, long address, int file, int first, int last, String disposition) {
        public Function {
            if (name == null || name.isBlank() || name.indexOf('\0') >= 0 || address < 0 ||
                    file < 1 || first < 3 || last < first || disposition == null ||
                    !Set.of("decompiled", "failed", "omitted").contains(disposition)) {
                throw new IllegalArgumentException("invalid source function inventory");
            }
        }
    }

    public record Manifest(String indexName, String inputSha256, String logicalSourceSha256,
            int targetLines, List<Part> parts, List<Function> functions) {
        public Manifest {
            hash(inputSha256);
            hash(logicalSourceSha256);
            if (indexName == null || indexName.isBlank() || indexName.indexOf('\0') >= 0 ||
                    indexName.contains("/") || indexName.contains("\\") ||
                    indexName.equals(".") || indexName.equals("..") || targetLines < 1 ||
                    parts == null || parts.isEmpty() || parts.size() > 65536 ||
                    functions == null || functions.size() > 250000) {
                throw new IllegalArgumentException("invalid source generation manifest");
            }
            parts = List.copyOf(parts);
            functions = List.copyOf(functions);
            long nextLine = 1;
            for (int index = 0; index < parts.size(); index++) {
                Part part = parts.get(index);
                if (part.file() != index + 1 || part.first() != nextLine) {
                    throw new IllegalArgumentException("source generation has missing, duplicate or unordered parts");
                }
                nextLine = (long) part.last() + 1;
            }
            int previousEnd = 0;
            var keys = new java.util.HashSet<String>();
            for (Function function : functions) {
                if (function.file() > parts.size()) throw new IllegalArgumentException("function references missing source part");
                Part part = parts.get(function.file() - 1);
                long first = (long) part.first() + function.first() - 3;
                long last = (long) part.first() + function.last() - 3;
                if (last > part.last() || first <= previousEnd ||
                        !keys.add(function.address() + ":" + function.name())) {
                    throw new IllegalArgumentException("source function bounds or identity conflict");
                }
                previousEnd = (int) last;
            }
        }
    }

    public static final class Plan {
        private final Manifest manifest;
        private final SourcePartitionPlan partitions;
        private final byte[] manifestBytes;
        private final String manifestSha256;
        private final Map<String, Part> byName;

        private Plan(Manifest manifest, SourcePartitionPlan partitions, byte[] bytes) {
            this.manifest = manifest;
            this.partitions = partitions;
            this.manifestBytes = bytes;
            this.manifestSha256 = sha256(bytes);
            var names = new HashMap<String, Part>();
            for (Part part : manifest.parts()) names.put(part.fileName(), part);
            byName = Map.copyOf(names);
        }

        public Manifest manifest() { return manifest; }
        public String manifestName() { return manifestNameFor(manifestSha256); }
        public String manifestSha256() { return manifestSha256; }
        public byte[] manifestBytes() { return manifestBytes.clone(); }
        public byte[] indexBytes(BooleanSupplier cancelled) { return renderIndex(manifest, manifestSha256, cancelled); }

        public List<String> fileNames() {
            var names = new ArrayList<>(manifest.parts().stream().map(Part::fileName).toList());
            names.add(manifestName());
            return List.copyOf(names);
        }

        public String expectedSha256(String name) {
            return name.equals(manifestName()) ? manifestSha256 : part(name).sha256();
        }

        public int expectedBytes(String name) {
            return name.equals(manifestName()) ? manifestBytes.length : part(name).bytes();
        }

        public byte[] bytes(String name) {
            return name.equals(manifestName()) ? manifestBytes() : partitions.parts().get(part(name).file() - 1).utf8();
        }

        public Dwarf5LineTable.FileLayout fileLayout() {
            return Dwarf5LineTable.FileLayout.partitioned(manifest.indexName(),
                manifest.parts().stream().map(Part::fileName).toList(), partitions);
        }

        private Part part(String name) {
            Part part = byName.get(name);
            if (part == null) throw new IllegalArgumentException("file is outside source generation");
            return part;
        }
    }

    private SourceBundle() { }

    public static Plan prepare(String inputSha256, String indexName, SyntheticSourceFile source,
            int targetLines, BooleanSupplier cancelled) throws IOException {
        check(cancelled);
        var partitions = SourcePartitionPlan.build(source, targetLines, cancelled);
        var parts = new ArrayList<Part>();
        for (var part : partitions.parts()) {
            check(cancelled);
            byte[] bytes = part.utf8();
            parts.add(new Part(part.file(), sha256(bytes), bytes.length,
                part.firstLogicalLine(), part.lastLogicalLine()));
        }
        var functions = new ArrayList<Function>();
        for (var function : source.functions()) {
            check(cancelled);
            var start = partitions.locate(function.startLine());
            var end = partitions.locate(function.endLine());
            if (start.file() != end.file()) throw new IllegalArgumentException("partition splits a source function");
            functions.add(new Function(function.name(), function.address(), start.file(), start.line(), end.line(),
                function.decompiled() ? "decompiled" : function.failureDiagnostic() != null ? "failed" : "omitted"));
        }
        var manifest = new Manifest(indexName, inputSha256, partitions.sourceSha256(), targetLines, parts, functions);
        byte[] bytes = render(manifest, cancelled);
        // Apply the same strict bounds and Unicode/document rules to generated and consumed inventories.
        if (!manifest.equals(read(bytes, cancelled))) throw new IOException("source manifest round trip differs");
        check(cancelled);
        return new Plan(manifest, partitions, bytes);
    }

    public static byte[] render(Manifest manifest, BooleanSupplier cancelled) throws IOException {
        var text = new StringWriter();
        try (var json = new JsonWriter(text)) {
            json.beginObject();
            json.name("schema").value(1);
            json.name("indexName").value(manifest.indexName());
            json.name("inputSha256").value(manifest.inputSha256());
            json.name("logicalSourceSha256").value(manifest.logicalSourceSha256());
            json.name("targetLines").value(manifest.targetLines());
            json.name("parts").beginArray();
            for (Part part : manifest.parts()) {
                check(cancelled);
                json.beginObject();
                json.name("file").value(part.file()); json.name("name").value(part.fileName());
                json.name("sha256").value(part.sha256()); json.name("bytes").value(part.bytes());
                json.name("first").value(part.first()); json.name("last").value(part.last());
                json.endObject();
            }
            json.endArray();
            json.name("functions").beginArray();
            for (Function function : manifest.functions()) {
                check(cancelled);
                json.beginObject();
                json.name("name").value(function.name());
                json.name("address").value("0x" + Long.toHexString(function.address()));
                json.name("file").value(function.file()); json.name("first").value(function.first());
                json.name("last").value(function.last()); json.name("disposition").value(function.disposition());
                json.endObject();
            }
            json.endArray(); json.endObject();
        }
        check(cancelled);
        return (text + "\n").getBytes(StandardCharsets.UTF_8);
    }

    public static Manifest read(byte[] bytes, BooleanSupplier cancelled) throws IOException {
        try (var input = new ReportJsonReader(new ByteArrayInputStream(bytes), cancelled, LIMITS);
                var json = new JsonReader(input)) {
            Manifest manifest = new Reader(json, cancelled).read();
            if (!Arrays.equals(bytes, render(manifest, cancelled))) {
                throw new IOException("source manifest is not in canonical generated form");
            }
            return manifest;
        }
        catch (CancellationException cancelledRead) {
            throw cancelledRead;
        }
        catch (IllegalArgumentException | IllegalStateException invalid) {
            throw new IOException("invalid source manifest", invalid);
        }
    }

    public static String manifestNameFor(String sha256) {
        hash(sha256);
        return "forge-src-" + sha256 + ".json";
    }

    /** Index contents contain only generated ASCII filenames, never executable analyst text. */
    public static byte[] renderIndex(Manifest manifest, String manifestSha256, BooleanSupplier cancelled) {
        check(cancelled);
        var text = new StringBuilder(INDEX_PREFIX);
        text.append(" * This is decompiler presentation, not recovered original source.\n")
            .append(" * Manifest: ").append(manifestNameFor(manifestSha256)).append("\n")
            .append(" * Keep this index, the manifest and all listed parts beside the sidecar.\n");
        for (Part part : manifest.parts()) {
            check(cancelled);
            text.append(" * ").append(part.fileName()).append(" [logical lines ")
                .append(part.first()).append('-').append(part.last()).append(']');
            if ((long) part.last() - part.first() + 1 > manifest.targetLines()) text.append(" (indivisible oversized unit)");
            text.append('\n');
        }
        text.append(" */\n");
        check(cancelled);
        return text.toString().getBytes(StandardCharsets.UTF_8);
    }

    static String sha256(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }

    private static void hash(String value) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid source SHA-256");
    }

    static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("source generation cancelled");
    }

    private static final class Reader extends ReportValueReader {
        Reader(JsonReader json, BooleanSupplier cancelled) { super(json, cancelled, LIMITS); }

        Manifest read() throws IOException {
            var text = new HashMap<String, String>();
            int[] target = { 0 };
            var parts = new ArrayList<Part>();
            var functions = new ArrayList<Function>();
            object("source manifest", Set.of("schema", "indexName", "inputSha256", "logicalSourceSha256",
                "targetLines", "parts", "functions"), field -> {
                switch (field) {
                    case "schema" -> { if (integer() != 1) throw invalid("unsupported source manifest schema"); }
                    case "targetLines" -> target[0] = integer();
                    case "parts" -> array(() -> parts.add(readPart()));
                    case "functions" -> array(() -> functions.add(readFunction()));
                    default -> text.put(field, text(true));
                }
            });
            value(JsonToken.END_DOCUMENT);
            return new Manifest(text.get("indexName"), text.get("inputSha256"), text.get("logicalSourceSha256"),
                target[0], parts, functions);
        }

        private Part readPart() throws IOException {
            var numbers = new HashMap<String, Integer>();
            var text = new HashMap<String, String>();
            object("source part", Set.of("file", "name", "sha256", "bytes", "first", "last"), field -> {
                if (field.equals("name") || field.equals("sha256")) text.put(field, text(true));
                else numbers.put(field, integer());
            });
            var part = new Part(numbers.get("file"), text.get("sha256"), numbers.get("bytes"),
                numbers.get("first"), numbers.get("last"));
            if (!part.fileName().equals(text.get("name"))) throw invalid("source part path differs from content identity");
            return part;
        }

        private Function readFunction() throws IOException {
            var numbers = new HashMap<String, Integer>();
            var text = new HashMap<String, String>();
            long[] address = { 0 };
            object("source function", Set.of("name", "address", "file", "first", "last", "disposition"), field -> {
                if (field.equals("address")) address[0] = address();
                else if (field.equals("name") || field.equals("disposition")) text.put(field, text(true));
                else numbers.put(field, integer());
            });
            return new Function(text.get("name"), address[0], numbers.get("file"), numbers.get("first"),
                numbers.get("last"), text.get("disposition"));
        }
    }
}

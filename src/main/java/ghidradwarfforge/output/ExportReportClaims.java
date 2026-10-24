package ghidradwarfforge.output;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * Immutable claims from one current-shape completed export report. These are
 * reported strings/counts, not verified files, ELF identity, validation results,
 * an atomic snapshot, or attachment readiness. Only the supplied report is
 * opened. Artifact paths and hashes retain their exporting-host spelling;
 * referenced artifacts are never opened, resolved, normalized or compared.
 *
 * The reader accepts the current schema-one shape, including the required
 * functionStaticVariables count. Older schema-one shapes are unsupported;
 * version/field presence cannot attest exporter version or count semantics.
 * Inventories are validated and discarded. Their five explicit cardinalities
 * and SUCCESS/PARTIAL status rule are checked without inferring relationships
 * between independently supplied function, type, or variable counts.
 *
 * Reader resource limits, not writer/JSON format constraints: 64 MiB input
 * (plus at most one byte to detect overflow), 65536 UTF-16 units per string,
 * nesting eight, one million values, and 250000 elements per array. Strings
 * are bounded before Gson can grow an unbounded token. Cancellation is checked
 * before opening, around reads, per character/value and after EOF; it cannot
 * interrupt a blocked filesystem read. The owned stream always closes.
 */
public record ExportReportClaims(int schemaVersion, ExportReport.Status status,
        ExportReport.TargetInfo target, ExportReport.Artifacts artifacts,
        ExportReport.Counts counts, ExportReport.ValidationStatus validationStatus,
        String libdwarfVersion) {
    private static final int CURRENT_SCHEMA = 1;

    public ExportReportClaims {
        if (schemaVersion != CURRENT_SCHEMA ||
                (status != ExportReport.Status.SUCCESS && status != ExportReport.Status.PARTIAL)) {
            throw new IllegalArgumentException("completed current-schema report claims are required");
        }
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(artifacts, "artifacts");
        Objects.requireNonNull(counts, "counts");
        Objects.requireNonNull(validationStatus, "validationStatus");
        if (libdwarfVersion == null || libdwarfVersion.isBlank()) {
            throw new IllegalArgumentException("reported libdwarf version is required");
        }
    }

    /** A structurally valid terminal report contains no completed artifact claims. */
    public static final class TerminalReportException extends IOException {
        private static final long serialVersionUID = 1L;
        private final ExportReport.Status status;

        private TerminalReportException(ExportReport.Status status) {
            super("terminal " + status + " report has no completed artifact claims");
            this.status = status;
        }

        public ExportReport.Status status() {
            return status;
        }
    }

    /** A version or historical shape is outside this reader's explicit contract. */
    public static final class UnsupportedReportShapeException extends IOException {
        private static final long serialVersionUID = 1L;

        private UnsupportedReportShapeException(String message) {
            super(message);
        }
    }

    @FunctionalInterface
    interface InputOpener {
        InputStream open(Path path) throws IOException;
    }

    public static ExportReportClaims read(Path report) throws IOException {
        return read(report, () -> false);
    }

    public static ExportReportClaims read(Path report, BooleanSupplier cancelled) throws IOException {
        return read(report, cancelled, Files::newInputStream, ReportJsonReader.DEFAULT_LIMITS);
    }

    /** Test seam: this method owns a successfully opened input; no artifact is accessed. */
    static ExportReportClaims read(Path report, BooleanSupplier cancelled, InputOpener opener,
            ReportJsonReader.Limits limits) throws IOException {
        Objects.requireNonNull(report, "report");
        Objects.requireNonNull(cancelled, "cancelled");
        Objects.requireNonNull(opener, "opener");
        Objects.requireNonNull(limits, "limits");
        ReportJsonReader.checkCancelled(cancelled);
        try (JsonReader json = new JsonReader(new ReportJsonReader(
                Objects.requireNonNull(opener.open(report), "opened report"), cancelled, limits))) {
            json.setLenient(false);
            return new Parser(json, cancelled, limits).read();
        }
    }

    private static final class Parser {
        private static final Set<String> ROOT_FIELDS = Set.of("schemaVersion", "status", "target",
            "artifacts", "counts", "sections", "failedFunctions", "skippedFunctions",
            "omittedLocations", "unsupportedConstructs", "diagnostics", "validation", "native", "failure");
        private static final List<String> COUNT_FIELDS = List.of("functionsExported", "functionsDecompiled",
            "functionsFailed", "functionsSkipped", "functionSignatures", "parameters", "localVariables",
            "globalVariables", "functionStaticVariables", "canonicalTypes", "defensibleVariableLocations",
            "omittedLocationRanges", "mappedSourceLines", "unsupportedConstructs", "diagnostics");
        private static final Set<String> ARTIFACT_FIELDS = Set.of("inputPath", "inputSha256",
            "outputPath", "outputSha256", "sourcePath", "sourceSha256");

        private final JsonReader json;
        private final BooleanSupplier cancelled;
        private final ReportJsonReader.Limits limits;
        private int values;
        private int schema;
        private ExportReport.Status status;
        private ExportReport.TargetInfo target;
        private ExportReport.Artifacts artifacts;
        private ExportReport.Counts counts;
        private String nativeVersion;
        private boolean failure;
        private int sections;
        private int failed;
        private int skipped;
        private int omitted;
        private int unsupported;
        private int diagnostics;

        private Parser(JsonReader json, BooleanSupplier cancelled, ReportJsonReader.Limits limits) {
            this.json = json;
            this.cancelled = cancelled;
            this.limits = limits;
        }

        private ExportReportClaims read() throws IOException {
            object("report", ROOT_FIELDS, name -> {
                switch (name) {
                    case "schemaVersion" -> {
                        schema = integer();
                        if (schema != CURRENT_SCHEMA) {
                            throw new UnsupportedReportShapeException("unsupported report schema version " + schema);
                        }
                    }
                    case "status" -> {
                        String text = text(true);
                        try {
                            status = ExportReport.Status.valueOf(text);
                        }
                        catch (IllegalArgumentException invalid) {
                            throw invalid("unknown report status");
                        }
                    }
                    case "target" -> target = nullable(this::target);
                    case "artifacts" -> artifacts = nullable(this::artifacts);
                    case "counts" -> counts = nullable(this::counts);
                    case "sections" -> sections = array(() -> text(false));
                    case "failedFunctions" -> failed = array(this::failedFunction);
                    case "skippedFunctions" -> skipped = array(() -> textObject("skipped function",
                        Set.of("name", "reason")));
                    case "omittedLocations" -> omitted = array(this::omittedLocation);
                    case "unsupportedConstructs" -> unsupported = array(() -> textObject("unsupported construct",
                        Set.of("kind", "name", "diagnostic")));
                    case "diagnostics" -> diagnostics = array(() -> text(false));
                    case "validation" -> object("validation", Set.of("status"), ignored -> {
                        if (!text(true).equals("NOT_RUN")) {
                            throw invalid("report validation status must remain NOT_RUN");
                        }
                    });
                    case "native" -> object("native", Set.of("libdwarfVersion"),
                        ignored -> nativeVersion = nullable(() -> text(true)));
                    case "failure" -> failure = nullable(() -> {
                        textObject("failure", Set.of("type", "message"));
                        return Boolean.TRUE;
                    }) != null;
                    default -> throw new AssertionError("unhandled known report field");
                }
            });
            if (json.peek() != JsonToken.END_DOCUMENT) {
                throw invalid("trailing content after report");
            }
            ReportJsonReader.checkCancelled(cancelled);
            if (status == ExportReport.Status.CANCELLED || status == ExportReport.Status.FATAL) {
                if (target != null || artifacts != null || counts != null || nativeVersion != null ||
                        !failure || sections != 0 || failed != 0 || skipped != 0 || omitted != 0 ||
                        unsupported != 0 || diagnostics != 0) {
                    throw invalid("terminal report has inconsistent fields or inventories");
                }
                throw new TerminalReportException(status);
            }
            if (target == null || artifacts == null || counts == null || nativeVersion == null || failure) {
                throw invalid("completed report requires target, artifacts, counts, native version and null failure");
            }
            if (counts.functionsFailed() != failed || counts.functionsSkipped() != skipped ||
                    counts.omittedLocationRanges() != omitted || counts.unsupportedConstructs() != unsupported ||
                    counts.diagnostics() != diagnostics) {
                throw invalid("reported counts disagree with report inventories");
            }
            boolean partial = failed != 0 || skipped != 0 || omitted != 0 || unsupported != 0 || diagnostics != 0;
            if (partial != (status == ExportReport.Status.PARTIAL)) {
                throw invalid("SUCCESS/PARTIAL status disagrees with report inventories");
            }
            return new ExportReportClaims(schema, status, target, artifacts, counts,
                ExportReport.ValidationStatus.NOT_RUN, nativeVersion);
        }

        private ExportReport.TargetInfo target() throws IOException {
            String[] strings = new String[2];
            int[] bits = new int[1];
            object("target", Set.of("architecture", "addressBits", "byteOrder"), name -> {
                switch (name) {
                    case "architecture" -> strings[0] = text(true);
                    case "addressBits" -> bits[0] = integer();
                    case "byteOrder" -> strings[1] = text(true);
                    default -> throw new AssertionError();
                }
            });
            if ((bits[0] != 32 && bits[0] != 64) ||
                    (!strings[1].equals("LITTLE_ENDIAN") && !strings[1].equals("BIG_ENDIAN"))) {
                throw invalid("unsupported reported address size or byte order");
            }
            return new ExportReport.TargetInfo(strings[0], bits[0], strings[1]);
        }

        private ExportReport.Artifacts artifacts() throws IOException {
            java.util.Map<String, String> fields = new java.util.HashMap<>();
            object("artifacts", ARTIFACT_FIELDS, name -> {
                String value = text(true);
                if (name.endsWith("Sha256") && !value.matches("[0-9a-fA-F]{64}")) {
                    throw invalid("invalid reported SHA-256 spelling");
                }
                fields.put(name, value);
            });
            return new ExportReport.Artifacts(fields.get("inputPath"), fields.get("inputSha256"),
                fields.get("outputPath"), fields.get("outputSha256"), fields.get("sourcePath"),
                fields.get("sourceSha256"));
        }

        private ExportReport.Counts counts() throws IOException {
            int[] count = new int[COUNT_FIELDS.size()];
            object("counts", Set.copyOf(COUNT_FIELDS), name -> count[COUNT_FIELDS.indexOf(name)] = integer());
            return new ExportReport.Counts(count[0], count[1], count[2], count[3], count[4],
                count[5], count[6], count[7], count[8], count[9], count[10], count[11], count[12],
                count[13], count[14]);
        }

        private void failedFunction() throws IOException {
            object("failed function", Set.of("name", "address", "diagnostic"), name -> {
                if (name.equals("address")) {
                    address(); // Any long's unsigned hex spelling is writer-valid here.
                }
                else {
                    text(true);
                }
            });
        }

        private void omittedLocation() throws IOException {
            long[] bounds = new long[2];
            object("omitted location", Set.of("function", "variable", "kind", "startAddress",
                "endAddress", "reason", "diagnostic"), name -> {
                    switch (name) {
                        case "startAddress" -> bounds[0] = address();
                        case "endAddress" -> bounds[1] = address();
                        default -> text(true);
                    }
                });
            if (bounds[0] < 0 || bounds[1] <= bounds[0]) {
                throw invalid("invalid omitted-location range");
            }
        }

        private long address() throws IOException {
            String value = text(true);
            if (!value.matches("0x(?:0|[1-9a-f][0-9a-f]{0,15})")) {
                throw invalid("invalid report address spelling");
            }
            return Long.parseUnsignedLong(value.substring(2), 16);
        }

        private void textObject(String description, Set<String> fields) throws IOException {
            object(description, fields, ignored -> text(true));
        }

        private void object(String description, Set<String> fields, FieldReader reader) throws IOException {
            value(JsonToken.BEGIN_OBJECT);
            json.beginObject();
            Set<String> seen = new HashSet<>();
            while (json.hasNext()) {
                ReportJsonReader.checkCancelled(cancelled);
                String name = json.nextName();
                if (!fields.contains(name)) {
                    throw invalid("unknown field in " + description);
                }
                if (!seen.add(name)) {
                    throw invalid("duplicate decoded field in " + description);
                }
                reader.read(name);
            }
            json.endObject();
            if (!seen.equals(fields)) {
                Set<String> missing = new HashSet<>(fields);
                missing.removeAll(seen);
                if (description.equals("counts") && missing.equals(Set.of("functionStaticVariables"))) {
                    throw new UnsupportedReportShapeException(
                        "unsupported historical schema-one report shape: counts.functionStaticVariables is required");
                }
                throw invalid("missing field in " + description);
            }
        }

        private int array(ValueReader reader) throws IOException {
            value(JsonToken.BEGIN_ARRAY);
            json.beginArray();
            int count = 0;
            while (json.hasNext()) {
                if (count == limits.arrayItems()) {
                    throw invalid("array exceeds safety limit " + limits.arrayItems());
                }
                count++;
                reader.read();
            }
            json.endArray();
            return count;
        }

        private <T> T nullable(NullableReader<T> reader) throws IOException {
            if (json.peek() == JsonToken.NULL) {
                value(JsonToken.NULL);
                json.nextNull();
                return null;
            }
            return reader.read();
        }

        private String text(boolean nonblank) throws IOException {
            value(JsonToken.STRING);
            String text = json.nextString();
            if (nonblank && text.isBlank()) {
                throw invalid("required report text is blank");
            }
            return text;
        }

        private int integer() throws IOException {
            value(JsonToken.NUMBER);
            String spelling = json.nextString();
            if (!spelling.matches("0|[1-9][0-9]{0,9}")) {
                throw invalid("expected canonical nonnegative report integer");
            }
            try {
                return Integer.parseInt(spelling);
            }
            catch (NumberFormatException overflow) {
                throw new IOException("report integer exceeds signed 32-bit range", overflow);
            }
        }

        private void value(JsonToken expected) throws IOException {
            ReportJsonReader.checkCancelled(cancelled);
            if (values == limits.values()) {
                throw invalid("value count exceeds safety limit " + limits.values());
            }
            values++;
            if (json.peek() != expected) {
                throw invalid("expected " + expected + " report value");
            }
        }

        private static IOException invalid(String detail) {
            return new IOException("invalid export report: " + detail);
        }

        @FunctionalInterface
        private interface FieldReader {
            void read(String name) throws IOException;
        }

        @FunctionalInterface
        private interface ValueReader {
            void read() throws IOException;
        }

        @FunctionalInterface
        private interface NullableReader<T> {
            T read() throws IOException;
        }
    }
}

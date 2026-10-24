package ghidradwarfforge.output;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Writer-derived schema controls and bounded, native-free reader fault injection. */
public final class ExportReportClaimsSmoke {
    private static final Path SUPPLIED = Path.of("unopened/alias/../report.json");
    private static final ReportJsonReader.Limits LIMITS = ReportJsonReader.DEFAULT_LIMITS;
    private static int rejected;

    private ExportReportClaimsSmoke() {
    }

    public static void main(String[] args) throws Exception {
        JsonObject success = json(ExportReportClaimsFixtures.completed(false));
        JsonObject partial = json(ExportReportClaimsFixtures.completed(true));
        writerFixtures(success, partial);
        objectFields(partial);
        scalarContracts(success, partial);
        lexicalControls(success);
        budgets(success);
        resources(success);
        actualFile(success);
        System.out.println("export-report-claims-smoke=PASS rejected-controls=" + rejected);
    }

    private static JsonObject json(ExportReport report) {
        return JsonParser.parseString(report.toJson()).getAsJsonObject();
    }

    private static void writerFixtures(JsonObject success, JsonObject partial) throws Exception {
        for (JsonObject document : List.of(success, partial)) {
            String text = document.toString();
            require(parse(ExportReportClaimsFixtures.completed(document == partial).toJson()).equals(parse(text)),
                "actual writer formatting changed parsed claims");
            for (int chunk : new int[] { 1, 2, 3, 7, 1024, 8192 }) {
                TrackingInput input = new TrackingInput(bytes(text), chunk);
                ExportReportClaims claims = read(input, LIMITS);
                require(input.closed == 1 && input.eof, "completed read must close at EOF");
                require(claims.schemaVersion() == 1 && claims.status().name().equals(document.get("status").getAsString()),
                    "writer status/schema changed");
                require(claims.counts().functionsExported() == 99 && claims.counts().functionsDecompiled() == 1,
                    "reader invented a relationship between independent counts");
                require(claims.validationStatus() == ExportReport.ValidationStatus.NOT_RUN &&
                    claims.libdwarfVersion().equals("reported version"), "reported status/version changed");
                require(claims.artifacts().inputSha256().equals("A".repeat(64)) &&
                    claims.artifacts().inputPath().equals(document.getAsJsonObject("artifacts").get("inputPath").getAsString()),
                    "hash or path spelling changed");
                require(claims.target().addressBits() == 64 && claims.target().architecture().equals("x86_64"),
                    "target claim changed");
            }
            require(parse(reverse(document).toString()).equals(parse(text)), "object ordering affected claims");
        }
        require(partial.getAsJsonArray("failedFunctions").get(0).getAsJsonObject()
            .get("address").getAsString().equals("0x8000000000000000"), "unsigned address control is vacuous");
        require(partial.getAsJsonArray("sections").get(0).getAsString().isEmpty(), "empty section control missing");
        for (ExportReport.Status status : List.of(ExportReport.Status.CANCELLED, ExportReport.Status.FATAL)) {
            JsonObject terminal = json(ExportReportClaimsFixtures.terminal(status));
            var failure = expect(ExportReportClaims.TerminalReportException.class, () -> parse(terminal.toString()));
            require(failure.status() == status, "terminal status lost");
            for (String name : List.of("target", "artifacts", "counts", "native")) {
                JsonObject bad = terminal.deepCopy();
                bad.add(name, success.get(name));
                reject(bad.toString());
            }
            for (String name : List.of("sections", "failedFunctions", "skippedFunctions",
                    "omittedLocations", "unsupportedConstructs", "diagnostics")) {
                JsonObject bad = terminal.deepCopy();
                JsonArray nonempty = partial.getAsJsonArray(name).deepCopy();
                require(nonempty.size() > 0, "terminal inventory control is empty");
                bad.add(name, nonempty);
                reject(bad.toString());
            }
            JsonObject noFailure = terminal.deepCopy();
            noFailure.add("failure", JsonNull.INSTANCE);
            reject(noFailure.toString());
            checkObject(terminal, List.of("failure"));
        }
        JsonObject historical = success.deepCopy();
        historical.getAsJsonObject("counts").remove("functionStaticVariables");
        expect(ExportReportClaims.UnsupportedReportShapeException.class, () -> parse(historical.toString()));
        JsonObject version = success.deepCopy();
        version.addProperty("schemaVersion", 2);
        expect(ExportReportClaims.UnsupportedReportShapeException.class, () -> parse(version.toString()));
    }

    private static JsonElement reverse(JsonElement element) {
        if (element.isJsonObject()) {
            JsonObject result = new JsonObject();
            List<String> keys = new ArrayList<>(element.getAsJsonObject().keySet());
            Collections.reverse(keys);
            for (String key : keys) {
                result.add(key, reverse(element.getAsJsonObject().get(key)));
            }
            return result;
        }
        if (element.isJsonArray()) {
            JsonArray result = new JsonArray();
            for (JsonElement value : element.getAsJsonArray()) {
                result.add(reverse(value));
            }
            return result;
        }
        return element.deepCopy();
    }

    private static void objectFields(JsonObject partial) throws Exception {
        for (List<String> path : List.of(List.<String>of(), List.of("target"), List.of("artifacts"),
                List.of("counts"), List.of("validation"), List.of("native"), List.of("failedFunctions", "0"),
                List.of("skippedFunctions", "0"), List.of("omittedLocations", "0"),
                List.of("unsupportedConstructs", "0"))) {
            checkObject(partial, path);
        }
    }

    private static JsonObject at(JsonObject document, List<String> path) {
        JsonElement current = document;
        for (String part : path) {
            current = current.isJsonArray() ? current.getAsJsonArray().get(Integer.parseInt(part))
                : current.getAsJsonObject().get(part);
        }
        return current.getAsJsonObject();
    }

    private static void checkObject(JsonObject document, List<String> path) throws Exception {
        JsonObject object = at(document, path);
        for (String key : object.keySet()) {
            JsonObject missing = document.deepCopy();
            at(missing, path).remove(key);
            if (path.equals(List.of("counts")) && key.equals("functionStaticVariables")) {
                expect(ExportReportClaims.UnsupportedReportShapeException.class, () -> parse(missing.toString()));
            }
            else {
                reject(missing.toString());
            }
            String quoted = new JsonPrimitive(key).toString();
            String escaped = "\"\\u" + String.format("%04x", (int) key.charAt(0)) + key.substring(1) + "\"";
            for (String duplicate : List.of(quoted, escaped)) {
                String old = object.toString();
                String replacement = old.substring(0, old.length() - 1) + "," + duplicate + ":" + object.get(key) + "}";
                String all = document.toString();
                require(all.indexOf(old) == all.lastIndexOf(old), "duplicate-key mutation is ambiguous");
                reject(all.replace(old, replacement));
            }
            JsonObject wrongType = document.deepCopy();
            JsonElement original = object.get(key);
            JsonElement bad = original.isJsonArray() || original.isJsonObject()
                ? new JsonPrimitive("wrong type") : new JsonArray();
            at(wrongType, path).add(key, bad);
            reject(wrongType.toString());
            if (!original.isJsonNull()) {
                JsonObject nullField = document.deepCopy();
                at(nullField, path).add(key, JsonNull.INSTANCE);
                reject(nullField.toString());
            }
            if (original.isJsonPrimitive() && original.getAsJsonPrimitive().isString()) {
                JsonObject blank = document.deepCopy();
                at(blank, path).addProperty(key, " \t\n");
                reject(blank.toString());
            }
        }
        JsonObject unknown = document.deepCopy();
        at(unknown, path).addProperty("unknown", "not ignored");
        reject(unknown.toString());
    }

    private static void scalarContracts(JsonObject success, JsonObject partial) throws Exception {
        for (String field : List.of("functionsFailed", "functionsSkipped", "omittedLocationRanges",
                "unsupportedConstructs", "diagnostics")) {
            JsonObject bad = partial.deepCopy();
            bad.getAsJsonObject("counts").addProperty(field, 0);
            reject(bad.toString());
        }
        for (JsonObject document : List.of(success, partial)) {
            JsonObject bad = document.deepCopy();
            bad.addProperty("status", document == success ? "PARTIAL" : "SUCCESS");
            reject(bad.toString());
        }
        for (String name : List.of("target", "artifacts", "counts")) {
            JsonObject bad = success.deepCopy();
            bad.add(name, JsonNull.INSTANCE);
            reject(bad.toString());
        }
        JsonObject badFailure = success.deepCopy();
        badFailure.add("failure", json(ExportReportClaimsFixtures.terminal(ExportReport.Status.FATAL)).get("failure"));
        reject(badFailure.toString());
        for (String number : List.of("-1", "-0", "+1", "01", "1.0", "1e0", "2147483648",
                "12345678901", "true", "false", "null", "\"1\"")) {
            reject(success.toString().replace("\"functionsExported\":99", "\"functionsExported\":" + number));
        }
        for (String hash : List.of("a".repeat(63), "a".repeat(65), "g".repeat(64), "")) {
            JsonObject bad = success.deepCopy();
            bad.getAsJsonObject("artifacts").addProperty("inputSha256", hash);
            reject(bad.toString());
        }
        for (String address : List.of("0X1000", "0x01000", "0xA", "-1", "0x10000000000000000")) {
            JsonObject bad = partial.deepCopy();
            bad.getAsJsonArray("failedFunctions").get(0).getAsJsonObject().addProperty("address", address);
            reject(bad.toString());
        }
        for (String end : List.of("0x1000", "0xfff", "0x8000000000000000")) {
            JsonObject bad = partial.deepCopy();
            bad.getAsJsonArray("omittedLocations").get(0).getAsJsonObject().addProperty("endAddress", end);
            reject(bad.toString());
        }
        for (String field : List.of("architecture", "byteOrder")) {
            JsonObject bad = success.deepCopy();
            bad.getAsJsonObject("target").addProperty(field, " ");
            reject(bad.toString());
        }
        for (String status : List.of("success", "UNKNOWN", "")) {
            JsonObject bad = success.deepCopy();
            bad.addProperty("status", status);
            reject(bad.toString());
        }
        JsonObject validated = success.deepCopy();
        validated.getAsJsonObject("validation").addProperty("status", "PASS");
        reject(validated.toString());
        JsonObject opaque = success.deepCopy();
        opaque.getAsJsonObject("target").addProperty("architecture", "unrecognized reported profile");
        opaque.getAsJsonObject("artifacts").addProperty("inputPath", "C:\\missing\\..\\foreign\u0000path");
        require(parse(opaque.toString()).artifacts().inputPath().equals("C:\\missing\\..\\foreign\u0000path"),
            "opaque foreign path was interpreted locally");
    }

    private static String rawPath(JsonObject document, String rawContents) {
        JsonObject copy = document.deepCopy();
        copy.getAsJsonObject("artifacts").addProperty("inputPath", "STRING_MARKER");
        return copy.toString().replace("STRING_MARKER", rawContents);
    }

    private static void lexicalControls(JsonObject success) throws Exception {
        String text = success.toString();
        for (String bad : List.of("\ufeff" + text, text + "{}", text + "null", "/*comment*/" + text,
                text + "\u000b", text + "\u00a0", text.replace("null", "NULL"), text.replace("null", "nUlL"),
                text.substring(0, text.length() - 1), "", "[]", "null")) {
            reject(bad);
        }
        for (String bad : List.of("raw\nnewline", "raw\tcontrol", "raw\u0000zero", "\\'", "\\x41",
                "escaped\\\nnewline", "\\uD800", "\\uDC00", "\\uD800x", "\\uD800\\u0041",
                "\\u12xz", "\\u１２３４")) {
            reject(rawPath(success, bad));
        }
        for (String good : List.of("literal 😀", "escaped \\uD83D\\uDE00", "escaped \\/\\b\\f\\n\\r\\t",
                "interior\ufeffBOM", "\\u0000inside", "quote\\\"slash\\\\")) {
            parse(" \t\n\r" + rawPath(success, good) + " \t\n\r");
        }
        byte[] valid = bytes(rawPath(success, "UTF8_MARKER"));
        int marker = new String(valid, StandardCharsets.UTF_8).indexOf("UTF8_MARKER");
        for (byte[] invalid : List.of(new byte[] { (byte) 0xc0, (byte) 0x80 },
                new byte[] { (byte) 0xed, (byte) 0xa0, (byte) 0x80 },
                new byte[] { (byte) 0xf4, (byte) 0x90, (byte) 0x80, (byte) 0x80 },
                new byte[] { (byte) 0x80 })) {
            byte[] malformed = new byte[valid.length - 11 + invalid.length];
            System.arraycopy(valid, 0, malformed, 0, marker);
            System.arraycopy(invalid, 0, malformed, marker, invalid.length);
            System.arraycopy(valid, marker + 11, malformed, marker + invalid.length, valid.length - marker - 11);
            reject(malformed);
        }
    }

    private static void budgets(JsonObject success) throws Exception {
        require(LIMITS.equals(new ReportJsonReader.Limits(64L * 1024 * 1024, 65536, 8, 1_000_000, 250000)),
            "public safety limits changed without boundary review");
        parse(rawPath(success, "x".repeat(65536)));
        reject(rawPath(success, "x".repeat(65537)));
        parse(rawPath(success, "\\u0061".repeat(65536)));
        reject(rawPath(success, "\\u0061".repeat(65537)));
        JsonObject many = success.deepCopy();
        many.addProperty("status", "PARTIAL");
        many.getAsJsonObject("counts").addProperty("diagnostics", 250000);
        String document = many.toString().replace("\"diagnostics\":[]", "\"diagnostics\":[" + "\"d\",".repeat(249999) + "\"d\"]");
        require(parse(document).counts().diagnostics() == 250000, "exact array limit rejected");
        reject(document.replace("\"diagnostics\":250000", "\"diagnostics\":250001")
            .replace("\"diagnostics\":[", "\"diagnostics\":[\"d\","));
        byte[] shortReport = bytes(success.toString());
        for (long total : new long[] { LIMITS.bytes(), LIMITS.bytes() + 1 }) {
            PaddedInput input = new PaddedInput(shortReport, total);
            if (total == LIMITS.bytes()) {
                read(input, LIMITS);
            }
            else {
                expect(IOException.class, () -> read(input, LIMITS));
            }
            require(input.closed == 1, "byte-limit path leaked input");
        }
        int values = countValues(success);
        read(new TrackingInput(shortReport, 7), limits(values, LIMITS.depth()));
        expect(IOException.class, () -> read(new TrackingInput(shortReport, 7), limits(values - 1, LIMITS.depth())));
        millionValueBoundary(success, values);
        for (int depth : new int[] { 8, 9 }) {
            TrackingInput input = new TrackingInput(bytes("[".repeat(depth) + "0" + "]".repeat(depth)), 1);
            try (ReportJsonReader guard = new ReportJsonReader(input, () -> false, LIMITS)) {
                if (depth == 8) {
                    while (guard.read() != -1) { }
                }
                else {
                    expect(IOException.class, () -> { while (guard.read() != -1) { } });
                }
            }
            require(input.closed == 1, "depth-limit path leaked input");
        }
    }

    private static void millionValueBoundary(JsonObject success, int baseValues) throws Exception {
        // Each skipped object adds its object plus two scalar values. Stream
        // repeated records instead of retaining their million-value object tree.
        int skips = 249999;
        int diagnostics = LIMITS.values() - baseValues - skips * 3;
        require(diagnostics > 0 && diagnostics < LIMITS.arrayItems(), "value-bound control is not representable");
        for (int extra : new int[] { 0, 1 }) {
            JsonObject fixture = success.deepCopy();
            fixture.addProperty("status", "PARTIAL");
            fixture.getAsJsonObject("counts").addProperty("functionsSkipped", skips);
            fixture.getAsJsonObject("counts").addProperty("diagnostics", diagnostics + extra);
            String text = fixture.toString().replace("\"skippedFunctions\":[]", "\"skippedFunctions\":[SKIPPED_MARKER]")
                .replace("\"diagnostics\":[]", "\"diagnostics\":[DIAGNOSTICS_MARKER]");
            String[] skipParts = text.split("SKIPPED_MARKER", -1);
            String[] diagnosticParts = skipParts[1].split("DIAGNOSTICS_MARKER", -1);
            require(skipParts.length == 2 && diagnosticParts.length == 2, "streaming value control is malformed");
            List<InputStream> parts = List.of(new ByteArrayInputStream(bytes(skipParts[0])),
                new RepeatedInput(bytes("{\"name\":\"s\",\"reason\":\"r\"},"), skips - 1),
                new ByteArrayInputStream(bytes("{\"name\":\"s\",\"reason\":\"r\"}" + diagnosticParts[0])),
                new RepeatedInput(bytes("\"d\","), diagnostics + extra - 1),
                new ByteArrayInputStream(bytes("\"d\"" + diagnosticParts[1])));
            try (InputStream input = new java.io.SequenceInputStream(Collections.enumeration(parts))) {
                if (extra == 0) {
                    require(read(input, LIMITS).counts().diagnostics() == diagnostics, "exact value limit rejected");
                }
                else {
                    expect(IOException.class, () -> read(input, LIMITS));
                }
            }
        }
    }

    private static int countValues(JsonElement element) {
        int count = 1;
        if (element.isJsonArray()) {
            for (JsonElement value : element.getAsJsonArray()) {
                count += countValues(value);
            }
        }
        else if (element.isJsonObject()) {
            for (var entry : element.getAsJsonObject().entrySet()) {
                count += countValues(entry.getValue());
            }
        }
        return count;
    }

    private static ReportJsonReader.Limits limits(int values, int depth) {
        return new ReportJsonReader.Limits(LIMITS.bytes(), LIMITS.stringUnits(), depth, values, LIMITS.arrayItems());
    }

    private static void resources(JsonObject success) throws Exception {
        byte[] document = bytes(success.toString());
        AtomicInteger opens = new AtomicInteger();
        expect(CancellationException.class, () -> ExportReportClaims.read(SUPPLIED, () -> true,
            path -> { opens.incrementAndGet(); throw new AssertionError("cancelled input opened"); }, LIMITS));
        require(opens.get() == 0, "cancel-before-open reached filesystem");
        for (boolean afterEof : new boolean[] { false, true }) {
            TrackingInput input = new TrackingInput(document, 3);
            expect(CancellationException.class, () -> ExportReportClaims.read(SUPPLIED,
                () -> afterEof ? input.eof : input.position > 5, path -> input, LIMITS));
            require(input.closed == 1 && (!afterEof || input.eof), "cancelled stream leaked or wrong checkpoint");
        }
        IOException openFailure = new IOException("open sentinel");
        require(expect(IOException.class, () -> ExportReportClaims.read(SUPPLIED, () -> false,
            path -> { throw openFailure; }, LIMITS)) == openFailure, "open failure identity lost");
        TrackingInput cancelledWithClose = new TrackingInput(document, 1);
        IOException cancelledClose = new IOException("cancel close sentinel");
        cancelledWithClose.closeFailure = cancelledClose;
        CancellationException cancellation = expect(CancellationException.class, () -> ExportReportClaims.read(SUPPLIED,
            () -> cancelledWithClose.position > 1, path -> cancelledWithClose, LIMITS));
        require(cancelledWithClose.closed == 1 && Arrays.equals(cancellation.getSuppressed(), new Throwable[] { cancelledClose }),
            "cancellation did not retain suppressed close failure");
        TrackingInput supplier = new TrackingInput(document, 1);
        RuntimeException supplierFailure = new IllegalStateException("supplier sentinel");
        require(expect(IllegalStateException.class, () -> ExportReportClaims.read(SUPPLIED,
            () -> { if (supplier.position > 3) { throw supplierFailure; } return false; }, path -> supplier, LIMITS))
            == supplierFailure && supplier.closed == 1, "supplier failure/closure lost");
        for (boolean failRead : new boolean[] { false, true }) {
            TrackingInput input = new TrackingInput(document, 7);
            IOException primary = new IOException("read sentinel");
            IOException close = new IOException("close sentinel");
            input.readFailure = failRead ? primary : null;
            input.closeFailure = close;
            IOException result = expect(IOException.class, () -> read(input, LIMITS));
            require(input.closed == 1, "exception path did not close");
            require(failRead ? result == primary && Arrays.equals(result.getSuppressed(), new Throwable[] { close })
                : result == close, "primary/suppressed I/O failures changed");
        }
        for (int invalidRead : new int[] { 0, -2, 9000 }) {
            TrackingInput input = new TrackingInput(document, 7);
            input.invalidRead = invalidRead;
            expect(IOException.class, () -> read(input, LIMITS));
            require(input.closed == 1, "invalid-read path leaked input");
        }
    }

    private static void actualFile(JsonObject success) throws Exception {
        Path directory = Files.createTempDirectory("forge-report-claims-");
        Path report = directory.resolve("report.json");
        Path sentinel = directory.resolve("opaque-artifact");
        try {
            Files.writeString(sentinel, "unchanged artifact");
            JsonObject fixture = success.deepCopy();
            fixture.getAsJsonObject("artifacts").addProperty("inputPath", sentinel.toString());
            fixture.getAsJsonObject("artifacts").addProperty("outputPath", directory.resolve("missing").toString());
            byte[] content = bytes(fixture.toString());
            Files.write(report, content);
            var reportTime = Files.getLastModifiedTime(report);
            var sentinelTime = Files.getLastModifiedTime(sentinel);
            require(ExportReportClaims.read(report).equals(ExportReportClaims.read(report, () -> false)),
                "public overloads disagree");
            expect(CancellationException.class, () -> ExportReportClaims.read(report, () -> true));
            require(Arrays.equals(content, Files.readAllBytes(report)) && Files.getLastModifiedTime(report).equals(reportTime),
                "report bytes or mtime changed");
            require(Files.readString(sentinel).equals("unchanged artifact") && Files.getLastModifiedTime(sentinel).equals(sentinelTime)
                && !Files.exists(directory.resolve("missing")), "referenced artifacts changed");
        }
        finally {
            Files.deleteIfExists(report);
            Files.deleteIfExists(sentinel);
            Files.delete(directory);
        }
    }

    private static ExportReportClaims parse(String json) throws Exception {
        return read(new TrackingInput(bytes(json), 7), LIMITS);
    }

    private static ExportReportClaims read(InputStream input, ReportJsonReader.Limits limits) throws IOException {
        return ExportReportClaims.read(SUPPLIED, () -> false, path -> {
            require(path == SUPPLIED, "supplied report Path was rewritten");
            return input;
        }, limits);
    }

    private static void reject(String json) throws Exception {
        reject(bytes(json));
    }

    private static void reject(byte[] json) throws Exception {
        TrackingInput input = new TrackingInput(json, 3);
        IOException error = expect(IOException.class, () -> read(input, LIMITS));
        require(!(error instanceof ExportReportClaims.TerminalReportException) &&
            !(error instanceof ExportReportClaims.UnsupportedReportShapeException),
            "malformed fixture was mistaken for a valid terminal/historical report");
        require(input.closed == 1, "rejected stream leaked");
        rejected++;
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static <T extends Throwable> T expect(Class<T> type, Action action) throws Exception {
        try {
            action.run();
        }
        catch (Throwable failure) {
            if (type.isInstance(failure)) {
                return type.cast(failure);
            }
            throw new AssertionError("expected " + type.getName() + ", got " + failure, failure);
        }
        throw new AssertionError("expected " + type.getName());
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    @FunctionalInterface
    private interface Action {
        void run() throws Exception;
    }

    private static final class TrackingInput extends InputStream {
        private final ByteArrayInputStream input;
        private final int chunk;
        private int position;
        private int closed;
        private boolean eof;
        private IOException readFailure;
        private IOException closeFailure;
        private Integer invalidRead;

        private TrackingInput(byte[] data, int chunk) {
            input = new ByteArrayInputStream(data);
            this.chunk = chunk;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) throws IOException {
            if (readFailure != null) {
                throw readFailure;
            }
            if (invalidRead != null) {
                return invalidRead;
            }
            int count = input.read(buffer, offset, Math.min(length, chunk));
            eof |= count == -1;
            if (count > 0) {
                position += count;
            }
            return count;
        }

        @Override
        public int read() throws IOException {
            byte[] single = new byte[1];
            return read(single, 0, 1) == -1 ? -1 : single[0] & 255;
        }

        @Override
        public void close() throws IOException {
            closed++;
            if (closeFailure != null) {
                throw closeFailure;
            }
            input.close();
        }
    }

    private static final class RepeatedInput extends InputStream {
        private final byte[] unit;
        private final long size;
        private long position;

        private RepeatedInput(byte[] unit, int repeats) {
            this.unit = unit;
            size = (long) unit.length * repeats;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (position == size) {
                return -1;
            }
            int count = (int) Math.min(length, size - position);
            for (int index = 0; index < count; index++, position++) {
                buffer[offset + index] = unit[(int) (position % unit.length)];
            }
            return count;
        }

        @Override
        public int read() {
            return position == size ? -1 : unit[(int) (position++ % unit.length)] & 255;
        }
    }

    /** Large actual byte-limit control without allocating a large byte array. */
    private static final class PaddedInput extends InputStream {
        private final byte[] prefix;
        private final long total;
        private long position;
        private int closed;

        private PaddedInput(byte[] prefix, long total) {
            this.prefix = prefix;
            this.total = total;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (position == total) {
                return -1;
            }
            int count = (int) Math.min(length, total - position);
            for (int index = 0; index < count; index++, position++) {
                buffer[offset + index] = position < prefix.length ? prefix[(int) position] : (byte) ' ';
            }
            return count;
        }

        @Override
        public int read() {
            if (position == total) {
                return -1;
            }
            return position < prefix.length ? prefix[(int) position++] & 255 : pad();
        }

        private int pad() {
            position++;
            return ' ';
        }

        @Override
        public void close() {
            closed++;
        }
    }
}

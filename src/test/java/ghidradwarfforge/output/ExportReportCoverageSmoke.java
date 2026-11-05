package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/** Schema migration must preserve old receipts and validate coverage in every reader path. */
public final class ExportReportCoverageSmoke {
    private static final Path UNOPENED = Path.of("unopened/report.json");
    private static final ReportJsonReader.Limits LIMITS = ReportJsonReader.DEFAULT_LIMITS;
    private static int rejected;
    private record ReadResult(ExportReportClaims claims, CoverageReportClaims coverage) { }

    public static void main(String[] args) throws Exception {
        var profile = new CoverageReportJson.Profile("x86:LE:64:default", "gcc");
        var evidence = CoverageReportClaimsSmoke.knownFixture();
        var coverageClaims = new CoverageReportClaims(profile, evidence);
        String payload = CoverageReportJson.write(evidence, profile, () -> false);
        for (boolean partial : List.of(false, true)) {
            String legacy = ExportReportClaimsFixtures.completed(partial).toJson();
            var old = read(legacy, 2, LIMITS, () -> false);
            require(old.coverage() == null && old.claims().schemaVersion() == 1, "legacy coverage must be unavailable");
            require(legacy.equals(ExportReportClaimsFixtures.completed(partial).toJson()), "legacy writer bytes changed");
            var report = JsonParser.parseString(legacy).getAsJsonObject();
            report.addProperty("schemaVersion", 2);
            report.getAsJsonObject("counts").addProperty("functionsExported", 1);
            report.add("coverage", JsonParser.parseString(payload));
            String text = report.toString();
            var writer = ExportReportClaimsFixtures.completed(partial, 1);
            String written = writer.toJsonWithCoverage(coverageClaims, () -> false);
            require(JsonParser.parseString(written).equals(report), "versioned writer changed base fields or coverage");
            require(written.equals(writer.toJsonWithCoverage(coverageClaims, () -> false)), "nondeterministic schema two");
            var claims = read(text, 2, LIMITS, () -> false);
            require(claims.claims().schemaVersion() == 2 && claims.coverage().profile().equals(profile) &&
                claims.coverage().coverage().equals(evidence), "schema two dropped claims");
            for (int mode = 0; mode < 3; mode++) {
                require(read(text, mode, LIMITS, () -> false).claims().equals(claims.claims()), "reader paths disagree");
                require(read(reverse(report).toString(), mode, LIMITS, () -> false).claims().equals(claims.claims()), "field-order dependence");
            }
            int values = values(report);
            int bytes = text.getBytes(StandardCharsets.UTF_8).length;
            read(text, 2, limits(bytes, values, 8), () -> false);
            rejectAll(text, limits(bytes - 1, values, 8));
            rejectAll(text, limits(bytes, values - 1, 8));
            rejectAll(text, limits(bytes, values, 4));
            for (var budget : List.of(limits(written.getBytes(StandardCharsets.UTF_8).length - 1, values, 8),
                    limits(LIMITS.bytes(), values - 1, 8), limits(LIMITS.bytes(), values, 4))) {
                try { writer.toJsonWithCoverage(coverageClaims, () -> false, budget); throw new AssertionError("writer skipped complete document preflight"); }
                catch (IOException expected) { rejected++; }
            }
            try { ExportReportClaimsFixtures.completed(partial).toJsonWithCoverage(coverageClaims, () -> false); throw new AssertionError("writer accepted different function populations"); }
            catch (IOException expected) { rejected++; }
            var bad = report.deepCopy();
            bad.remove("coverage");
            rejectAll(bad.toString(), LIMITS);
            bad = report.deepCopy();
            bad.add("coverage", JsonNull.INSTANCE);
            rejectAll(bad.toString(), LIMITS);
            bad = report.deepCopy();
            bad.addProperty("schemaVersion", 1);
            rejectAll(bad.toString(), LIMITS);
            bad.add("coverage", JsonNull.INSTANCE);
            rejectAll(bad.toString(), LIMITS);
            bad = report.deepCopy();
            bad.addProperty("schemaVersion", 3);
            rejectAll(bad.toString(), LIMITS);
            bad = report.deepCopy();
            bad.getAsJsonObject("counts").addProperty("functionsExported", 2);
            rejectAll(bad.toString(), LIMITS);
            bad = report.deepCopy();
            bad.getAsJsonObject("coverage").getAsJsonObject("summary").getAsJsonObject("source")
                .addProperty("anchoredInstructions", "0");
            rejectAll(bad.toString(), LIMITS);
            bad = report.deepCopy();
            bad.getAsJsonObject("counts").remove("functionStaticVariables");
            rejectAll(bad.toString(), LIMITS);
            rejectAll(text.replace("\"coverage\":", "\"coverage\":null,\"coverage\":"), LIMITS);
            rejectAll(text.replace("\"coverage\":", "\"cove\\u0072age\":null,\"coverage\":"), LIMITS);
            rejectAll(text + "{}", LIMITS);
            // A structurally coherent alteration is still just a claim, never verification authority.
            bad = report.deepCopy();
            bad.getAsJsonObject("coverage").getAsJsonArray("functions").get(0).getAsJsonObject()
                .getAsJsonObject("source").getAsJsonArray("anchoredStarts").set(0, new com.google.gson.JsonPrimitive("0x64"));
            var changed = read(bad.toString(), 2, LIMITS, () -> false);
            require(changed.claims().equals(claims.claims()) && !changed.coverage().equals(claims.coverage()),
                "coverage changed independent artifact claims");
            require(changed.claims().validationStatus() == ExportReport.ValidationStatus.NOT_RUN, "invented validation");
            AtomicInteger checks = new AtomicInteger();
            read(text, 2, LIMITS, () -> { checks.incrementAndGet(); return false; });
            int total = checks.get();
            for (int sample = 1; sample <= 64; sample++) {
                int stop = Math.max(1, (int) ((long) total * sample / 64));
                checks.set(0);
                try { read(text, 2, LIMITS, () -> checks.incrementAndGet() >= stop); throw new AssertionError("cancellation ignored"); }
                catch (CancellationException expected) { }
            }
            checks.set(0);
            writer.toJsonWithCoverage(coverageClaims, () -> { checks.incrementAndGet(); return false; });
            int writerTotal = checks.get();
            for (int sample = 1; sample <= 64; sample++) {
                int stop = Math.max(1, (int) ((long) writerTotal * sample / 64));
                checks.set(0);
                try { writer.toJsonWithCoverage(coverageClaims, () -> checks.incrementAndGet() >= stop); throw new AssertionError("writer cancellation ignored"); }
                catch (CancellationException expected) { }
            }
        }
        for (var status : List.of(ExportReport.Status.CANCELLED, ExportReport.Status.FATAL)) {
            var terminal = JsonParser.parseString(ExportReportClaimsFixtures.terminal(status).toJson()).getAsJsonObject();
            terminal.addProperty("schemaVersion", 2);
            terminal.add("coverage", JsonNull.INSTANCE);
            require(JsonParser.parseString(ExportReportClaimsFixtures.terminal(status).toJsonWithCoverage(null, () -> false)).equals(terminal),
                "terminal writer changed claims");
            for (int mode = 0; mode < 3; mode++) {
                try { read(terminal.toString(), mode, LIMITS, () -> false); throw new AssertionError("terminal returned claims"); }
                catch (ExportReportClaims.TerminalReportException expected) { require(expected.status() == status, "terminal status changed"); }
            }
            terminal.add("coverage", JsonParser.parseString(payload));
            rejectAll(terminal.toString(), LIMITS);
        }
        bindingControls(payload);
        System.out.println("export-report-coverage=PASS rejected=" + rejected + " sampled-cancellations=256");
    }

    private static void bindingControls(String payload) throws Exception {
        Path directory = Files.createTempDirectory("forge-coverage-binding-");
        try {
            var pair = ExportArtifactHashBindingFixtures.create(directory, true);
            var legacy = ExportArtifactHashBinding.observe(pair.report(), pair.original(), pair.sidecar(), pair.source());
            var document = ExportArtifactHashBindingFixtures.report(pair);
            document.addProperty("schemaVersion", 2);
            document.getAsJsonObject("counts").addProperty("functionsExported", 1);
            document.add("coverage", JsonParser.parseString(payload));
            Files.writeString(pair.report(), document.toString(), StandardCharsets.UTF_8);
            var before = pair.all().stream().map(path -> {
                try { return ExportArtifactHashBindingFixtures.hash(path); }
                catch (Exception failure) { throw new AssertionError(failure); }
            }).toList();
            var observed = ExportArtifactHashBinding.observeDetailed(pair.report(), pair.original(), pair.sidecar(), pair.source());
            require(observed.binding().original().equals(legacy.original()) && observed.binding().sidecar().equals(legacy.sidecar()) &&
                observed.binding().source().equals(legacy.source()), "coverage altered selected-byte observations");
            require(observed.binding().claims().status() == ExportReport.Status.PARTIAL &&
                observed.binding().claims().validationStatus() == ExportReport.ValidationStatus.NOT_RUN, "coverage upgraded attachment authority");
            for (int i = 0; i < pair.all().size(); i++) {
                require(ExportArtifactHashBindingFixtures.hash(pair.all().get(i)).equals(before.get(i)), "reader modified files");
            }
            Files.writeString(pair.sidecar(), "changed sidecar", StandardCharsets.UTF_8);
            var changed = ExportArtifactHashBinding.observe(pair.report(), pair.original(), pair.sidecar(), pair.source());
            require(changed.sidecar().agreement() == ExportArtifactHashBinding.Agreement.DIFFERENT_REPORTED_SHA256,
                "coverage concealed changed artifact bytes");
            document.getAsJsonObject("coverage").getAsJsonObject("summary").addProperty("functions", "99");
            Files.writeString(pair.report(), document.toString(), StandardCharsets.UTF_8);
            Files.delete(pair.original());
            try {
                ExportArtifactHashBinding.observe(pair.report(), pair.original(), pair.sidecar(), pair.source());
                throw new AssertionError("binding accepted invalid coverage");
            }
            catch (java.nio.file.NoSuchFileException wrongOrder) { throw new AssertionError("artifact inspected before complete report validation", wrongOrder); }
            catch (IOException expected) { rejected++; }
        }
        finally {
            try (var paths = Files.walk(directory)) {
                for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    /** Modes exercise lightweight, diagnostic-retaining, and coverage-retaining paths. */
    private static ReadResult read(String text, int mode, ReportJsonReader.Limits limits,
            BooleanSupplier cancelled) throws IOException {
        var input = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)) {
            private boolean closed;
            @Override public void close() throws IOException { closed = true; super.close(); }
        };
        try {
            if (mode == 2) {
                var result = ExportReportClaims.readWithCoverage(UNOPENED, cancelled, path -> input, limits);
                return new ReadResult(result.claims(), result.coverage());
            }
            var claims = mode == 0 ? ExportReportClaims.read(UNOPENED, cancelled, path -> input, limits) :
                ExportReportClaims.readDetailed(UNOPENED, cancelled, path -> input, limits, ExportReportClaims.DEFAULT_RETENTION).claims();
            return new ReadResult(claims, null);
        }
        finally { require(input.closed, "owned report stream leaked"); }
    }

    private static void rejectAll(String text, ReportJsonReader.Limits limits) throws IOException {
        for (int mode = 0; mode < 3; mode++) {
            try { read(text, mode, limits, () -> false); throw new AssertionError("accepted malformed schema two"); }
            catch (ExportReportClaims.TerminalReportException wrong) { throw new AssertionError("malformed terminal reported as valid", wrong); }
            catch (IOException expected) { rejected++; }
        }
    }

    private static ReportJsonReader.Limits limits(long bytes, int values, int depth) {
        return new ReportJsonReader.Limits(bytes, 65536, depth, values, 250000);
    }

    private static int values(JsonElement value) {
        int total = 1;
        if (value.isJsonObject()) for (var entry : value.getAsJsonObject().entrySet()) total += values(entry.getValue());
        if (value.isJsonArray()) for (var entry : value.getAsJsonArray()) total += values(entry);
        return total;
    }

    private static JsonElement reverse(JsonElement value) {
        if (value.isJsonObject()) {
            var result = new JsonObject();
            var keys = new ArrayList<>(value.getAsJsonObject().keySet());
            java.util.Collections.reverse(keys);
            for (String key : keys) result.add(key, reverse(value.getAsJsonObject().get(key)));
            return result;
        }
        if (value.isJsonArray()) {
            var result = new JsonArray();
            for (var entry : value.getAsJsonArray()) result.add(reverse(entry));
            return result;
        }
        return value.deepCopy();
    }

    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
}

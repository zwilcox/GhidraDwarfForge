package ghidradwarfforge.output;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.output.ExportArtifactHashBindingFixtures.Pair;
import ghidradwarfforge.output.ExportReportClaims.Detailed;
import ghidradwarfforge.output.ExportReportClaims.Inventories;
import ghidradwarfforge.output.ExportReportClaims.RetentionLimits;

/** Opt-in retention and same-parse binding; shared lexical/digest tests stay separate. */
public final class ExportReportDetailsSmoke {
    private static final Path SUPPLIED = Path.of("unopened/alias/../report.json");
    private static final String[] ARRAYS = {"failedFunctions", "skippedFunctions", "omittedLocations",
        "unsupportedConstructs", "diagnostics"};
    private static final String[] COUNTS = {"functionsFailed", "functionsSkipped", "omittedLocationRanges",
        "unsupportedConstructs", "diagnostics"};
    private static int checks;

    private ExportReportDetailsSmoke() { }

    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("forge-report-details-");
        try {
            writerFixtures();
            budgets();
            parseFailures();
            parseResources();
            binding(root.resolve("binding"));
            bindingFailures(root.resolve("binding-failures"));
            constructorControls();
            System.out.println("export-report-details-smoke=PASS checks=" + checks);
        }
        finally {
            try (var files = Files.walk(root)) {
                for (Path path : files.sorted(Comparator.reverseOrder()).toList()) { Files.delete(path); }
            }
        }
    }

    private static JsonObject fixture(boolean partial) {
        return JsonParser.parseString(ExportReportClaimsFixtures.completed(partial).toJson()).getAsJsonObject();
    }

    private static void writerFixtures() throws Exception {
        for (boolean partial : new boolean[] {false, true}) {
            String actualWriter = ExportReportClaimsFixtures.completed(partial).toJson();
            JsonObject document = JsonParser.parseString(actualWriter).getAsJsonObject();
            Detailed expected = parse(actualWriter);
            require(expected.claims().equals(light(actualWriter)), "detailed claims differ from discard mode");
            require(expected.claims().validationStatus() == ExportReport.ValidationStatus.NOT_RUN, "validation upgraded");
            inventory(document, expected.inventories());
            for (int chunk : new int[] {1, 2, 7, 8192}) {
                Tracked stream = new Tracked(bytes(actualWriter), chunk);
                Detailed result = read(stream, () -> false, ExportReportClaims.DEFAULT_RETENTION);
                require(result.equals(expected), "chunking changed details");
                require(stream.closed == 1 && stream.eof, "result escaped before EOF/closure");
            }
            require(parse(reverse(document).toString()).equals(expected), "object field order changed inventories");
        }
        JsonObject document = fixture(true);
        for (String array : ARRAYS) {
            JsonArray items = document.getAsJsonArray(array);
            JsonElement first = items.get(0).deepCopy();
            if (first.isJsonObject()) {
                for (var field : first.getAsJsonObject().entrySet()) {
                    if (!field.getKey().toLowerCase().contains("address")) {
                        first.getAsJsonObject().addProperty(field.getKey(), "unknown\tΩ😀\\\"\n" + field.getKey());
                    }
                }
            }
            else { first = new com.google.gson.JsonPrimitive("😀\ncustom"); }
            items.add(first);
        }
        updateCounts(document);
        document.getAsJsonArray("diagnostics").add("duplicate");
        document.getAsJsonArray("diagnostics").add("duplicate");
        updateCounts(document);
        for (String array : ARRAYS) {
            JsonArray old = document.getAsJsonArray(array);
            JsonArray reversed = new JsonArray();
            for (int i = old.size() - 1; i >= 0; i--) { reversed.add(old.get(i)); }
            document.add(array, reversed);
        }
        Detailed varied = parse(document.toString());
        inventory(document, varied.inventories());
        require(varied.inventories().failedFunctions().get(0).address() == Long.MIN_VALUE, "unsigned address lost");
        require(varied.inventories().diagnostics().contains(""), "empty writer diagnostic discarded");
        for (String address : List.of("0x0", "0x7fffffffffffffff", "0x8000000000000000", "0xffffffffffffffff")) {
            document.getAsJsonArray("failedFunctions").get(0).getAsJsonObject().addProperty("address", address);
            var actual = parse(document.toString()).inventories().failedFunctions().get(0);
            require(("0x" + Long.toHexString(actual.address())).equals(address), "canonical failed address roundtrip");
        }
        JsonObject omitted = document.getAsJsonArray("omittedLocations").get(0).getAsJsonObject();
        omitted.addProperty("startAddress", "0x7ffffffffffffffe");
        omitted.addProperty("endAddress", "0x7fffffffffffffff");
        var range = parse(document.toString()).inventories().omittedLocations().get(0);
        require(range.startAddress() == Long.MAX_VALUE - 1 && range.endAddress() == Long.MAX_VALUE, "signed range boundary lost");
        immutable(varied.inventories());
    }

    private static void inventory(JsonObject doc, Inventories actual) {
        List<ExportReport.FunctionFailure> failed = new ArrayList<>();
        for (JsonElement e : doc.getAsJsonArray("failedFunctions")) {
            JsonObject v = e.getAsJsonObject();
            failed.add(new ExportReport.FunctionFailure(string(v, "name"), address(v, "address"), string(v, "diagnostic")));
        }
        List<ExportReport.SkippedFunctionInfo> skipped = new ArrayList<>();
        for (JsonElement e : doc.getAsJsonArray("skippedFunctions")) {
            JsonObject v = e.getAsJsonObject();
            skipped.add(new ExportReport.SkippedFunctionInfo(string(v, "name"), string(v, "reason")));
        }
        List<ExportReport.OmittedLocation> omitted = new ArrayList<>();
        for (JsonElement e : doc.getAsJsonArray("omittedLocations")) {
            JsonObject v = e.getAsJsonObject();
            omitted.add(new ExportReport.OmittedLocation(string(v, "function"), string(v, "variable"),
                string(v, "kind"), address(v, "startAddress"), address(v, "endAddress"),
                string(v, "reason"), string(v, "diagnostic")));
        }
        List<ExportReport.UnsupportedConstruct> unsupported = new ArrayList<>();
        for (JsonElement e : doc.getAsJsonArray("unsupportedConstructs")) {
            JsonObject v = e.getAsJsonObject();
            unsupported.add(new ExportReport.UnsupportedConstruct(string(v, "kind"), string(v, "name"), string(v, "diagnostic")));
        }
        List<String> diagnostics = new ArrayList<>();
        for (JsonElement e : doc.getAsJsonArray("diagnostics")) { diagnostics.add(e.getAsString()); }
        require(actual.failedFunctions().equals(failed), "failed inventory differs");
        require(actual.skippedFunctions().equals(skipped), "skipped inventory differs");
        require(actual.omittedLocations().equals(omitted), "omitted inventory differs");
        require(actual.unsupportedConstructs().equals(unsupported), "unsupported inventory differs");
        require(actual.diagnostics().equals(diagnostics), "diagnostic text/order differs");
    }

    private static void budgets() throws Exception {
        JsonObject small = fixture(true);
        int entries = entries(small);
        int units = units(small);
        read(new Tracked(bytes(small.toString()), 7), () -> false, new RetentionLimits(entries, units));
        JsonObject shorterAddress = small.deepCopy();
        shorterAddress.getAsJsonArray("failedFunctions").get(0).getAsJsonObject().addProperty("address", "0x0");
        read(new Tracked(bytes(shorterAddress.toString()), 7), () -> false, new RetentionLimits(entries, units));
        expect(IOException.class, () -> read(new Tracked(bytes(small.toString()), 7), () -> false, new RetentionLimits(entries - 1, units)));
        expect(IOException.class, () -> read(new Tracked(bytes(small.toString()), 7), () -> false, new RetentionLimits(entries, units - 1)));
        for (String array : ARRAYS) {
            if (array.equals("diagnostics")) { continue; }
            JsonObject item = small.getAsJsonArray(array).get(0).getAsJsonObject();
            for (String field : item.keySet()) {
                if (field.toLowerCase().contains("address")) { continue; }
                JsonObject changed = small.deepCopy();
                JsonObject value = changed.getAsJsonArray(array).get(0).getAsJsonObject();
                value.addProperty(field, value.get(field).getAsString() + "x");
                expect(IOException.class, () -> read(new Tracked(bytes(changed.toString()), 11), () -> false,
                    new RetentionLimits(entries, units)));
            }
        }
        JsonObject emoji = fixture(false);
        emoji.getAsJsonArray("diagnostics").add("😀"); updateCounts(emoji);
        read(new Tracked(bytes(emoji.toString()), 1), () -> false, new RetentionLimits(1, 2));
        expect(IOException.class, () -> read(new Tracked(bytes(emoji.toString()), 1), () -> false, new RetentionLimits(1, 1)));
        JsonObject empty = fixture(false);
        empty.getAsJsonArray("diagnostics").add(""); updateCounts(empty);
        read(new Tracked(bytes(empty.toString()), 1), () -> false, new RetentionLimits(1, 0));
        expect(IOException.class, () -> read(new Tracked(bytes(empty.toString()), 1), () -> false, new RetentionLimits(0, 0)));
        // Both selected DEFAULT caps at once, without increasing old lexical bounds.
        JsonObject maximum = fixture(false);
        JsonArray diagnostics = maximum.getAsJsonArray("diagnostics");
        for (int i = 0; i < 16384; i++) { diagnostics.add("x".repeat(64)); }
        updateCounts(maximum);
        String exact = maximum.toString();
        Detailed detailed = parse(exact);
        require(detailed.inventories().diagnostics().size() == 16384 && units(maximum) == 1048576,
            "combined default boundary is vacuous");
        require(detailed.claims().equals(light(exact)), "exact detailed default differs from light mode");
        diagnostics.add(""); updateCounts(maximum);
        String overEntries = maximum.toString();
        expect(IOException.class, () -> parse(overEntries));
        require(light(overEntries).counts().diagnostics() == 16385, "new cap narrowed discard mode");
        diagnostics.remove(diagnostics.size() - 1);
        diagnostics.set(0, new com.google.gson.JsonPrimitive("x".repeat(65))); updateCounts(maximum);
        String overUnits = maximum.toString();
        expect(IOException.class, () -> parse(overUnits));
        require(light(overUnits).counts().diagnostics() == 16384, "retained units cap narrowed discard mode");
        System.out.println("detailed-default-boundary=16384 entries,1048576 UTF16 units PASS");
    }

    private static void parseFailures() throws Exception {
        for (ExportReport.Status status : List.of(ExportReport.Status.FATAL, ExportReport.Status.CANCELLED)) {
            String text = ExportReportClaimsFixtures.terminal(status).toJson();
            var terminal = expect(ExportReportClaims.TerminalReportException.class, () -> parse(text));
            require(terminal.status() == status, "terminal status changed");
            JsonObject malformed = JsonParser.parseString(text).getAsJsonObject();
            malformed.getAsJsonArray("diagnostics").add("late invalid terminal inventory");
            IOException bad = expect(IOException.class, () -> parse(malformed.toString()));
            require(!(bad instanceof ExportReportClaims.TerminalReportException), "malformed terminal was called valid terminal");
        }
        JsonObject historic = fixture(true);
        historic.getAsJsonObject("counts").remove("functionStaticVariables");
        expect(ExportReportClaims.UnsupportedReportShapeException.class, () -> parse(historic.toString()));
        String base = fixture(true).toString();
        for (String text : List.of(base + "{}", base.substring(0, base.length() - 1),
                base.substring(0, base.length() - 1) + ",\"status\":\"PARTIAL\"}",
                base.replace("\"PARTIAL\"", "\"SUCCESS\""),
                base.replace("\"failedFunctions\":[", "\"failedFunctions\":[{} ,"))) {
            expect(IOException.class, () -> parse(text));
        }
        for (String name : COUNTS) {
            JsonObject changed = fixture(true);
            changed.getAsJsonObject("counts").addProperty(name, 919);
            expect(IOException.class, () -> parse(changed.toString()));
        }
    }

    private static void parseResources() throws Exception {
        byte[] document = bytes(fixture(true).toString());
        AtomicInteger opens = new AtomicInteger();
        expect(CancellationException.class, () -> ExportReportClaims.readDetailed(SUPPLIED, () -> true,
            path -> { opens.incrementAndGet(); throw new AssertionError("opened after cancellation"); },
            ReportJsonReader.DEFAULT_LIMITS, ExportReportClaims.DEFAULT_RETENTION));
        require(opens.get() == 0, "cancel-before-open performed I/O");
        for (String phase : List.of("read", "eof", "closed")) {
            Tracked input = new Tracked(document, 3);
            expect(CancellationException.class, () -> read(input, () -> switch (phase) {
                case "read" -> input.position > 4;
                case "eof" -> input.eof;
                default -> input.closed != 0;
            }, ExportReportClaims.DEFAULT_RETENTION));
            require(input.closed == 1, "cancel leaked report at " + phase);
            require(!phase.equals("closed") || input.eof, "post-close cancellation was early");
        }
        IOException open = new IOException("open marker");
        require(expect(IOException.class, () -> ExportReportClaims.readDetailed(SUPPLIED, () -> false,
            path -> { throw open; }, ReportJsonReader.DEFAULT_LIMITS, ExportReportClaims.DEFAULT_RETENTION)) == open,
            "open exception identity changed");
        for (boolean failRead : new boolean[] {false, true}) {
            Tracked input = new Tracked(document, 3);
            IOException read = new IOException("read marker");
            IOException close = new IOException("close marker");
            input.readFailure = failRead ? read : null; input.closeFailure = close;
            IOException failure = expect(IOException.class, () -> read(input, () -> false, ExportReportClaims.DEFAULT_RETENTION));
            require(failRead ? failure == read && Arrays.equals(failure.getSuppressed(), new Throwable[] {close}) : failure == close,
                "primary/close exception identity changed");
            require(input.closed == 1, "I/O failure leaked report");
        }
        Tracked input = new Tracked(document, 1);
        IllegalArgumentException marker = new IllegalArgumentException("supplier marker");
        require(expect(IllegalArgumentException.class, () -> read(input, () -> {
            if (input.position > 4) { throw marker; } return false;
        }, ExportReportClaims.DEFAULT_RETENTION)) == marker && input.closed == 1, "supplier identity/closure");
        Tracked overflow = new Tracked(document, 3);
        IOException close = new IOException("budget close marker"); overflow.closeFailure = close;
        IOException budget = expect(IOException.class, () -> read(overflow, () -> false, new RetentionLimits(0, 0)));
        require(budget != close && Arrays.equals(budget.getSuppressed(), new Throwable[] {close}) && overflow.closed == 1,
            "budget/close suppression changed");
    }

    private static void binding(Path root) throws Exception {
        for (boolean partial : new boolean[] {false, true}) {
            Pair pair = ExportArtifactHashBindingFixtures.create(root.resolve(Boolean.toString(partial)), partial);
            Map<Path, Snapshot> saved = snapshots(pair.all());
            Tracking access = new Tracking(pair);
            var result = observe(pair, () -> false, access);
            require(result.binding().equals(ExportArtifactHashBinding.observe(pair.report(), pair.original(), pair.sidecar(), pair.source())),
                "binding differs from lightweight API");
            inventory(ExportArtifactHashBindingFixtures.report(pair), result.inventories());
            var direct = ExportReportClaims.readDetailed(pair.report());
            require(direct.equals(ExportReportClaims.readDetailed(pair.report(), () -> false)) &&
                direct.claims().equals(result.binding().claims()) && direct.inventories().equals(result.inventories()),
                "direct public detailed reader disagrees");
            require(access.events.equals(List.of("attributes:report", "open:report", "close:report",
                "attributes:original", "attributes:sidecar", "attributes:source",
                "open:original", "close:original", "open:sidecar", "close:sidecar", "open:source", "close:source")),
                "one-parse/report-first/all-precheck order changed: " + access.events);
            access.closed();
            require(result.equals(ExportArtifactHashBinding.observeDetailed(pair.report(), pair.original(), pair.sidecar(), pair.source(), () -> false)),
                "public overload differs");
            unchanged(saved);
            var other = parse(fixture(!partial).toString()).inventories();
            expect(IllegalArgumentException.class, () -> new ExportArtifactHashBinding.DetailedResult(result.binding(), other));
            byte[][] originals = new byte[3][];
            for (int i = 0; i < 3; i++) { originals[i] = Files.readAllBytes(pair.artifacts().get(i)); }
            for (int mask = 1; mask < 8; mask++) {
                for (int i = 0; i < 3; i++) {
                    byte[] bytes = originals[i].clone();
                    if ((mask & (1 << i)) != 0) { bytes[0] ^= 0x5a; }
                    Files.write(pair.artifacts().get(i), bytes);
                }
                Tracking all = new Tracking(pair);
                var changed = observe(pair, () -> false, all);
                var roles = List.of(changed.binding().original(), changed.binding().sidecar(), changed.binding().source());
                for (int i = 0; i < 3; i++) {
                    require(roles.get(i).agreement() == ((mask & (1 << i)) == 0 ?
                        ExportArtifactHashBinding.Agreement.MATCHING_REPORTED_SHA256 : ExportArtifactHashBinding.Agreement.DIFFERENT_REPORTED_SHA256),
                        "detailed mismatch role lost");
                }
                require(changed.inventories().equals(result.inventories()) && all.streams.size() == 4, "mismatch hid inventory or later role");
                all.closed();
            }
        }
        // A second report open would return different, valid claims/diagnostics;
        // the accessor seam proves the returned pair came from exactly one parse.
        Pair pair = ExportArtifactHashBindingFixtures.create(root.resolve("one-parse"), true);
        Tracking access = new Tracking(pair);
        access.alternateReport = bytes(fixture(false).toString());
        var once = observe(pair, () -> false, access);
        require(access.reportOpens == 1 && once.binding().claims().status() == ExportReport.Status.PARTIAL &&
            !once.inventories().omittedLocations().isEmpty(), "binding combined separate report parses");
        access.closed();
    }

    private static void bindingFailures(Path root) throws Exception {
        Pair pair = ExportArtifactHashBindingFixtures.create(root, true);
        String valid = Files.readString(pair.report());
        for (String text : List.of(valid + "[]", valid.substring(0, valid.length() - 1),
                ExportReportClaimsFixtures.terminal(ExportReport.Status.FATAL).toJson(),
                ExportReportClaimsFixtures.terminal(ExportReport.Status.CANCELLED).toJson())) {
            Files.writeString(pair.report(), text);
            Tracking access = new Tracking(pair);
            IOException rejected = expect(IOException.class, () -> observe(pair, () -> false, access));
            if (text.contains("\"status\":\"FATAL\"") || text.contains("\"status\":\"CANCELLED\"")) {
                require(rejected instanceof ExportReportClaims.TerminalReportException, "valid terminal binder classification lost");
            }
            require(access.events.equals(List.of("attributes:report", "open:report", "close:report")), "failed complete parse inspected artifact");
            access.closed();
        }
        JsonObject historical = JsonParser.parseString(valid).getAsJsonObject();
        historical.getAsJsonObject("counts").remove("functionStaticVariables");
        Files.writeString(pair.report(), historical.toString());
        Tracking old = new Tracking(pair);
        expect(ExportReportClaims.UnsupportedReportShapeException.class, () -> observe(pair, () -> false, old));
        require(old.streams.size() == 1 && old.events.size() == 3, "historical report inspected artifacts");
        old.closed();
        JsonObject tooMany = fixture(false);
        for (int i = 0; i < 16385; i++) { tooMany.getAsJsonArray("diagnostics").add(""); }
        updateCounts(tooMany); Files.writeString(pair.report(), tooMany.toString());
        Tracking limited = new Tracking(pair);
        IOException overflow = expect(IOException.class, () -> observe(pair, () -> false, limited));
        require(overflow.getMessage().equals("detailed report inventory exceeds entry limit 16384") &&
            limited.events.equals(List.of("attributes:report", "open:report", "close:report")), "retention overflow touched artifacts");
        limited.closed();
        Files.writeString(pair.report(), valid);
        for (Path path : pair.all()) {
            for (String phase : List.of("attributes", "open", "read", "close", "read-close")) {
                Tracking access = new Tracking(pair);
                access.failing = path; access.phase = phase;
                access.primary = new IOException("primary " + phase); access.secondary = new IOException("secondary close");
                IOException failure = expect(IOException.class, () -> observe(pair, () -> false, access));
                require(failure == access.primary, "binder failure identity at " + phase);
                require(phase.equals("read-close") ? Arrays.equals(failure.getSuppressed(), new Throwable[] {access.secondary}) :
                    failure.getSuppressed().length == 0, "binder suppression at " + phase);
                access.closed();
                int role = pair.all().indexOf(path);
                if (phase.equals("attributes") && role > 0) {
                    require(access.streams.size() == 1, "artifact opened before all preconditions");
                }
            }
        }
        for (Path path : pair.all()) {
            for (String point : List.of("read", "closed")) {
                Tracking access = new Tracking(pair);
                expect(CancellationException.class, () -> observe(pair, () -> {
                    BoundStream stream = access.streams.get(path);
                    return stream != null && (point.equals("read") ? stream.reads > 0 : stream.closes > 0);
                }, access));
                access.closed();
                if (path.equals(pair.report())) {
                    require(access.streams.size() == 1, "report cancellation opened an artifact");
                }
            }
        }
        Tracking early = new Tracking(pair);
        expect(CancellationException.class, () -> observe(pair, () -> true, early));
        require(early.events.isEmpty(), "early cancellation touched files");
    }

    private static void constructorControls() throws Exception {
        Detailed partial = parse(fixture(true).toString());
        Detailed success = parse(fixture(false).toString());
        expect(IllegalArgumentException.class, () -> new Detailed(success.claims(), partial.inventories()));
        var p = partial.claims();
        var falseSuccess = new ExportReportClaims(p.schemaVersion(), ExportReport.Status.SUCCESS, p.target(),
            p.artifacts(), p.counts(), p.validationStatus(), p.libdwarfVersion());
        expect(IllegalArgumentException.class, () -> new Detailed(falseSuccess, partial.inventories()));
        var mutable = new ArrayList<>(partial.inventories().diagnostics());
        Inventories copied = new Inventories(partial.inventories().failedFunctions(), partial.inventories().skippedFunctions(),
            partial.inventories().omittedLocations(), partial.inventories().unsupportedConstructs(), mutable);
        mutable.clear();
        require(copied.equals(partial.inventories()), "inventory constructor retained mutable list");
        immutable(copied);
        expect(NullPointerException.class, () -> new Detailed(partial.claims(), null));
        expect(NullPointerException.class, () -> new Inventories(null, List.of(), List.of(), List.of(), List.of()));
        expect(IllegalArgumentException.class, () -> new RetentionLimits(-1, 0));
        expect(IllegalArgumentException.class, () -> new RetentionLimits(0, -1));
    }

    private static void immutable(Inventories value) throws Exception {
        for (List<?> list : List.of(value.failedFunctions(), value.skippedFunctions(), value.omittedLocations(),
                value.unsupportedConstructs(), value.diagnostics())) {
            expect(UnsupportedOperationException.class, list::clear);
        }
    }

    private static Detailed parse(String text) throws IOException {
        return read(new Tracked(bytes(text), 8192), () -> false, ExportReportClaims.DEFAULT_RETENTION);
    }
    private static Detailed read(Tracked input, BooleanSupplier cancelled, RetentionLimits retained) throws IOException {
        return ExportReportClaims.readDetailed(SUPPLIED, cancelled, path -> input, ReportJsonReader.DEFAULT_LIMITS, retained);
    }
    private static ExportReportClaims light(String text) throws IOException {
        return ExportReportClaims.read(SUPPLIED, () -> false, path -> new ByteArrayInputStream(bytes(text)), ReportJsonReader.DEFAULT_LIMITS);
    }
    private static ExportArtifactHashBinding.DetailedResult observe(Pair pair, BooleanSupplier cancelled, Tracking access) throws IOException {
        return ExportArtifactHashBinding.observeDetailed(pair.report(), pair.original(), pair.sidecar(), pair.source(), cancelled, access);
    }
    private static void updateCounts(JsonObject doc) {
        boolean partial = false;
        for (int i = 0; i < ARRAYS.length; i++) {
            int count = doc.getAsJsonArray(ARRAYS[i]).size();
            doc.getAsJsonObject("counts").addProperty(COUNTS[i], count); partial |= count != 0;
        }
        doc.addProperty("status", partial ? "PARTIAL" : "SUCCESS");
    }
    private static int entries(JsonObject doc) { int n = 0; for (String array : ARRAYS) { n += doc.getAsJsonArray(array).size(); } return n; }
    private static int units(JsonObject doc) {
        int count = 0;
        for (String array : ARRAYS) {
            for (JsonElement item : doc.getAsJsonArray(array)) {
                if (item.isJsonObject()) {
                    for (var field : item.getAsJsonObject().entrySet()) {
                        if (!field.getKey().toLowerCase().contains("address")) { count += field.getValue().getAsString().length(); }
                    }
                }
                else { count += item.getAsString().length(); }
            }
        }
        return count;
    }
    private static JsonElement reverse(JsonElement value) {
        if (value.isJsonObject()) {
            JsonObject result = new JsonObject(); List<String> keys = new ArrayList<>(value.getAsJsonObject().keySet());
            Collections.reverse(keys); for (String k : keys) { result.add(k, reverse(value.getAsJsonObject().get(k))); } return result;
        }
        if (value.isJsonArray()) { JsonArray result = new JsonArray(); for (JsonElement item : value.getAsJsonArray()) { result.add(reverse(item)); } return result; }
        return value.deepCopy();
    }
    private static String string(JsonObject value, String field) { return value.get(field).getAsString(); }
    private static long address(JsonObject value, String field) { return Long.parseUnsignedLong(string(value, field).substring(2), 16); }
    private static byte[] bytes(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static void require(boolean truth, String message) { if (!truth) { throw new AssertionError(message); } checks++; }
    @FunctionalInterface private interface Action { void run() throws Exception; }
    private static <T extends Throwable> T expect(Class<T> kind, Action action) throws Exception {
        try { action.run(); } catch (Throwable failure) { if (!kind.isInstance(failure)) { throw new AssertionError("wrong failure type", failure); } checks++; return kind.cast(failure); }
        throw new AssertionError("expected " + kind.getName());
    }
    private record Snapshot(byte[] bytes, java.nio.file.attribute.FileTime modified) { }
    private static Map<Path, Snapshot> snapshots(List<Path> paths) throws IOException {
        Map<Path, Snapshot> result = new HashMap<>();
        for (Path path : paths) { result.put(path, new Snapshot(Files.readAllBytes(path), Files.getLastModifiedTime(path))); }
        return result;
    }
    private static void unchanged(Map<Path, Snapshot> before) throws IOException {
        for (var e : before.entrySet()) { require(Arrays.equals(e.getValue().bytes(), Files.readAllBytes(e.getKey())) &&
            e.getValue().modified().equals(Files.getLastModifiedTime(e.getKey())), "selected bytes/mtime changed"); }
    }

    private static final class Tracked extends InputStream {
        final byte[] bytes;
        final int chunk;
        int position;
        int closed;
        boolean eof;
        IOException readFailure;
        IOException closeFailure;
        Tracked(byte[] bytes, int chunk) { this.bytes = bytes; this.chunk = chunk; }
        public int read() throws IOException { byte[] one = new byte[1]; int n = read(one, 0, 1); return n == -1 ? -1 : Byte.toUnsignedInt(one[0]); }
        public int read(byte[] target, int at, int count) throws IOException {
            if (readFailure != null) { throw readFailure; }
            if (position == bytes.length) { eof = true; return -1; }
            int n = Math.min(Math.min(chunk, count), bytes.length - position);
            System.arraycopy(bytes, position, target, at, n); position += n; return n;
        }
        public void close() throws IOException { closed++; if (closeFailure != null) { throw closeFailure; } }
    }

    private static final class Tracking implements ExportArtifactHashBinding.FileAccess {
        final Pair pair;
        final List<String> events = new ArrayList<>();
        final Map<Path, BoundStream> streams = new HashMap<>();
        int reportOpens;
        byte[] alternateReport;
        Path failing;
        String phase;
        IOException primary;
        IOException secondary;
        Tracking(Pair pair) { this.pair = pair; }
        String role(Path path) { return List.of("report", "original", "sidecar", "source").get(pair.all().indexOf(path)); }
        public BasicFileAttributes attributes(Path path) throws IOException {
            events.add("attributes:" + role(path));
            if (path.equals(failing) && "attributes".equals(phase)) { throw primary; }
            return Files.readAttributes(path, BasicFileAttributes.class);
        }
        public InputStream open(Path path) throws IOException {
            events.add("open:" + role(path));
            if (path.equals(failing) && "open".equals(phase)) { throw primary; }
            if (path.equals(pair.report())) { reportOpens++; }
            InputStream input = path.equals(pair.report()) && reportOpens > 1 && alternateReport != null ?
                new ByteArrayInputStream(alternateReport) : Files.newInputStream(path);
            BoundStream stream = new BoundStream(input, path, this); streams.put(path, stream); return stream;
        }
        void closed() { for (BoundStream s : streams.values()) { require(s.closes == 1, "owned binding stream close count"); } }
    }

    private static final class BoundStream extends FilterInputStream {
        final Path path;
        final Tracking access;
        int reads;
        int closes;
        BoundStream(InputStream input, Path path, Tracking access) { super(input); this.path = path; this.access = access; }
        public int read(byte[] b, int at, int count) throws IOException {
            reads++;
            if (path.equals(access.failing) && List.of("read", "read-close").contains(access.phase)) { throw access.primary; }
            return in.read(b, at, count);
        }
        public void close() throws IOException {
            closes++; access.events.add("close:" + access.role(path)); super.close();
            if (path.equals(access.failing)) {
                if ("close".equals(access.phase)) { throw access.primary; }
                if ("read-close".equals(access.phase)) { throw access.secondary; }
            }
        }
    }
}

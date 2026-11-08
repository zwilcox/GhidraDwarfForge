package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import ghidradwarfforge.coverage.DecodedInstructions;
import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission;
import ghidradwarfforge.coverage.ExportEmission.FunctionEmission;
import ghidradwarfforge.coverage.VariableCoverageInventory;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Writer-derived malformed controls plus semantic counterexamples and shared reader budgets. */
public final class CoverageReportClaimsSmoke {
    private static final CoverageReportJson.Profile PROFILE = new CoverageReportJson.Profile("x86:LE:64:default", "gcc");
    private static final ReportJsonReader.Limits LIMITS = ReportJsonReader.DEFAULT_LIMITS;
    private static int rejected;

    public static void main(String[] args) throws Exception {
        String huge = CoverageReportJson.write(CoverageReportJsonSmoke.fixture(), PROFILE, () -> false);
        String known = CoverageReportJson.write(knownFixture(), PROFILE, () -> false);
        String storage = CoverageReportJson.write(storageFixture(), PROFILE, () -> false);
        for (String text : List.of(huge, known, storage)) {
            var claims = parse(text);
            require(CoverageReportJson.write(claims.coverage(), claims.profile(), () -> false).equals(text), "exact writer roundtrip");
            require(parse(reverse(JsonParser.parseString(text)).toString()).equals(claims), "object field order independent");
            fieldControls(JsonParser.parseString(text).getAsJsonObject());
        }
        var dictionary = JsonParser.parseString(storage).getAsJsonObject();
        require(dictionary.getAsJsonArray("storageEvidenceDetails").size() == 2, "exact evidence details shared across owners");
        require(parse(storage).coverage().equals(storageFixture()), "dictionary roundtrip preserves every range and exact text");
        for (String reference : List.of("-1", "01", "2", "2147483648", "9223372036854775807")) {
            mutate(dictionary, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonArray("storageEvidence")
                .get(0).getAsJsonArray().set(2, new com.google.gson.JsonPrimitive(reference)));
        }
        mutate(dictionary, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonArray("storageEvidence").get(0).getAsJsonArray().add("0"));
        mutate(dictionary, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonArray("storageEvidence").get(0).getAsJsonArray().remove(2));
        mutate(dictionary, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonArray("storageEvidence").get(1).getAsJsonArray()
            .set(0, new com.google.gson.JsonPrimitive("0x0")));
        mutate(dictionary, d -> d.getAsJsonArray("storageEvidenceDetails").add(d.getAsJsonArray("storageEvidenceDetails").get(0).deepCopy()));
        mutate(dictionary, d -> {
            var unused = d.getAsJsonArray("storageEvidenceDetails").get(0).getAsJsonObject().deepCopy();
            unused.addProperty("source", "unreferenced detail");
            d.getAsJsonArray("storageEvidenceDetails").add(unused);
        });
        mutate(dictionary, d -> d.getAsJsonArray("storageEvidenceDetails").get(0).getAsJsonObject().addProperty("source", ""));
        mutate(dictionary, d -> d.getAsJsonArray("storageEvidenceDetails").get(0).getAsJsonObject().addProperty("category", "UNKNOWN"));
        mutate(dictionary, d -> d.getAsJsonArray("storageEvidenceDetails").get(0).getAsJsonObject().addProperty("omissionReason", "UNPAIRED"));
        var document = JsonParser.parseString(huge).getAsJsonObject();
        for (String count : List.of("", "-1", "+1", "01", "1e3", "1.0", "9223372036854775808", " 1", "١")) {
            var bad = document.deepCopy();
            bad.getAsJsonObject("summary").addProperty("functions", count);
            reject(bad.toString());
        }
        for (String address : List.of("0X1", "0x01", "0x8000000000000000", "0x-1", "0x10000000000000000")) {
            var bad = document.deepCopy();
            bad.getAsJsonArray("functions").get(0).getAsJsonObject().addProperty("entry", address);
            reject(bad.toString());
        }
        for (String flag : List.of("true", "FALSE", "UNKNOWN", "yes")) {
            var bad = document.deepCopy();
            bad.getAsJsonObject("summary").addProperty("recoveredGlobalsKnown", flag);
            reject(bad.toString());
        }
        mutate(document, d -> d.getAsJsonObject("summary").getAsJsonObject("variables").addProperty("recoveredVariables", "3"));
        mutate(document, d -> d.getAsJsonObject("summary").getAsJsonObject("functionTypes").addProperty("recoveredRoots", "99"));
        mutate(document, d -> d.getAsJsonArray("functions").get(1).getAsJsonObject().addProperty("entry", "0x0"));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().addProperty("function", "0x7"));
        mutate(document, d -> d.getAsJsonArray("variables").add(d.getAsJsonArray("variables").get(0).deepCopy()));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().addProperty("parameterOrdinal", "2"));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonObject("location").addProperty("knownScopeBytes", "0"));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonObject("location").addProperty("coveredScopeBytes", "1"));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonObject("location").addProperty("declarationEmitted", "NO"));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonObject("declarationProvenance").addProperty("subject", "LOCAL_DECLARATION"));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonObject("declarationProvenance").addProperty("category", "IMPORTED"));
        mutate(document, d -> d.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonObject("location")
            .getAsJsonArray("knownScopeRanges").get(0).getAsJsonArray().add("0x1"));
        var source = JsonParser.parseString(known).getAsJsonObject();
        mutate(source, d -> source(d).addProperty("decodedInstructions", "3"));
        mutate(source, d -> source(d).add("decodedStarts", JsonNull.INSTANCE));
        mutate(source, d -> source(d).getAsJsonArray("decodedStarts").add("0x64"));
        mutate(source, d -> source(d).getAsJsonArray("decodedStarts").set(0, new com.google.gson.JsonPrimitive("0x99")));
        mutate(source, d -> source(d).getAsJsonArray("anchoredStarts").set(0, new com.google.gson.JsonPrimitive("0x65")));
        mutate(source, d -> source(d).add("lineVisibleStarts", new JsonArray()));
        mutate(source, d -> source(d).addProperty("instructionUnavailableReason", "unknown"));
        mutate(source, d -> d.getAsJsonObject("summary").getAsJsonObject("source").addProperty("anchoredInstructions", "0"));
        mutate(source, d -> d.getAsJsonArray("functions").get(0).getAsJsonObject().getAsJsonObject("signature").addProperty("emitted", "NO"));
        // A coherent report is still only a claim. No binary/source artifact is opened to authenticate anchors.
        var changedClaim = source.deepCopy();
        source(changedClaim).getAsJsonArray("anchoredStarts").set(0, new com.google.gson.JsonPrimitive("0x64"));
        require(parse(changedClaim.toString()).coverage().functions().getFirst().source().observedPoints().anchored().equals(List.of(100L)),
            "structural validation is not artifact verification or attachment authority");
        for (String text : List.of(huge + "{}", "\ufeff" + huge, huge.replace("\"YES\"", "true"),
                huge.replace("\"definitionVersion\":1", "\"definitionVersion\":1,\"definitionVersion\":1"),
                huge.replace("\"definitionVersion\":1", "\"definitionVersion\":1,\"definition\\u0056ersion\":1"))) reject(text);
        int values = values(JsonParser.parseString(huge));
        int bytes = huge.getBytes(StandardCharsets.UTF_8).length;
        parse(huge, limits(bytes, values, 250000), () -> false);
        rejectBudget(huge, limits(bytes - 1, values, 250000));
        rejectBudget(huge, limits(bytes, values - 1, 250000));
        rejectBudget(huge, limits(bytes, values, 1));
        envelope(huge, values + 3);
        try { envelope(huge, values + 2); throw new AssertionError("embedded decoder reset shared budget"); }
        catch (IOException expected) { rejected++; }
        AtomicInteger checks = new AtomicInteger();
        parse(huge, LIMITS, () -> { checks.incrementAndGet(); return false; });
        int points = checks.get();
        var stops = new java.util.TreeSet<Integer>();
        for (int i = 1; i <= 32; i++) stops.add(i);
        for (int i = 1; i <= 256; i++) stops.add(Math.max(1, (int) ((long) points * i / 256)));
        for (int stop : stops) {
            checks.set(0);
            try { parse(huge, LIMITS, () -> checks.incrementAndGet() >= stop); throw new AssertionError("ignored cancellation " + stop); }
            catch (CancellationException expected) { }
        }
        try { CoverageReportClaims.read(Path.of("unopened/nonexistent/coverage.json"), () -> true); throw new AssertionError("opened before cancellation"); }
        catch (CancellationException expected) { }
        System.out.println("coverage-report-claims=PASS rejected=" + rejected + " sampled-cancellations=" + stops.size() + " values=" + values);
    }

    static ExportCoverage knownFixture() {
        var type = new TypeRef("int");
        var graph = new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED)));
        var signature = new FunctionSignature("f", 100, type, List.of(), List.of(), false, false, "default", "USER_DEFINED");
        var symbol = new FunctionSymbol("f", 100, 4);
        var model = new ProgramTypeModel(graph, List.of(signature), List.of());
        var source = SyntheticSourceFile.build("fixture", "test", List.of(new FunctionText("f", 100,
            "int f() {\n    return 1;\n}\n", null, List.of(new RelativeLine(2, List.of(102L))))));
        var lines = Dwarf5LineTable.buildWithPlan("f.c", ".", 8, ByteOrder.LITTLE_ENDIAN, List.of(symbol), source.mappedLines());
        var actual = new ExportEmission(graph, Map.of("int", List.of()), lines, List.of(new FunctionEmission(symbol, signature, List.of())));
        return ExportCoverage.build(model, source, List.of(new DecodedInstructions(symbol, List.of(100L, 102L), "")), actual, () -> false);
    }

    private static ExportCoverage storageFixture() {
        var base = CoverageReportJsonSmoke.fixture();
        var functions = new ArrayList<ExportCoverage.Function>();
        for (var function : base.functions()) {
            long entry = function.function().address();
            var variable = function.variables().variables().getFirst();
            var evidence = List.of(
                new VariableCoverageInventory.StorageEvidence(entry, entry + 1, "ANALYSIS", "evidence 🛠", "", ""),
                new VariableCoverageInventory.StorageEvidence(entry + 1, entry + 2, "DECOMPILER", "recovered evidence", "UNKNOWN_LIFETIME", "unknown\nrange"));
            var changed = new VariableCoverageInventory.Variable(variable.identity(), variable.displayName(), variable.recoveredType(),
                variable.emittedType(), variable.declarationProvenance(), evidence, variable.location(), variable.omissionReason(), variable.diagnostic());
            var inventory = new VariableCoverageInventory.FunctionInventory(function.function(), true, List.of(changed),
                function.variables().totals(), function.variables().byKind());
            functions.add(new ExportCoverage.Function(function.function(), function.source(), inventory, function.types(), function.signature(), function.typeProvenance()));
        }
        return new ExportCoverage(functions, base.sourceUnion(), base.variables(), base.variablesByKind(), base.functionTypeUnion(),
            base.unknownSignatureFunctions(), base.recoveredGlobals(), base.recoveredGlobalsKnown());
    }

    private static JsonObject source(JsonObject document) {
        return document.getAsJsonArray("functions").get(0).getAsJsonObject().getAsJsonObject("source");
    }

    private static CoverageReportClaims parse(String text) throws IOException { return parse(text, LIMITS, () -> false); }
    private static CoverageReportClaims parse(String text, ReportJsonReader.Limits limits, BooleanSupplier cancelled) throws IOException {
        var closed = new AtomicBoolean();
        var input = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)) {
            @Override public void close() throws IOException { closed.set(true); super.close(); }
        };
        try { return CoverageReportClaims.read(input, cancelled, limits); }
        finally { require(closed.get(), "owned stream did not close"); }
    }

    private static void envelope(String text, int budget) throws IOException {
        String wrapped = "{\"before\":0,\"coverage\":" + text + ",\"after\":0}";
        var limits = limits(wrapped.getBytes(StandardCharsets.UTF_8).length, budget, 250000);
        try (var json = new JsonReader(new ReportJsonReader(new ByteArrayInputStream(wrapped.getBytes(StandardCharsets.UTF_8)), () -> false, limits))) {
            json.setLenient(false);
            new ReportValueReader(json, () -> false, limits) {
                void read() throws IOException {
                    object("envelope", Set.of("before", "coverage", "after"), name -> {
                        if (name.equals("coverage")) CoverageReportClaims.read(this);
                        else integer();
                    });
                }
            }.read();
            require(json.peek() == JsonToken.END_DOCUMENT, "embedded coverage not fully consumed");
        }
    }

    private static ReportJsonReader.Limits limits(long bytes, int values, int array) {
        return new ReportJsonReader.Limits(bytes, 65536, 8, values, array);
    }

    private static void fieldControls(JsonObject original) throws IOException {
        var paths = new ArrayList<List<Object>>();
        objectPaths(original, new ArrayList<>(), paths);
        for (var path : paths) {
            var object = at(original, path).getAsJsonObject();
            for (String key : object.keySet()) {
                var changed = original.deepCopy();
                at(changed, path).getAsJsonObject().remove(key);
                reject(changed.toString());
            }
            var changed = original.deepCopy();
            at(changed, path).getAsJsonObject().addProperty("unknown", "unexpected");
            reject(changed.toString());
        }
    }

    private static void objectPaths(JsonElement element, List<Object> path, List<List<Object>> result) {
        if (element.isJsonObject()) {
            result.add(List.copyOf(path));
            for (var entry : element.getAsJsonObject().entrySet()) {
                path.add(entry.getKey()); objectPaths(entry.getValue(), path, result); path.removeLast();
            }
        }
        else if (element.isJsonArray()) {
            for (int i = 0; i < element.getAsJsonArray().size(); i++) {
                path.add(i); objectPaths(element.getAsJsonArray().get(i), path, result); path.removeLast();
            }
        }
    }

    private static JsonElement at(JsonElement element, List<Object> path) {
        for (Object step : path) element = step instanceof String name ? element.getAsJsonObject().get(name) : element.getAsJsonArray().get((Integer) step);
        return element;
    }

    private static JsonElement reverse(JsonElement element) {
        if (element.isJsonObject()) {
            var result = new JsonObject();
            new ArrayList<>(element.getAsJsonObject().entrySet()).reversed().forEach(e -> result.add(e.getKey(), reverse(e.getValue())));
            return result;
        }
        if (element.isJsonArray()) {
            var result = new JsonArray(); element.getAsJsonArray().forEach(e -> result.add(reverse(e))); return result;
        }
        return element.deepCopy();
    }

    private static int values(JsonElement element) {
        int result = 1;
        if (element.isJsonObject()) for (var entry : element.getAsJsonObject().entrySet()) result += values(entry.getValue());
        else if (element.isJsonArray()) for (var child : element.getAsJsonArray()) result += values(child);
        return result;
    }

    private static void mutate(JsonObject original, java.util.function.Consumer<JsonObject> mutation) throws IOException {
        var changed = original.deepCopy(); mutation.accept(changed); reject(changed.toString());
    }
    private static void reject(String text) throws IOException {
        try { parse(text); }
        catch (IOException expected) { rejected++; return; }
        throw new AssertionError("malformed coverage accepted: " + text.substring(0, Math.min(180, text.length())));
    }
    private static void rejectBudget(String text, ReportJsonReader.Limits limits) throws IOException {
        try { parse(text, limits, () -> false); }
        catch (IOException expected) { rejected++; return; }
        throw new AssertionError("budget overflow accepted");
    }
    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}

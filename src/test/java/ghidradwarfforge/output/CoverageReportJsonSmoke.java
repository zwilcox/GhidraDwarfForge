package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission;
import ghidradwarfforge.coverage.ExportEmission.*;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.*;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Exact decimal/UTF-8 budgets, nulls, deterministic ordering and unchanged lexical grammar. */
public final class CoverageReportJsonSmoke {
    public static void main(String[] args) throws Exception {
        var integer = new TypeRef("int");
        var graph = new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED)));
        var f = new FunctionSignature("f", 0, integer, List.of(new Parameter("x", integer, false)),
            List.of(), false, false, "default", "USER_DEFINED");
        var g = new FunctionSignature("g", 1, integer, List.of(new Parameter("x", integer, false)),
            List.of(), false, false, "default", "IMPORTED");
        var model = new ProgramTypeModel(graph, List.of(f, g), List.of(
            new GlobalVariable("lambda λ 🛠\n\"", 4096, 4, integer, false, "USER_DEFINED")));
        var first = new FunctionSymbol("f", 0, Long.MAX_VALUE);
        var second = new FunctionSymbol("g", 1, Long.MAX_VALUE - 1);
        var line = Dwarf5LineTable.buildWithPlan("fixture.c", ".", 8, ByteOrder.LITTLE_ENDIAN, List.of(first, second), List.of());
        var variable = new VariableEmission(Kind.PARAMETER, 0, "x", "x", "", integer, false, false,
            new NoLocation("UNASSIGNED", "unknown storage"));
        var actual = new ExportEmission(graph, Map.of("int", List.of()), line, List.of(
            new FunctionEmission(first, f, List.of(variable)), new FunctionEmission(second, g, List.of(variable))));
        var coverage = ExportCoverage.build(model, null, List.of(), actual, () -> false);
        var profile = new CoverageReportJson.Profile("x86:LE:64:default λ 🛠", "gcc");
        String text = CoverageReportJson.write(coverage, profile, () -> false);
        var document = JsonParser.parseString(text).getAsJsonObject();
        require(document.get("definitionVersion").getAsInt() == 1, "metric definition version");
        require(document.getAsJsonObject("summary").getAsJsonObject("variables").get("knownScopeBytes").isJsonNull() &&
            document.getAsJsonObject("summary").getAsJsonObject("variables").get("extentUnavailableReason").getAsString().equals("OVERFLOW"),
            "overflow is null with explicit reason, never a wrapped number");
        var location = document.getAsJsonArray("variables").get(0).getAsJsonObject().getAsJsonObject("location");
        require(location.get("knownScopeBytes").getAsString().equals("9223372036854775807"), "full signed64 count remains exact");
        require(location.getAsJsonArray("knownScopeRanges").get(0).getAsJsonArray().get(1).getAsString().equals("0x7fffffffffffffff"),
            "canonical supported address boundary");
        var source = document.getAsJsonArray("functions").get(0).getAsJsonObject().getAsJsonObject("source");
        require(source.get("decodedInstructions").isJsonNull() && source.get("decodedStarts").isJsonNull(), "unknown source is not zero/empty");
        require(document.getAsJsonArray("recoveredGlobals").get(0).getAsJsonObject().get("name").getAsString()
            .equals("lambda λ 🛠\n\""), "Unicode/control/quote content preserved");
        require(document.getAsJsonObject("profile").get("languageId").getAsString().equals(profile.languageId()), "explicit profile retained");
        scalars(document, "");
        String wrapped = "{\"coverage\":" + text + "}";
        try (var reader = new JsonReader(new ReportJsonReader(new ByteArrayInputStream(wrapped.getBytes(StandardCharsets.UTF_8)),
                () -> false, ReportJsonReader.DEFAULT_LIMITS))) {
            reader.setLenient(false);
            reader.skipValue();
            require(reader.peek() == JsonToken.END_DOCUMENT, "payload fits unchanged strict lexical grammar/depth");
        }
        int bytes = text.getBytes(StandardCharsets.UTF_8).length;
        require(CoverageReportJson.write(coverage, profile, () -> false, bytes).equals(text), "exact UTF8 byte limit accepted");
        rejected(() -> CoverageReportJson.write(coverage, profile, () -> false, bytes - 1));
        rejected(() -> CoverageReportJson.write(coverage, new CoverageReportJson.Profile("\ud800", "gcc"), () -> false));
        rejected(() -> CoverageReportJson.write(coverage, new CoverageReportJson.Profile("\udc00", "gcc"), () -> false));
        require(CoverageReportJson.write(coverage, new CoverageReportJson.Profile("x".repeat(65536), "gcc"), () -> false)
            .contains("x".repeat(65536)), "exact decoded string-unit budget");
        rejected(() -> CoverageReportJson.write(coverage, new CoverageReportJson.Profile("x".repeat(65537), "gcc"), () -> false));
        AtomicInteger calls = new AtomicInteger();
        require(CoverageReportJson.write(coverage, profile, () -> { calls.incrementAndGet(); return false; }).equals(text),
            "serialization deterministic with observation");
        int points = calls.get();
        for (int limit = 1; limit <= points; limit++) {
            final int stop = limit;
            calls.set(0);
            try {
                CoverageReportJson.write(coverage, profile, () -> calls.incrementAndGet() >= stop);
                throw new AssertionError("ignored cancellation " + stop);
            }
            catch (CancellationException expected) { }
        }
        System.out.println("coverage-report-json=PASS utf8-bytes=" + bytes + " cancellation-points=" + points);
    }

    private static void scalars(JsonElement value, String key) {
        if (value.isJsonObject()) {
            value.getAsJsonObject().entrySet().forEach(entry -> scalars(entry.getValue(), entry.getKey()));
        }
        else if (value.isJsonArray()) {
            value.getAsJsonArray().forEach(item -> scalars(item, key));
        }
        else if (!value.isJsonNull()) {
            var primitive = value.getAsJsonPrimitive();
            require(key.equals("definitionVersion") ? primitive.isNumber() : primitive.isString(),
                "all metric scalars use exact strings, except definition version");
        }
    }

    private interface Attempt { void run() throws IOException; }
    private static void rejected(Attempt task) {
        try { task.run(); }
        catch (IOException expected) { return; }
        throw new AssertionError("invalid/oversized JSON accepted");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

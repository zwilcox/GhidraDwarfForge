package ghidradwarfforge.output;

import java.io.IOException;
import java.io.StringReader;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission.Kind;
import ghidradwarfforge.coverage.LocationCoverage;
import ghidradwarfforge.coverage.SourceCoverageIndex;
import ghidradwarfforge.coverage.SourceCoverageInventory;
import ghidradwarfforge.coverage.VariableCoverageInventory;
import ghidradwarfforge.coverage.VariableCoverageTotals;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Exploratory report-size/reader-cost probe; not native-export or whole-application performance acceptance. */
public final class CoverageReportWorkload {
    public static void main(String[] args) throws Exception {
        if (args.length == 0) throw new IllegalArgumentException("supply function counts");
        for (String argument : args) {
            String[] shape = argument.split(":");
            if (shape.length > 3) throw new IllegalArgumentException("expected functions[:instructions[:locals]]");
            int count = Integer.parseInt(shape[0]);
            int instructions = shape.length > 1 ? Integer.parseInt(shape[1]) : 2;
            int locals = shape.length > 2 ? Integer.parseInt(shape[2]) : 0;
            if (count < 1 || count > 100000) throw new IllegalArgumentException("function count outside probe bounds");
            if (instructions < 1 || instructions > 10000 || locals < 0 || locals > 100 ||
                    (long) count * (instructions + locals) > 2_000_000) throw new IllegalArgumentException("probe population exceeds bounds");
            var coverage = fixture(count, instructions, locals);
            var profile = new CoverageReportJson.Profile("x86:LE:64:default", "gcc");
            var result = new JsonObject();
            result.addProperty("scope", "synthetic equally sized functions, known full-scope locals, shared canonical int; excludes extraction/native export");
            result.addProperty("functions", count);
            result.addProperty("instructionsPerFunction", instructions);
            result.addProperty("localsPerFunction", locals);
            result.addProperty("javaVersion", System.getProperty("java.version"));
            result.addProperty("heapLimitBytes", Runtime.getRuntime().maxMemory());
            Integer valueLimit = Integer.getInteger("forge.workload.values");
            var limits = valueLimit == null ? ReportJsonReader.DEFAULT_LIMITS : new ReportJsonReader.Limits(ReportJsonReader.DEFAULT_LIMITS.bytes(),
                ReportJsonReader.DEFAULT_LIMITS.stringUnits(), ReportJsonReader.DEFAULT_LIMITS.depth(), valueLimit,
                ReportJsonReader.DEFAULT_LIMITS.arrayItems());
            result.addProperty("legacyValueLimit", limits.values());
            result.addProperty("coverageValueLimit", limits.coverageValues());
            result.addProperty("totalValueLimit", limits.totalValues());
            result.addProperty("experimentalOverride", valueLimit != null);
            long start = System.nanoTime();
            try {
                payloadSize(coverage, profile, result);
                result.addProperty("payloadWriteAndCountNanos", System.nanoTime() - start);
                start = System.nanoTime();
                String report = ExportReportClaimsFixtures.completed(false, count)
                    .toJsonWithCoverage(new CoverageReportClaims(profile, coverage), () -> false, limits);
                result.addProperty("reportWriteAndPreflightNanos", System.nanoTime() - start);
                result.addProperty("reportUtf8Bytes", report.getBytes(StandardCharsets.UTF_8).length);
                result.addProperty("status", "ACCEPTED");
            }
            catch (IOException rejected) {
                result.addProperty("elapsedUntilRejectionNanos", System.nanoTime() - start);
                result.addProperty("status", "REJECTED");
                result.addProperty("diagnostic", rejected.getMessage());
            }
            result.addProperty("heapUsedBytesAtObservation", ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed());
            System.out.println(result);
        }
    }

    private static void payloadSize(ExportCoverage coverage, CoverageReportJson.Profile profile, JsonObject result) throws IOException {
        String payload = CoverageReportJson.write(coverage, profile, () -> false);
        result.addProperty("payloadUtf8Bytes", payload.getBytes(StandardCharsets.UTF_8).length);
        try (var reader = new JsonReader(new StringReader(payload))) {
            result.addProperty("payloadValues", values(reader));
        }
    }

    private static long values(JsonReader reader) throws IOException {
        long count = 1;
        switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                reader.beginObject();
                while (reader.hasNext()) { reader.nextName(); count += values(reader); }
                reader.endObject();
            }
            case BEGIN_ARRAY -> {
                reader.beginArray();
                while (reader.hasNext()) count += values(reader);
                reader.endArray();
            }
            case NULL -> reader.nextNull();
            case STRING, NUMBER -> reader.nextString();
            default -> throw new IOException("unexpected generated token");
        }
        return count;
    }

    private static ExportCoverage fixture(int count, int instructions, int locals) {
        var template = CoverageReportClaimsSmoke.knownFixture();
        var first = template.functions().getFirst();
        var functions = new ArrayList<ExportCoverage.Function>(count);
        long size = 2L * instructions;
        var totals = new VariableCoverageTotals(locals, locals, locals, locals, 0, size * locals, size * locals, "");
        var byKind = new java.util.EnumMap<Kind, VariableCoverageTotals>(Kind.class);
        byKind.putAll(template.variablesByKind());
        byKind.put(Kind.LOCAL, totals);
        for (int i = 0; i < count; i++) {
            long entry = 0x1000L + (size + 16) * i;
            var symbol = new FunctionSymbol("workload_" + i, entry, size);
            var starts = new ArrayList<Long>(instructions);
            for (int instruction = 0; instruction < instructions; instruction++) starts.add(entry + 2L * instruction);
            var points = new SourceCoverageIndex.Points(starts, List.of(starts.getLast()), starts);
            var source = new SourceCoverageInventory.FunctionInventory(symbol, "DECOMPILED", "", (long) instructions, 1L, (long) instructions, "", "", points);
            var declarations = new ArrayList<VariableCoverageInventory.Variable>(locals);
            for (int local = 0; local < locals; local++) {
                String name = "local_" + local;
                var location = new LocationCoverage(true, true, "EXPLICIT_LOCAL_SCOPE", symbol.ranges(), symbol.ranges(), size, size, size);
                declarations.add(new VariableCoverageInventory.Variable(new VariableCoverageInventory.Identity(Kind.LOCAL, -1, name, "", null),
                    name, new TypeRef("int"), new TypeRef("int"), new VariableCoverageInventory.Provenance("USER_DEFINED", "USER_DEFINED", "LOCAL_DECLARATION"),
                    List.of(), location, "", ""));
            }
            var variables = new VariableCoverageInventory.FunctionInventory(symbol, true, declarations, totals, byKind);
            functions.add(new ExportCoverage.Function(symbol, source, variables, first.types(), first.signature(), first.typeProvenance()));
        }
        long variables = (long) count * locals;
        var programTotals = new VariableCoverageTotals(variables, variables, variables, variables, 0, size * variables, size * variables, "");
        byKind.put(Kind.LOCAL, programTotals);
        return new ExportCoverage(functions, new SourceCoverageInventory.Union(count, 0, 0, (long) instructions * count, count, (long) instructions * count),
            programTotals, byKind, template.functionTypeUnion(), 0, List.of(), true);
    }
}

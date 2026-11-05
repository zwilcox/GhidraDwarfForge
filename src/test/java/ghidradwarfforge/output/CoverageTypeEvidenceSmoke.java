package ghidradwarfforge.output;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.TypeGraphEvidence;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/** Definition-two graph consistency, migration and equal-total individual regression checks. */
public final class CoverageTypeEvidenceSmoke {
    private static int rejected;
    public static void main(String[] args) throws Exception {
        var before = fixture(false);
        var after = fixture(true);
        String text = CoverageReportJson.write(before, () -> false);
        require(parse(text).equals(before), "typed evidence roundtrip");
        require(CoverageReportJson.write(parse(text), () -> false).equals(text), "typed evidence bytes changed");
        var root = JsonParser.parseString(text).getAsJsonObject();
        require(root.get("definitionVersion").getAsInt() == 2, "missing definition version");
        mutate(root, value -> value.addProperty("definitionVersion", 1));
        mutate(root, value -> value.addProperty("definitionVersion", 3));
        mutate(root, value -> value.remove("typeNodes"));
        mutate(root, value -> value.remove("functionTypeRoots"));
        mutate(root, value -> value.getAsJsonArray("typeNodes").add(value.getAsJsonArray("typeNodes").get(0).deepCopy()));
        mutate(root, value -> value.getAsJsonArray("typeNodes").remove(0));
        mutate(root, value -> value.getAsJsonArray("typeNodes").get(0).getAsJsonObject().addProperty("kind", "IMPLICIT_VOID"));
        mutate(root, value -> value.getAsJsonArray("typeNodes").get(0).getAsJsonObject().addProperty("definitionKind", "UnknownType"));
        mutate(root, value -> value.getAsJsonArray("functionTypeRoots").get(0).getAsJsonObject().addProperty("entry", "0x65"));
        mutate(root, value -> value.getAsJsonArray("functionTypeRoots").add(value.getAsJsonArray("functionTypeRoots").get(0).deepCopy()));
        mutate(root, value -> value.getAsJsonArray("functionTypeRoots").get(0).getAsJsonObject().getAsJsonArray("recovered").add("root"));
        mutate(root, value -> value.getAsJsonArray("functionTypeRoots").get(0).getAsJsonObject().getAsJsonArray("emitted").remove(0));
        mutate(root, value -> value.getAsJsonArray("typeNodes").get(2).getAsJsonObject().getAsJsonArray("emittedReferences")
            .get(0).getAsJsonObject().addProperty("count", "3"));
        mutate(root, value -> value.getAsJsonArray("typeNodes").get(2).getAsJsonObject().getAsJsonArray("recoveredReferences")
            .get(0).getAsJsonObject().addProperty("key", "missing"));
        mutate(root, value -> value.getAsJsonObject("summary").getAsJsonObject("functionTypes").addProperty("opaqueFreeEmittedRoots", "1"));
        String legacy = CoverageReportJson.write(before.coverage(), before.profile(), () -> false);
        require(parse(legacy).typeEvidence() == null && parse(legacy).coverage().equals(before.coverage()), "definition one migration");
        require(CoverageReportJson.write(parse(legacy), () -> false).equals(legacy), "legacy bytes changed");
        var reversed = new JsonObject();
        var entries = new ArrayList<>(root.entrySet());
        java.util.Collections.reverse(entries);
        for (var entry : entries) reversed.add(entry.getKey(), entry.getValue());
        require(parse(reversed.toString()).equals(before), "version must not depend on field order");

        var calls = new AtomicInteger();
        CoverageReportClaims.read(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)),
            () -> { calls.incrementAndGet(); return false; }, ReportJsonReader.DEFAULT_LIMITS);
        int points = calls.get();
        for (int stop = 1; stop <= points; stop++) {
            int limit = stop;
            calls.set(0);
            try {
                CoverageReportClaims.read(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)),
                    () -> calls.incrementAndGet() >= limit, ReportJsonReader.DEFAULT_LIMITS);
                throw new AssertionError("ignored type report cancellation " + stop);
            }
            catch (CancellationException expected) { }
        }
        var directory = Files.createTempDirectory("forge-type-comparison-");
        try {
            var report = ExportReportClaimsFixtures.completed(false, 1);
            var first = directory.resolve("before.json");
            var second = directory.resolve("after.json");
            Files.writeString(first, report.toJsonWithCoverage(before, () -> false));
            Files.writeString(second, report.toJsonWithCoverage(after, () -> false));
            var old = ExportReportClaims.readWithCoverage(first, () -> false);
            var next = ExportReportClaims.readWithCoverage(second, () -> false);
            var changes = new ArrayList<CoverageComparison.Change>();
            var result = CoverageComparison.compare(old, next, changes::add, () -> false);
            require(result.comparable(), "same input/profile type evidence incomparable");
            require(changes.stream().noneMatch(c -> c.kind().equals("TYPE_COUNTS_CHANGED")), "fixture aggregate counts differ");
            require(changes.stream().anyMatch(c -> c.kind().equals("TYPE_STATE_CHANGED") && c.detail().equals("a: RESOLVED -> OPAQUE")),
                "aggregate counts hid individual regression");
            require(changes.stream().anyMatch(c -> c.kind().equals("TYPE_STATE_CHANGED") && c.detail().equals("b: OPAQUE -> RESOLVED")),
                "offsetting gain missing");
            require(result.reasons().stream().noneMatch(reason -> reason.contains("evidence unavailable")), "available graph ignored");
            changes.clear();
            CoverageComparison.compare(old, old, changes::add, () -> false);
            require(changes.isEmpty(), "identical graph changed");
            calls.set(0);
            CoverageComparison.compare(old, next, ignored -> { }, () -> { calls.incrementAndGet(); return false; });
            int comparisonPoints = calls.get();
            for (int stop = 1; stop <= comparisonPoints; stop++) {
                int limit = stop;
                calls.set(0);
                try {
                    CoverageComparison.compare(old, next, ignored -> { }, () -> calls.incrementAndGet() >= limit);
                    throw new AssertionError("ignored type comparison cancellation");
                }
                catch (CancellationException expected) { }
            }
            System.out.println("coverage-type-evidence=PASS rejected=" + rejected + " reader-cancellation-points=" + points +
                " comparison-cancellation-points=" + comparisonPoints);
        }
        finally {
            try (var files = Files.list(directory)) { for (var file : files.toList()) Files.delete(file); }
            Files.delete(directory);
        }
    }

    private static CoverageReportClaims fixture(boolean swap) {
        var base = CoverageReportClaimsSmoke.knownFixture();
        TypeNode a = swap ? new OpaqueType("a", "A", 4, "unresolved") : new BaseType("a", "A", 4, BaseEncoding.SIGNED);
        TypeNode b = swap ? new BaseType("b", "B", 4, BaseEncoding.SIGNED) : new OpaqueType("b", "B", 4, "unresolved");
        var root = new AggregateType("root", "Root", 12, AggregateKind.STRUCTURE, List.of(
            new Member("a1", new TypeRef("a"), 0), new Member("a2", new TypeRef("a"), 4), new Member("b", new TypeRef("b"), 8)));
        var graph = TypeGraphEvidence.capture(new TypeGraph(List.of(a, b, root)),
            Map.of("a", List.of(), "b", List.of(), "root", root.references()), () -> false);
        var roots = List.of(new TypeRef("root"));
        var counts = graph.inspect(roots, roots, () -> false).totals();
        var original = base.functions().getFirst();
        var function = new ExportCoverage.Function(original.function(), original.source(), original.variables(), counts,
            original.signature(), original.typeProvenance());
        var coverage = new ExportCoverage(List.of(function), base.sourceUnion(), base.variables(), base.variablesByKind(), counts,
            0, List.of(), true);
        return new CoverageReportClaims(new CoverageReportJson.Profile("x86:LE:64:default", "gcc"), coverage,
            new CoverageTypeEvidence(graph, Map.of(100L, new CoverageTypeEvidence.Roots(roots, roots))));
    }
    private static CoverageReportClaims parse(String text) throws IOException {
        return CoverageReportClaims.read(new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)), () -> false,
            ReportJsonReader.DEFAULT_LIMITS);
    }
    private static void mutate(JsonObject original, Consumer<JsonObject> action) throws Exception {
        var copy = original.deepCopy();
        action.accept(copy);
        try { parse(copy.toString()); }
        catch (IOException expected) { rejected++; return; }
        throw new AssertionError("invalid type report admitted");
    }
    private static void require(boolean condition, String message) { if (!condition) throw new AssertionError(message); }
}

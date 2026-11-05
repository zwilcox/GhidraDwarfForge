package ghidradwarfforge.output;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import com.google.gson.JsonParser;
import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.SourceCoverageIndex.Points;
import ghidradwarfforge.coverage.SourceCoverageInventory;
import ghidradwarfforge.coverage.VariableCoverageInventory;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Exact losses must survive unchanged totals; reported identity is not file authentication. */
public final class CoverageComparisonSmoke {
    private static final CoverageReportJson.Profile PROFILE = new CoverageReportJson.Profile("x86:LE:64:default", "gcc");
    private record Run(int status, String out, String err) { }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("forge-coverage-cli-");
        try {
            Path before = directory.resolve("before λ 🛠.json");
            Path after = directory.resolve("after.json");
            Files.writeString(before, report("old name", List.of(100L, 102L, 104L), List.of(100L, 104L), List.of(100L, 102L, 104L)));
            Files.writeString(after, report("renamed", List.of(100L, 102L, 104L), List.of(102L, 104L), List.of(102L, 104L)));
            var first = ExportReportClaims.readWithCoverage(before, () -> false);
            var second = ExportReportClaims.readWithCoverage(after, () -> false);
            var changes = new ArrayList<CoverageComparison.Change>();
            var calls = new AtomicInteger();
            var compared = CoverageComparison.compare(first, second, changes::add, () -> { calls.incrementAndGet(); return false; });
            require(compared.comparable() && compared.changes() == changes.size(), "comparison/count mismatch");
            require(has(changes, "FUNCTION_RENAMED", "old name -> renamed"), "rename at same link-time entry lost");
            require(has(changes, "ANCHOR_LOST", "0x64") && has(changes, "ANCHOR_GAINED", "0x66"),
                "equal anchor totals hid the lost point");
            require(has(changes, "LINE_VISIBILITY_LOST", "0x64"), "lost line visibility missing");
            require(compared.reasons().stream().anyMatch(s -> s.contains("individual resolved-to-opaque")), "type identity limit hidden");
            for (int point = 1; point <= calls.get(); point++) {
                int stop = point;
                var checks = new AtomicInteger();
                try {
                    CoverageComparison.compare(first, second, ignored -> { }, () -> checks.incrementAndGet() >= stop);
                    throw new AssertionError("comparison ignored cancellation " + point);
                }
                catch (CancellationException expected) { }
            }
            var moved = JsonParser.parseString(Files.readString(before)).getAsJsonObject();
            var artifacts = moved.getAsJsonObject("artifacts");
            artifacts.addProperty("inputPath", "Z:\\moved\\input");
            artifacts.addProperty("outputPath", "/missing/sidecar");
            artifacts.addProperty("sourcePath", "/missing/source");
            artifacts.addProperty("inputSha256", artifacts.get("inputSha256").getAsString().toLowerCase());
            Path movedPath = Files.writeString(directory.resolve("moved.json"), moved.toString());
            var matching = CoverageComparison.compare(first, ExportReportClaims.readWithCoverage(movedPath, () -> false),
                change -> { throw new AssertionError("path moves changed coverage"); }, () -> false);
            require(matching.comparable() && matching.changes() == 0, "path move/hash spelling invalidated identity");
            artifacts.addProperty("inputSha256", "f".repeat(64));
            Files.writeString(movedPath, moved.toString());
            require(run("--report", movedPath.toString(), "--before", before.toString()).status() == 2, "different input compared");
            moved = JsonParser.parseString(Files.readString(before)).getAsJsonObject();
            moved.getAsJsonObject("coverage").getAsJsonObject("profile").addProperty("compilerSpecId", "different");
            Files.writeString(movedPath, moved.toString());
            require(run("--report", movedPath.toString(), "--before", before.toString()).status() == 2, "different compiler profile compared");
            moved.getAsJsonObject("coverage").addProperty("definitionVersion", 2);
            Files.writeString(movedPath, moved.toString());
            require(run("--report", movedPath.toString()).status() == 1, "unknown metric version admitted");

            Files.writeString(after, report("old name", List.of(100L, 104L, 106L), List.of(104L, 106L), List.of(104L, 106L)));
            changes.clear();
            CoverageComparison.compare(first, ExportReportClaims.readWithCoverage(after, () -> false), changes::add, () -> false);
            require(has(changes, "DECODED_REMOVED", "0x66") && has(changes, "DECODED_ADDED", "0x6a"), "changed decoded population missing");
            require(!has(changes, "LINE_VISIBILITY_LOST", "0x66") && !has(changes, "ANCHOR_GAINED", "0x6a"),
                "changed population counted as matching-population loss/gain");
            Files.writeString(after, report("old name", null, null, null));
            changes.clear();
            CoverageComparison.compare(first, ExportReportClaims.readWithCoverage(after, () -> false), changes::add, () -> false);
            require(changes.stream().anyMatch(c -> c.kind().equals("INSTRUCTION_EVIDENCE_CHANGED")) &&
                changes.stream().noneMatch(c -> c.kind().contains("LOST")), "unknown evidence treated as zero");

            var shown = run("--report", before.toString());
            require(shown.status() == 0 && shown.out().contains("66.66% (2/3)") && shown.out().contains("old name\t0x64"), "CLI missing per-function exact fractions");
            var detail = run("--report-utf8-base64", AttachmentPathArgument.encode(before.toString()), "--function", "0x64");
            require(detail.status() == 0 && detail.out().contains("Signature provenance: USER_DEFINED"), "encoded path or function detail failed");
            var summary = run("--report", before.toString(), "--summary");
            require(summary.status() == 0 && !summary.out().contains("old name\t0x64"), "summary mode included table");
            require(run("--report", before.toString(), "--function", "0xffff").status() == 64, "missing function not reported");
            require(run("--report", before.toString(), "--summary", "--before", after.toString()).status() == 64, "incompatible CLI modes admitted");
            require(run("--report", before.toString(), "--report", before.toString()).status() == 64, "duplicate option admitted");
            require(run("--report", directory.resolve("missing.json").toString()).status() == 1, "missing report not reported");
            Path legacy = Files.writeString(directory.resolve("legacy.json"), ExportReportClaimsFixtures.completed(false).toJson());
            require(run("--report", legacy.toString()).out().contains("UNAVAILABLE (schema one)"), "legacy coverage fabricated");
            require(run("--report", before.toString(), "--before", legacy.toString()).status() == 2, "legacy comparison fabricated");
            var out = new StringWriter();
            var err = new StringWriter();
            require(CoverageReportTool.run(new String[] {"--report", before.toString()}, new PrintWriter(out), new PrintWriter(err), () -> true) == 11,
                "CLI ignored cancellation");
            var failedOutput = new PrintWriter(new java.io.Writer() {
                @Override public void write(char[] text, int offset, int length) throws java.io.IOException { throw new java.io.IOException("closed pipe"); }
                @Override public void flush() { }
                @Override public void close() { }
            });
            require(CoverageReportTool.run(new String[] {"--report", before.toString()}, failedOutput,
                new PrintWriter(err), () -> false) == 1, "failed stdout reported success");
            require(CoverageReportTool.safe("a\t\n\033[31m\u202eλ🛠").equals("a\\t\\n\\u001b[31m\\u202eλ🛠"), "terminal controls passed through");
            require(Files.readString(before).equals(report("old name", List.of(100L, 102L, 104L), List.of(100L, 104L), List.of(100L, 102L, 104L))),
                "read-only CLI modified report");
            System.out.println("coverage-comparison=PASS cli=PASS cancellation-points=" + calls.get());
        }
        finally {
            try (var files = Files.list(directory)) { for (Path path : files.toList()) Files.delete(path); }
            Files.delete(directory);
        }
    }

    private static String report(String name, List<Long> decoded, List<Long> anchors, List<Long> visible) throws Exception {
        var base = CoverageReportClaimsSmoke.knownFixture();
        var function = base.functions().getFirst();
        var symbol = new FunctionSymbol(name, 100, 10);
        boolean unknown = decoded == null;
        var points = unknown ? null : new Points(decoded, anchors, visible);
        var source = new SourceCoverageInventory.FunctionInventory(symbol, "DECOMPILED", "",
            unknown ? null : (long) decoded.size(), unknown ? null : (long) anchors.size(), unknown ? null : (long) visible.size(),
            unknown ? "listing unavailable" : "", unknown ? "tokens unavailable" : "", points);
        var variables = new VariableCoverageInventory.FunctionInventory(symbol, true, List.of(), function.variables().totals(), function.variables().byKind());
        var row = new ExportCoverage.Function(symbol, source, variables, function.types(), function.signature(), function.typeProvenance());
        var coverage = new ExportCoverage(List.of(row), new SourceCoverageInventory.Union(1, unknown ? 1 : 0, unknown ? 1 : 0,
            unknown ? 0 : decoded.size(), unknown ? 0 : anchors.size(), unknown ? 0 : visible.size()), base.variables(), base.variablesByKind(),
            base.functionTypeUnion(), 0, List.of(), true);
        return ExportReportClaimsFixtures.completed(false, 1).toJsonWithCoverage(new CoverageReportClaims(PROFILE, coverage), () -> false);
    }

    private static Run run(String... arguments) {
        var out = new StringWriter();
        var err = new StringWriter();
        int code = CoverageReportTool.run(arguments, new PrintWriter(out), new PrintWriter(err), () -> false);
        return new Run(code, out.toString(), err.toString());
    }
    private static boolean has(List<CoverageComparison.Change> changes, String kind, String detail) {
        return changes.stream().anyMatch(change -> change.kind().equals(kind) && change.detail().equals(detail));
    }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
}

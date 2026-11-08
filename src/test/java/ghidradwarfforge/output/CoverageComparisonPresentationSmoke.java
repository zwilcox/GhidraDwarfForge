package ghidradwarfforge.output;

import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Read-only comparison admission, bounded display, exact counts and cancellation. */
public final class CoverageComparisonPresentationSmoke {
    public static void main(String[] args) throws Exception {
        var directory = Files.createTempDirectory("forge-gui-comparison-");
        try {
            var before = directory.resolve("earlier λ 🛠.json");
            var after = directory.resolve("current.json");
            String first = CoverageComparisonSmoke.report("earlier", List.of(100L, 102L, 104L), List.of(100L, 104L), List.of(100L, 102L, 104L));
            String second = CoverageComparisonSmoke.report("current", List.of(100L, 102L, 104L), List.of(102L, 104L), List.of(102L, 104L));
            Files.writeString(before, first);
            Files.writeString(after, second);
            String text = CoverageComparisonPresentation.compare(second, before, () -> false);
            require(text.contains("ANCHOR_LOST") && text.contains("LINE_VISIBILITY_LOST") && text.contains("0x64"), "display omitted changes");
            require(text.contains("does not prove declaration lineage") && text.contains("no referenced artifact"), "comparison authority limits missing");
            var old = ExportReportClaims.readWithCoverage(before, () -> false);
            var next = ExportReportClaims.readWithCoverage(after, () -> false);
            long changes = CoverageComparison.compare(old, next, ignored -> { }, () -> false).changes();
            String limited = CoverageComparisonPresentation.render(old, next, () -> false, 1);
            require(limited.contains("Display limit reached") && limited.contains("Reported changes: " + changes + "\n"), "display clipping changed totals or hid truncation");
            require(limited.length() < 3000, "bounded prefix unexpectedly retained whole changes");
            require(CoverageComparisonPresentation.compare(first, before, () -> false).contains("No differences in the compared evidence fields"),
                "identical report display missing limitations");
            var calls = new AtomicInteger();
            CoverageComparisonPresentation.render(old, next, () -> { calls.incrementAndGet(); return false; }, 1);
            int points = calls.get();
            for (int stop = 1; stop <= points; stop++) {
                int limit = stop;
                calls.set(0);
                try {
                    CoverageComparisonPresentation.render(old, next, () -> calls.incrementAndGet() >= limit, 1);
                    throw new AssertionError("display ignored cancellation after clipping");
                }
                catch (CancellationException expected) { }
            }
            try {
                CoverageComparisonPresentation.compare(second, directory.resolve("does-not-exist"), () -> true);
                throw new AssertionError("opened path before cancellation");
            }
            catch (CancellationException expected) { }
            var legacy = directory.resolve("legacy.json");
            Files.writeString(legacy, ExportReportClaimsFixtures.completed(false, 1).toJson());
            require(CoverageComparisonPresentation.compare(second, legacy, () -> false).contains("INCOMPARABLE"), "legacy report fabricated comparable coverage");
            var malformed = directory.resolve("malformed.json");
            Files.writeString(malformed, "{");
            try { CoverageComparisonPresentation.compare(second, malformed, () -> false); throw new AssertionError("malformed report accepted"); }
            catch (java.io.IOException expected) { }
            require(Files.readString(before).equals(first) && Files.readString(after).equals(second), "comparison changed selected reports");
            System.out.println("coverage-comparison-presentation=PASS cancellation-points=" + points + " read-only=true clipped-counts-exact=true");
        }
        finally {
            try (var files = Files.list(directory)) { for (var file : files.toList()) Files.delete(file); }
            Files.delete(directory);
        }
    }
    private static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
}

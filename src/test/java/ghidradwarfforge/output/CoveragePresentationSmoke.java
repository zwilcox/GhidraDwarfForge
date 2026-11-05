package ghidradwarfforge.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Display semantics and report publication must preserve unknowns and existing files. */
public final class CoveragePresentationSmoke {
    public static void main(String[] args) throws Exception {
        require(CoveragePresentation.ratio(null, 10L).equals("Unknown"), "unknown is not zero");
        require(CoveragePresentation.ratio(0L, 0L).equals("N/A (0/0)"), "empty is not full coverage");
        require(CoveragePresentation.ratio(Long.MAX_VALUE - 1, Long.MAX_VALUE).startsWith("99.99%"),
            "incomplete large population must not round to 100%");
        require(CoveragePresentation.ratio(1L, 3L).equals("33.33% (1/3)"), "exact counts remain visible");
        var claims = new CoverageReportClaims(new CoverageReportJson.Profile("x".repeat(65536), "gcc"),
            CoverageReportJsonSmoke.fixture());
        String summary = CoveragePresentation.summary(claims, "PARTIAL");
        require(summary.length() < 3000 && summary.contains("full value in saved report"), "bounded summary");
        require(summary.contains("Unknown (incomplete evidence)") && summary.contains("OVERFLOW") &&
            summary.contains("not execution coverage") && summary.contains("NOT_RUN"), "honest unavailable populations");
        var function = claims.coverage().functions().get(0);
        require(CoveragePresentation.cell(function, 3).equals("Unknown"), "table withholds unknown denominator");
        String details = CoveragePresentation.details(function);
        require(details.contains("USER_DEFINED") && details.contains("UNASSIGNED") && details.contains("unknown storage"),
            "declaration provenance and omission reason retained");

        require(details.contains("Token anchors: Unknown") && details.contains("Resolved types:"),
            "selection reveals complete metrics when table cells are narrow");
        var source = function.source();
        var longSource = new ghidradwarfforge.coverage.SourceCoverageInventory.FunctionInventory(
            source.function(), source.disposition(), "🛠".repeat(32768), source.decodedInstructions(),
            source.anchoredInstructions(), source.lineVisibleInstructions(), source.instructionUnavailableReason(),
            source.tokenUnavailableReason(), source.observedPoints());
        String bounded = CoveragePresentation.details(new ghidradwarfforge.coverage.ExportCoverage.Function(
            function.function(), longSource, function.variables(), function.types(), function.signature(), function.typeProvenance()));
        require(bounded.length() < 33000 && bounded.contains("Display limit reached"), "explicit bounded detail view");
        require(new String(bounded.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8).equals(bounded),
            "bounded details preserve Unicode boundaries");

        Path directory = Files.createTempDirectory("forge-report-save-");
        try {
            // A surrogate pair crosses the writer's chunk boundary.
            String report = "x".repeat(8191) + "🛠λ" + "y".repeat(20000);
            Path saved = directory.resolve("report λ.json");
            AtomicInteger calls = new AtomicInteger();
            ReportFileSave.writeNew(saved, report, () -> { calls.incrementAndGet(); return false; });
            require(java.util.Arrays.equals(Files.readAllBytes(saved), report.getBytes(StandardCharsets.UTF_8)),
                "complete UTF8 report saved across chunk boundary");
            reject(saved, "replacement");
            Path alias = directory.resolve("hardlink");
            Files.createLink(alias, saved);
            reject(alias, "replacement");
            if (!System.getProperty("os.name").startsWith("Windows")) {
                Path link = directory.resolve("symlink");
                Files.createSymbolicLink(link, saved);
                reject(link, "replacement");
                Path dangling = directory.resolve("dangling");
                Files.createSymbolicLink(dangling, directory.resolve("missing"));
                reject(dangling, "replacement");
                require(!Files.exists(directory.resolve("missing")), "dangling referent was created");
            }
            require(Files.readString(saved).equals(report), "existing report/aliases changed");
            long entries;
            try (var files = Files.list(directory)) { entries = files.count(); }
            for (int point = 1; point <= calls.get(); point++) {
                int stop = point;
                var checks = new AtomicInteger();
                Path cancelled = directory.resolve("cancelled.json");
                try {
                    ReportFileSave.writeNew(cancelled, report, () -> checks.incrementAndGet() >= stop);
                    throw new AssertionError("save ignored cancellation " + point);
                }
                catch (CancellationException expected) { }
                require(!Files.exists(cancelled), "cancelled report published");
                try (var files = Files.list(directory)) { require(files.count() == entries, "save stage leaked"); }
            }
            Path race = directory.resolve("race.json");
            var checks = new AtomicInteger();
            try {
                ReportFileSave.writeNew(race, report, () -> {
                    if (checks.incrementAndGet() == calls.get()) {
                        try { Files.writeString(race, "racing file"); }
                        catch (IOException failure) { throw new RuntimeException(failure); }
                    }
                    return false;
                });
                throw new AssertionError("racing file replaced");
            }
            catch (IOException expected) { }
            require(Files.readString(race).equals("racing file"), "racing file changed");
            try (var files = Files.list(directory)) { require(files.count() == entries + 1, "racing save stage leaked"); }
        }
        finally {
            try (var files = Files.list(directory)) {
                for (Path path : files.toList()) Files.delete(path);
            }
            Files.delete(directory);
        }
        System.out.println("coverage-presentation=PASS report-save=PASS");
    }

    private static void reject(Path selected, String report) throws Exception {
        try { ReportFileSave.writeNew(selected, report, () -> false); }
        catch (IOException expected) { return; }
        throw new AssertionError("existing file accepted: " + selected);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

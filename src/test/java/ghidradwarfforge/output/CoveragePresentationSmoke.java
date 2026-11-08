package ghidradwarfforge.output;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission;
import ghidradwarfforge.coverage.SourceCoverageInventory;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

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
        unknownVariableInventories(claims);
        var source = function.source();
        var longSource = new SourceCoverageInventory.FunctionInventory(
            source.function(), source.disposition(), "🛠".repeat(32768), source.decodedInstructions(),
            source.anchoredInstructions(), source.lineVisibleInstructions(), source.instructionUnavailableReason(),
            source.tokenUnavailableReason(), source.observedPoints());
        String bounded = CoveragePresentation.details(new ExportCoverage.Function(
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

    private static void unknownVariableInventories(CoverageReportClaims known) throws Exception {
        var symbol = new FunctionSymbol(
            "unknown_signature", 0x2000, 8);
        var graph = new TypeGraph(List.of());
        var lines = Dwarf5LineTable.buildWithPlan("fixture.c", ".", 8,
            ByteOrder.LITTLE_ENDIAN, List.of(symbol), List.of());
        var actual = new ExportEmission(graph, Map.of(), lines,
            List.of(new ExportEmission.FunctionEmission(symbol, null, List.of())));
        var unknown = ExportCoverage.build(null, null, List.of(), actual, () -> false);
        var function = unknown.functions().get(0);
        require(!function.variables().recoveredSignatureKnown(), "fixture has unknown variable inventory");
        for (int column : new int[] {5, 6}) {
            require(CoveragePresentation.cell(function, column).startsWith("Unknown"),
                "unavailable variable inventory must not be displayed as known empty: column " + column);
        }
        String details = CoveragePresentation.details(function);
        require(details.contains("Variables located: Unknown") && details.contains("Known-scope address bytes: Unknown"),
            "detail view preserves unknown variable inventory");
        var onlyUnknown = new CoverageReportClaims(known.profile(), unknown);
        String summary = CoveragePresentation.summary(onlyUnknown, "PARTIAL");
        require(summary.contains("Variables with a valid location: Unknown") &&
            summary.contains("Known-scope variable address bytes: Unknown"), "unknown-only summary must not infer an empty population");
        var base = known.coverage();
        var functions = new ArrayList<>(base.functions());
        functions.add(function);
        var source = base.sourceUnion();
        var mixed = new ExportCoverage(functions,
            new SourceCoverageInventory.Union(source.functions() + 1,
                source.unavailableInstructionFunctions() + 1, source.unavailableTokenFunctions() + 1,
                source.decodedInstructions(), source.anchoredInstructions(), source.lineVisibleInstructions()),
            base.variables(), base.variablesByKind(), base.functionTypeUnion(), 1,
            base.recoveredGlobals(), base.recoveredGlobalsKnown());
        summary = CoveragePresentation.summary(new CoverageReportClaims(known.profile(), mixed), "PARTIAL");
        require(summary.contains("Variables with a valid location: Unknown") &&
            summary.contains("1 unavailable function inventory") && summary.contains("observed declarations: 0/2 located"),
            "mixed summary must disclose unavailable populations while retaining observed counts");
        require(CoveragePresentation.cell(base.functions().get(0), 5).equals("0.00% (0/1)"),
            "known recovered variables retain their exact ratio");
        var voidType = new TypeGraph.TypeRef("void");
        var knownGraph = new TypeGraph(List.of(
            new TypeGraph.VoidType("void")));
        var signature = new ProgramTypeModel.FunctionSignature(symbol.name(), symbol.address(),
            voidType, List.of(), List.of(), false, false, "default", "USER_DEFINED");
        var model = new ProgramTypeModel(knownGraph, List.of(signature), List.of());
        var knownEmission = new ExportEmission(knownGraph,
            Map.of("void", List.of()), lines, List.of(
                new ExportEmission.FunctionEmission(symbol, signature, List.of())));
        var empty = ExportCoverage.build(model, null, List.of(), knownEmission, () -> false);
        require(CoveragePresentation.cell(empty.functions().get(0), 5).equals("N/A (0/0)") &&
            CoveragePresentation.cell(empty.functions().get(0), 6).startsWith("N/A (0/0)"),
            "known empty inventories remain distinct from unknown recovery");

        // Exercise the same strict reader and CLI path used by saved reports.
        var emptySource = new SyntheticSourceFile(new byte[0], List.of(), List.of());
        var emptyModel = new ProgramTypeModel(graph, List.of(), List.of());
        var report = ExportReport.completed(new DwarfTarget("x86_64", "x86_64", 8, true, "x86"),
            "fixture", Path.of("unopened-input"), "a".repeat(64), Path.of("unopened-sidecar"), "b".repeat(64),
            Path.of("unopened-source"), "c".repeat(64), 1, List.of(".debug_info"), emptySource, emptyModel,
            List.of(), List.of("recovery unavailable"));
        var typeEvidence = CoverageTypeEvidence.capture(null, actual, unknown, () -> false);
        String encoded = report.toJsonWithCoverage(new CoverageReportClaims(known.profile(), unknown, typeEvidence), () -> false);
        Path selected = Files.createTempFile("forge-unknown-inventory-", ".json");
        try {
            Files.writeString(selected, encoded);
            for (String[] options : new String[][] { {"--summary"}, {"--function", "0x2000"} }) {
                var arguments = new ArrayList<String>(List.of("--report", selected.toString()));
                arguments.addAll(List.of(options));
                var output = new StringWriter();
                var errors = new StringWriter();
                int status = CoverageReportTool.run(arguments.toArray(String[]::new),
                    new PrintWriter(output), new PrintWriter(errors), () -> false);
                require(status == 0 && errors.toString().isEmpty(), "unknown-inventory CLI rejected valid report");
                require(output.toString().contains("unavailable function inventory") &&
                    output.toString().contains("Unknown"), "CLI lost unknown-inventory evidence");
            }
            require(Files.readString(selected).equals(encoded), "CLI changed unknown-inventory report");
        }
        finally { Files.delete(selected); }
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

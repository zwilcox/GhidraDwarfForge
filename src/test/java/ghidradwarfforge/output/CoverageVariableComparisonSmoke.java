package ghidradwarfforge.output;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission.Kind;
import ghidradwarfforge.coverage.LocationCoverage;
import ghidradwarfforge.coverage.SourceCoverageInventory;
import ghidradwarfforge.coverage.VariableCoverageInventory;
import ghidradwarfforge.coverage.VariableCoverageInventory.*;
import ghidradwarfforge.coverage.VariableCoverageTotals;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.TypeGraph.TypeRef;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

/** Independent bit-set oracle and strict-report regressions for explicit binding correspondence. */
public final class CoverageVariableComparisonSmoke {
    private static final FunctionSymbol FUNCTION = new FunctionSymbol("f", 100, 40);
    private static final List<FunctionRange> SCOPE = List.of(new FunctionRange(100, 40));
    private static final TypeRef INT = new TypeRef("int");
    private static int checks;

    public static void main(String[] args) throws Exception {
        var old = local("saved", "outer", "display", ranges(104, 108), SCOPE, true);
        var next = local("saved", "outer", "display", ranges(108, 112), SCOPE, true);
        var changes = compare(List.of(old), List.of(next));
        require(has(changes, "VARIABLE_COMMON_SCOPE_COVERAGE_LOST", "[0x68,0x6c)") &&
            has(changes, "VARIABLE_COMMON_SCOPE_COVERAGE_GAINED", "[0x6c,0x70)"), "equal byte totals hide shifted location");
        require(inventory(List.of(old)).totals().equals(inventory(List.of(next)).totals()), "fixture count equality");
        var narrowed = local("saved", "outer", "display", ranges(108, 112), ranges(108, 140), true);
        changes = compare(List.of(old), List.of(narrowed));
        require(has(changes, "VARIABLE_SCOPE_RANGE_REMOVED", "[0x64,0x6c)") &&
            has(changes, "VARIABLE_LOCATION_RANGE_REMOVED", "[0x68,0x6c)") &&
            changes.stream().noneMatch(c -> c.kind().equals("VARIABLE_COMMON_SCOPE_COVERAGE_LOST")), "removed scope counted as comparable loss");
        var unknownOld = local("saved", "", "display", ranges(104, 108), List.of(), false);
        var unknownNew = local("saved", "", "display", ranges(108, 112), List.of(), false);
        changes = compare(List.of(unknownOld), List.of(unknownNew));
        require(has(changes, "VARIABLE_LOCATION_RANGE_REMOVED", "[0x68,0x6c)") &&
            changes.stream().noneMatch(c -> c.kind().contains("COMMON_SCOPE")), "unknown scope fabricated a denominator");
        var renamed = local("different", "outer", "display", ranges(108, 112), SCOPE, true);
        changes = compare(List.of(old), List.of(renamed));
        require(changes.size() == 2 && has(changes, "VARIABLE_BINDING_ADDED", "no declaration identity inferred") &&
            has(changes, "VARIABLE_BINDING_REMOVED", "no declaration identity inferred"), "local rename silently matched");
        var displayEdit = local("saved", "outer", "edited", ranges(104, 108), SCOPE, true);
        require(has(compare(List.of(old), List.of(displayEdit)), "VARIABLE_DISPLAY_NAME_CHANGED", "display -> edited"), "display edit lost");
        var shadow = local("saved", "inner", "display", ranges(116, 120), SCOPE, true);
        changes = compare(List.of(old, shadow), List.of(next, shadow));
        require(changes.stream().allMatch(c -> c.detail().contains("block=\"outer\"")), "same display name merged shadow binding");
        changes = compare(List.of(parameter("x", ranges(104, 108))), List.of(parameter("renamed", ranges(108, 112))));
        require(has(changes, "VARIABLE_INTERNAL_NAME_CHANGED", "x -> renamed") &&
            has(changes, "VARIABLE_COMMON_SCOPE_COVERAGE_LOST", "ordinal=0") &&
            changes.stream().noneMatch(c -> c.kind().contains("BINDING_")), "parameter ordinal did not define reported slot");
        changes = compare(List.of(staticVariable(4096)), List.of(staticVariable(8192)));
        require(changes.size() == 2 && has(changes, "VARIABLE_BINDING_ADDED", "address=0x2000"), "static address change silently matched");
        var absent = new Variable(old.identity(), old.displayName(), INT, null, old.declarationProvenance(), List.of(),
            new LocationCoverage(false, true, "fixture scope", SCOPE, List.of(), 40, 0, 0), "DECLARATION_NOT_EMITTED", "fixture omission");
        changes = compare(List.of(old), List.of(absent));
        require(has(changes, "VARIABLE_DECLARATION_EMISSION_CHANGED", "true -> false") &&
            has(changes, "VARIABLE_COMMON_SCOPE_COVERAGE_LOST", "[0x68,0x6c)"), "omitted declaration location loss hidden");
        var proof = new StorageEvidence(104, 108, "USER_DEFINED", "saved definition", "", "");
        var otherProof = new StorageEvidence(108, 112, "ANALYSIS", "instruction proof", "", "");
        require(compare(List.of(withStorage(old, List.of(proof, otherProof))),
            List.of(withStorage(old, List.of(otherProof, proof)))).isEmpty(), "storage order fabricated a change");
        changes = compare(List.of(withStorage(old, List.of(proof))), List.of(withStorage(old, List.of(proof, proof))));
        require(changes.size() == 1 && has(changes, "VARIABLE_STORAGE_EVIDENCE_CHANGED", "count=1 -> 2"), "storage multiplicity lost");
        var unknownPopulation = new FunctionInventory(FUNCTION, false, List.of(), inventory(List.of()).totals(), inventory(List.of()).byKind());
        changes.clear();
        CoverageVariableComparison.compare(inventory(List.of(old)), unknownPopulation, changes::add, () -> false);
        require(changes.size() == 1 && has(changes, "VARIABLE_POPULATION_EVIDENCE_CHANGED", "true -> false"), "unknown population treated as removed declarations");
        try { compare(List.of(old, old), List.of(next)); throw new AssertionError("duplicate binding accepted"); }
        catch (IllegalArgumentException expected) { checks++; }

        var calls = new AtomicInteger();
        var before = inventory(List.of(old, shadow, withStorage(parameter("x", ranges(104, 108)), List.of(proof))));
        var after = inventory(List.of(next, shadow, withStorage(parameter("renamed", ranges(108, 112)), List.of(otherProof))));
        CoverageVariableComparison.compare(before, after, ignored -> { }, () -> { calls.incrementAndGet(); return false; });
        int points = calls.get();
        for (int stop = 1; stop <= points; stop++) {
            int limit = stop;
            calls.set(0);
            try {
                CoverageVariableComparison.compare(before, after, ignored -> { }, () -> calls.incrementAndGet() >= limit);
                throw new AssertionError("ignored comparison cancellation " + stop);
            }
            catch (CancellationException expected) { }
        }
        for (int a = 0; a < 256; a++) {
            for (int b = 0; b < 256; b++) {
                var result = new ArrayList<FunctionRange>();
                CoverageVariableComparison.difference(bits(a), bits(b), result::add, () -> false);
                require(mask(result) == (a & ~b), "interval subtraction differs from independent bit-set oracle");
            }
        }
        var wide = new ArrayList<FunctionRange>();
        CoverageVariableComparison.difference(List.of(new FunctionRange(0, Long.MAX_VALUE)),
            List.of(new FunctionRange(1, Long.MAX_VALUE - 2)), wide::add, () -> false);
        require(wide.equals(List.of(new FunctionRange(0, 1), new FunctionRange(Long.MAX_VALUE - 1, 1))), "wide interval overflow");
        var many = new ArrayList<FunctionRange>();
        for (int i = 0; i < 20000; i++) many.add(new FunctionRange(4L * i, 1));
        calls.set(0);
        CoverageVariableComparison.difference(many, List.of(new FunctionRange(0, 80000)),
            ignored -> { throw new AssertionError("covered range remained"); }, () -> {
                if (calls.incrementAndGet() > 10 * many.size()) throw new AssertionError("quadratic interval traversal");
                return false;
            });
        var directory = Files.createTempDirectory("forge-variable-comparison-");
        try {
            var first = directory.resolve("before.json");
            var second = directory.resolve("after.json");
            var report = ExportReportClaimsFixtures.completed(false, 1);
            Files.writeString(first, report.toJsonWithCoverage(claims(before), () -> false));
            Files.writeString(second, report.toJsonWithCoverage(claims(after), () -> false));
            var typedBefore = ExportReportClaims.readWithCoverage(first, () -> false);
            var typedAfter = ExportReportClaims.readWithCoverage(second, () -> false);
            changes.clear();
            var result = CoverageComparison.compare(typedBefore, typedAfter, changes::add, () -> false);
            require(result.comparable() && has(changes, "VARIABLE_COMMON_SCOPE_COVERAGE_LOST", "[0x68,0x6c)"), "strict report comparison lost regression");
            require(changes.stream().noneMatch(c -> c.kind().startsWith("VARIABLE_COUNTS")), "equal-count fixture accidentally differs");
            require(result.reasons().stream().anyMatch(reason -> reason.contains("does not prove declaration lineage")), "identity qualification absent");
            var out = new java.io.StringWriter();
            var err = new java.io.StringWriter();
            int status = CoverageReportTool.run(new String[] {"--report", second.toString(), "--before", first.toString()},
                new java.io.PrintWriter(out), new java.io.PrintWriter(err), () -> false);
            require(status == 0 && err.toString().isEmpty() && out.toString().contains("VARIABLE_COMMON_SCOPE_COVERAGE_LOST"), "CLI omitted variable ranges");
        }
        finally {
            try (var files = Files.list(directory)) { for (var file : files.toList()) Files.delete(file); }
            Files.delete(directory);
        }
        System.out.println("coverage-variable-comparison=PASS checks=" + checks + " cancellation-points=" + points +
            " interval-cases=65536 deep-checkpoints=" + calls.get());
    }

    private static CoverageReportClaims claims(FunctionInventory inventory) {
        var base = CoverageReportClaimsSmoke.knownFixture();
        var original = base.functions().getFirst();
        var source = original.source();
        var row = new ExportCoverage.Function(FUNCTION, new SourceCoverageInventory.FunctionInventory(FUNCTION,
            source.disposition(), source.diagnostic(), source.decodedInstructions(), source.anchoredInstructions(), source.lineVisibleInstructions(),
            source.instructionUnavailableReason(), source.tokenUnavailableReason(), source.observedPoints()), inventory, original.types(),
            original.signature(), original.typeProvenance());
        return new CoverageReportClaims(new CoverageReportJson.Profile("x86:LE:64:default", "gcc"),
            new ExportCoverage(List.of(row), base.sourceUnion(), inventory.totals(), inventory.byKind(), base.functionTypeUnion(), 0, List.of(), true));
    }
    private static Variable local(String name, String block, String display, List<FunctionRange> locations, List<FunctionRange> scope, boolean complete) {
        long known = scope.stream().mapToLong(FunctionRange::size).sum(), located = locations.stream().mapToLong(FunctionRange::size).sum();
        long covered = 0;
        for (var a : locations) for (var b : scope) covered += Math.max(0, Math.min(a.endExclusive(), b.endExclusive()) - Math.max(a.address(), b.address()));
        return new Variable(new Identity(Kind.LOCAL, -1, name, block, null), display, INT, INT,
            new Provenance("USER_DEFINED", "USER_DEFINED", "LOCAL_DECLARATION"), List.of(),
            new LocationCoverage(true, complete, complete ? "fixture scope" : "unknown scope", scope, locations, known, covered, located),
            located == 0 ? "UNASSIGNED" : "", located == 0 ? "fixture has no storage" : "");
    }
    private static Variable parameter(String name, List<FunctionRange> locations) {
        var value = local(name, "", name, locations, SCOPE, true);
        return new Variable(new Identity(Kind.PARAMETER, 0, name, "", null), name, INT, INT,
            new Provenance("USER_DEFINED", "USER_DEFINED", "SIGNATURE"), List.of(), value.location(), "", "");
    }
    private static Variable staticVariable(long address) {
        var value = local("counter", "", "counter", SCOPE, List.of(), false);
        return new Variable(new Identity(Kind.FUNCTION_STATIC, -1, "counter", "", address), "counter", INT, INT,
            new Provenance("USER_DEFINED", "USER_DEFINED", "STATIC_DECLARATION"), List.of(), value.location(), "", "");
    }
    private static Variable withStorage(Variable value, List<StorageEvidence> storage) {
        return new Variable(value.identity(), value.displayName(), value.recoveredType(), value.emittedType(),
            value.declarationProvenance(), storage, value.location(), value.omissionReason(), value.diagnostic());
    }
    private static FunctionInventory inventory(List<Variable> variables) {
        var groups = new EnumMap<Kind, VariableCoverageTotals>(Kind.class);
        for (var kind : Kind.values()) groups.put(kind, VariableCoverageTotals.measure(variables.stream()
            .filter(v -> v.identity().kind() == kind).map(Variable::location).toList(), () -> false));
        return new FunctionInventory(FUNCTION, true, variables,
            VariableCoverageTotals.measure(variables.stream().map(Variable::location).toList(), () -> false), groups);
    }
    private static ArrayList<CoverageComparison.Change> compare(List<Variable> before, List<Variable> after) {
        var changes = new ArrayList<CoverageComparison.Change>();
        CoverageVariableComparison.compare(inventory(before), inventory(after), changes::add, () -> false);
        return changes;
    }
    private static List<FunctionRange> ranges(long start, long end) { return List.of(new FunctionRange(start, end - start)); }
    private static List<FunctionRange> bits(int mask) {
        var result = new ArrayList<FunctionRange>();
        for (int bit = 0; bit < 8;) {
            if ((mask & (1 << bit)) == 0) { bit++; continue; }
            int start = bit;
            while (bit < 8 && (mask & (1 << bit)) != 0) bit++;
            result.add(new FunctionRange(start, bit - start));
        }
        return result;
    }
    private static int mask(List<FunctionRange> ranges) {
        int result = 0;
        for (var range : ranges) for (long address = range.address(); address < range.endExclusive(); address++) result |= 1 << (int) address;
        return result;
    }
    private static boolean has(List<CoverageComparison.Change> changes, String kind, String detail) {
        return changes.stream().anyMatch(c -> c.kind().equals(kind) && c.detail().contains(detail));
    }
    private static void require(boolean value, String message) { checks++; if (!value) throw new AssertionError(message); }
}

package ghidradwarfforge.coverage;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.coverage.ExportEmission.ExpressionLocation;
import ghidradwarfforge.coverage.ExportEmission.ListLocation;
import ghidradwarfforge.coverage.ExportEmission.NoLocation;
import ghidradwarfforge.coverage.LocationCoverage.Visibility;
import ghidradwarfforge.dwarf.Dwarf5LocationLists;
import ghidradwarfforge.dwarf.Dwarf5LocationLists.PlannedRange;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

public final class LocationCoverageSmoke {
    private static int checks;

    public static void main(String[] args) {
        var registers = TargetRegisterMap.forTarget("x86_64");
        var evidence = new Evidence(Confidence.USER_DEFINED, "fixture storage evidence");
        var available = registers.register("RAX", 0, 64);
        var unknown = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "unproved storage");
        var variable = new VariableLocation("fixture", 100, "local", VariableKind.LOCAL, 8,
            List.of(new LocationRange(100, 110, unknown, evidence),
                new LocationRange(110, 140, available, evidence),
                new LocationRange(200, 210, available, evidence),
                new LocationRange(210, 220, unknown, evidence)));
        var lists = Dwarf5LocationLists.build(List.of(variable), 8, java.nio.ByteOrder.LITTLE_ENDIAN);
        var location = new ListLocation(lists.offsets().get(variable), lists.plans().get(variable));
        var body = List.of(new FunctionRange(100, 40), new FunctionRange(200, 20));
        var visibility = new Visibility(body, true, "explicit analyst scope");
        var covered = LocationCoverage.measure(location, body, visibility, () -> false);
        require(covered.knownScopeBytes() == 60 && covered.coveredScopeBytes() == 40 &&
            covered.locatedBytes() == 40 && covered.hasFullValueLocation() && covered.percentageApplicable(),
            "unknown storage gaps remain in the independently evidenced denominator");
        var duplicated = new ArrayList<>(body);
        duplicated.add(new FunctionRange(105, 20));
        duplicated.addAll(body);
        require(LocationCoverage.measure(location, duplicated, new Visibility(duplicated, true,
            visibility.evidence()), () -> false).equals(covered), "duplicate/overlapping scopes cannot inflate coverage");
        require(LocationCoverage.measure(location, body.reversed(), new Visibility(body.reversed(), true,
            visibility.evidence()), () -> false).equals(covered), "stable canonical ordering");
        var expression = new ExpressionLocation(lists.plans().get(variable).getFirst().expression());
        var stable = LocationCoverage.measure(expression, body, visibility, () -> false);
        require(stable.coveredScopeBytes() == 60 && stable.locatedBytes() == 60, "expression uses actual owner scope");
        var partialKnowledge = new Visibility(List.of(new FunctionRange(100, 20)), false, "remaining visibility unknown");
        var partial = LocationCoverage.measure(location, body, partialKnowledge, () -> false);
        require(partial.knownScopeBytes() == 20 && partial.coveredScopeBytes() == 10 && partial.locatedBytes() == 40 &&
            !partial.percentageApplicable(), "partial scope knowledge never becomes a whole-lifetime percentage");
        var noKnowledge = LocationCoverage.measure(expression, body,
            new Visibility(List.of(), false, "no lexical visibility evidence"), () -> false);
        require(noKnowledge.hasFullValueLocation() && noKnowledge.knownScopeBytes() == 0 &&
            noKnowledge.coveredScopeBytes() == 0 && !noKnowledge.percentageApplicable(),
            "stable physical storage does not establish lifetime");
        var absent = LocationCoverage.measure(null, body, visibility, () -> false);
        var omitted = LocationCoverage.measure(new NoLocation("UNSUPPORTED_STORAGE", "partial value rejected"),
            body, visibility, () -> false);
        require(!absent.declarationEmitted() && omitted.declarationEmitted() &&
            absent.knownScopeBytes() == 60 && omitted.knownScopeBytes() == 60 &&
            absent.coveredScopeBytes() == 0 && !omitted.hasFullValueLocation(),
            "unemitted and emitted-without-location declarations retain their recovered denominator");
        var disjoint = LocationCoverage.measure(location, body,
            new Visibility(List.of(new FunctionRange(100, 10)), true, "explicit unavailable scope"), () -> false);
        require(disjoint.knownScopeBytes() == 10 && disjoint.coveredScopeBytes() == 0 &&
            !disjoint.hasFullValueLocation(), "locations outside known visibility are not usable coverage");
        var noOwner = LocationCoverage.measure(location, List.of(), visibility, () -> false);
        require(!noOwner.hasFullValueLocation() && noOwner.knownScopeBytes() == 60,
            "raw location entries cannot escape actual DIE ownership");
        var empty = LocationCoverage.measure(expression, body,
            new Visibility(List.of(), true, "explicit empty scope"), () -> false);
        require(!empty.hasFullValueLocation() && !empty.percentageApplicable(), "zero denominator is N/A, never 100 percent");
        var maximal = List.of(new FunctionRange(0, Long.MAX_VALUE));
        var large = LocationCoverage.measure(expression, maximal,
            new Visibility(maximal, true, "maximum supported address domain"), () -> false);
        require(large.knownScopeBytes() == Long.MAX_VALUE && large.coveredScopeBytes() == Long.MAX_VALUE,
            "full supported address width does not overflow");
        var totals = VariableCoverageTotals.measure(List.of(covered, noKnowledge, omitted, absent), () -> false);
        require(totals.equals(new VariableCoverageTotals(4, 3, 2, 3, 1, 180L, 40L, "")) &&
            totals.variablePercentageApplicable() && totals.knownScopePercentageApplicable(),
            "unknown-scope variables are disclosed and excluded from extent sums, never from declaration counts");
        var noDeclarations = VariableCoverageTotals.measure(List.of(), () -> false);
        require(!noDeclarations.variablePercentageApplicable() && !noDeclarations.knownScopePercentageApplicable(),
            "empty aggregate denominators remain N/A");
        var overflowing = VariableCoverageTotals.measure(List.of(large, large), () -> false);
        require(overflowing.recoveredVariables() == 2 && overflowing.variablesWithLocation() == 2 &&
            overflowing.knownScopeBytes() == null && overflowing.coveredScopeBytes() == null &&
            overflowing.extentUnavailableReason().equals("OVERFLOW") && !overflowing.knownScopePercentageApplicable(),
            "aggregate extent overflow is explicit unavailable, not wrapped or fabricated zero");
        require(VariableCoverageTotals.measure(List.of(large), () -> false).knownScopeBytes() == Long.MAX_VALUE,
            "maximum nonoverflowing total remains exact");

        // Exhaustively count integer PCs independently for a bounded overlapping range fixture.
        var messyOwner = List.of(new FunctionRange(0, 35), new FunctionRange(25, 30), new FunctionRange(90, 25));
        var messyScope = List.of(new FunctionRange(5, 12), new FunctionRange(13, 26), new FunctionRange(100, 10));
        List<PlannedRange> ranges = new ArrayList<>();
        for (long[] span : new long[][] {{8, 21}, {30, 50}, {95, 106}}) {
            ranges.add(new PlannedRange(new LocationRange(span[0], span[1], available, evidence), expression.expression()));
        }
        var measured = LocationCoverage.measure(new ListLocation(12, ranges), messyOwner,
            new Visibility(messyScope, true, "enumerated oracle"), () -> false);
        long known = 0;
        long located = 0;
        for (long pc = 0; pc < 120; pc++) {
            long address = pc;
            if (messyScope.stream().anyMatch(r -> r.contains(address))) {
                known++;
                if (messyOwner.stream().anyMatch(r -> r.contains(address)) &&
                        ranges.stream().anyMatch(r -> address >= r.range().start() && address < r.range().end())) located++;
            }
        }
        require(measured.knownScopeBytes() == known && measured.coveredScopeBytes() == located,
            "independent exhaustive PC oracle agrees with interval arithmetic");
        AtomicInteger ticks = new AtomicInteger();
        LocationCoverage.measure(location, body, visibility, () -> { ticks.incrementAndGet(); return false; });
        for (int stop : new int[] {1, 4, 10, ticks.get()}) {
            AtomicInteger current = new AtomicInteger();
            try {
                LocationCoverage.measure(location, body, visibility, () -> current.incrementAndGet() == stop);
                throw new AssertionError("cancelled measurement returned counts");
            }
            catch (CancellationException expected) {
                require(current.get() == stop, "prompt measurement cancellation");
            }
        }
        AtomicInteger aggregateTicks = new AtomicInteger();
        try {
            VariableCoverageTotals.measure(List.of(covered, noKnowledge, omitted, absent),
                () -> aggregateTicks.incrementAndGet() == 3);
            throw new AssertionError("cancelled aggregate returned partial counts");
        }
        catch (CancellationException expected) {
            require(aggregateTicks.get() == 3, "aggregate cancellation retains no partial total");
        }
        System.out.println("location coverage smoke passed: " + checks + " checks");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

package ghidradwarfforge.coverage;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;

public final class SourceCoverageInventorySmoke {
    private static int checks;

    public static void main(String[] args) {
        var first = new FunctionSymbol("first", 100, List.of(new FunctionRange(100, 10), new FunctionRange(120, 4)));
        var overlap = new FunctionSymbol("overlap", 102, 4);
        var failed = new FunctionSymbol("failed", 200, 4);
        var omitted = new FunctionSymbol("omitted", 300, 4);
        var empty = new FunctionSymbol("empty", 400, 1);
        var functions = List.of(first, overlap, failed, omitted, empty);
        var source = SyntheticSourceFile.build("fixture", "test", List.of(
            new FunctionText("first", 100, "int first()\n{\n    return 1;\n}\n", null,
                List.of(new RelativeLine(3, List.of(102L, 103L, 120L, 999L)))),
            new FunctionText("overlap", 102, "int overlap()\n{\n    return 2;\n}\n", null,
                List.of(new RelativeLine(3, List.of(102L, 104L)))),
            new FunctionText("failed", 200, null, "fixture failure"),
            FunctionText.omitted("omitted", 300, "intentional fixture omission"),
            new FunctionText("empty", 400, "void empty() {}\n", null)));
        var decoded = List.of(new DecodedInstructions(first, List.of(100L, 102L, 104L, 120L), ""),
            new DecodedInstructions(overlap, List.of(102L, 104L), ""),
            new DecodedInstructions(failed, List.of(200L, 202L), ""),
            new DecodedInstructions(omitted, List.of(300L), ""),
            new DecodedInstructions(empty, List.of(), ""));
        for (int width : List.of(4, 8)) {
            for (ByteOrder order : List.of(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var lines = Dwarf5LineTable.buildWithPlan("fixture.c", ".", width, order, functions, source.mappedLines());
                var inventory = SourceCoverageInventory.build(functions, decoded, source, lines, () -> false);
                var a = inventory.functions().getFirst();
                var b = inventory.functions().get(1);
                require(a.observedPoints().anchored().equals(List.of(102L, 120L)) &&
                    b.observedPoints().anchored().equals(List.of(104L)), "only own surviving token rows count");
                require(a.decodedInstructions() == 4 && a.anchoredInstructions() == 2 && a.lineVisibleInstructions() == 4,
                    "declaration and other-function carry-forward do not become token anchors");
                require(inventory.observedUnion().equals(new SourceCoverageInventory.Union(5, 0, 0, 7, 3, 4)),
                    "program counts are unions, not sums of overlapping function counts");
                require(inventory.functions().get(2).disposition().equals("FAILED") &&
                    inventory.functions().get(2).decodedInstructions() == 2 && inventory.functions().get(2).anchoredInstructions() == 0,
                    "failed function retains the decoded denominator");
                require(inventory.functions().get(3).disposition().equals("OMITTED") &&
                    inventory.functions().get(3).diagnostic().equals("intentional fixture omission"), "intentional omission stays separate");
                require(inventory.functions().get(4).decodedInstructions() == 0 &&
                    !inventory.functions().get(4).tokenPercentageApplicable(), "empty population is N/A");
                var legacy = new SyntheticSourceFile(source.utf8(), source.functions(), source.mappedLines());
                var noTokens = SourceCoverageInventory.build(functions, decoded, legacy, lines, () -> false);
                require(noTokens.functions().getFirst().anchoredInstructions() == null &&
                    noTokens.functions().getFirst().lineVisibleInstructions() == 4 &&
                    noTokens.functions().getFirst().visibilityPercentageApplicable() &&
                    !noTokens.functions().getFirst().tokenPercentageApplicable(), "unknown tokens do not become zero anchors");
                require(noTokens.observedUnion().unavailableTokenFunctions() == 5 &&
                    !noTokens.observedUnion().tokenPercentageApplicable() && noTokens.observedUnion().visibilityPercentageApplicable(),
                    "aggregate exposes unavailable token populations");
                var incomplete = new ArrayList<>(decoded);
                incomplete.set(0, new DecodedInstructions(first, List.of(), "changed body"));
                var missing = SourceCoverageInventory.build(functions, incomplete, source, lines, () -> false);
                require(missing.functions().getFirst().decodedInstructions() == null &&
                    missing.functions().getFirst().observedPoints() == null &&
                    missing.functions().getFirst().instructionUnavailableReason().equals("changed body"), "unavailable listing has no invented denominator");
                require(missing.observedUnion().decodedInstructions() == 5 &&
                    missing.observedUnion().unavailableInstructionFunctions() == 1 &&
                    !missing.observedUnion().visibilityPercentageApplicable(), "observed subset is not full-program coverage");
                var absent = SourceCoverageInventory.build(functions, List.of(), null, lines, () -> false);
                require(absent.observedUnion().unavailableInstructionFunctions() == 5 &&
                    absent.functions().getFirst().disposition().equals("UNAVAILABLE"), "missing input evidence is explicit");
                require(SourceCoverageInventory.build(functions, decoded.reversed(), source, lines, () -> false).equals(inventory),
                    "input inventory ordering does not affect deterministic result");
                var alias = new ArrayList<>(functions);
                alias.add(new FunctionSymbol("alias", 100, first.ranges()));
                rejected(() -> SourceCoverageInventory.build(alias, decoded, source, lines, () -> false));
                rejected(() -> SourceCoverageInventory.build(functions.subList(1, functions.size()), decoded, source, lines, () -> false));
                var stale = new ArrayList<>(decoded);
                stale.set(0, new DecodedInstructions(new FunctionSymbol("first", 100, 24), List.of(100L), ""));
                rejected(() -> SourceCoverageInventory.build(functions, stale, source, lines, () -> false));
                AtomicInteger checkpoints = new AtomicInteger();
                SourceCoverageInventory.build(functions, decoded, source, lines, () -> { checkpoints.incrementAndGet(); return false; });
                for (int stop = 1; stop <= checkpoints.get(); stop++) {
                    final int limit = stop;
                    AtomicInteger calls = new AtomicInteger();
                    try {
                        SourceCoverageInventory.build(functions, decoded, source, lines, () -> calls.incrementAndGet() >= limit);
                        throw new AssertionError("ignored cancellation " + stop);
                    }
                    catch (CancellationException expected) { }
                }
                require(checkpoints.get() != 0, "all observed inventory/aggregation cancellation checkpoints exercised");
            }
        }
        System.out.println("source-coverage-inventory=PASS checks=" + checks + " widths=2 byte-orders=2");
    }

    private static void rejected(Runnable task) {
        try { task.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("ambiguous evidence accepted");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}

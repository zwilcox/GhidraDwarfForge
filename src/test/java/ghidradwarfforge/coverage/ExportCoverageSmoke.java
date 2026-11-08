package ghidradwarfforge.coverage;

import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.coverage.ExportEmission.*;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.*;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Combined populations must retain incomplete evidence even when shared types exist elsewhere. */
public final class ExportCoverageSmoke {
    public static void main(String[] args) {
        var integer = new TypeRef("int");
        var voidType = new TypeRef("void");
        var graph = new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED), new VoidType("void")));
        var local = new LocalVariable("x", 4, integer, 0, false, "USER_DEFINED");
        var signature = new FunctionSignature("f", 100, voidType, List.of(), List.of(local), false, false,
            "recorded", "USER_DEFINED");
        var restricted = new FunctionSignature("f", 100, voidType, List.of(), List.of(local), false, false,
            "recorded", "USER_DEFINED", false, "fixture ABI restriction", "effective");
        var failed = new FunctionSignature("failed", 200, integer,
            List.of(new Parameter("hidden", integer, false)), List.of(), false, false, "default", "ANALYSIS");
        var global = new GlobalVariable("global", 4096, 4, integer, false, "IMPORTED");
        var model = new ProgramTypeModel(graph, List.of(signature, failed), List.of(global));
        var functions = List.of(new FunctionSymbol("f", 100, 4), new FunctionSymbol("failed", 200, 4),
            new FunctionSymbol("unknown", 300, 4));
        var source = SyntheticSourceFile.build("fixture", "test", List.of(
            new FunctionText("f", 100, "void f() {}\n", null),
            new FunctionText("failed", 200, null, "fixture failure"),
            FunctionText.omitted("unknown", 300, "no source")));
        var lines = Dwarf5LineTable.buildWithPlan("fixture.c", ".", 8, ByteOrder.LITTLE_ENDIAN, functions, source.mappedLines());
        var actual = new ExportEmission(graph, Map.of("int", List.of(), "void", List.of()), lines,
            List.of(new FunctionEmission(functions.get(0), restricted, List.of(new VariableEmission(Kind.LOCAL,
                -1, "x", "x", "", integer, false, false, new NoLocation("UNASSIGNED", "no proven storage")))),
                new FunctionEmission(functions.get(1), null, List.of()), new FunctionEmission(functions.get(2), null, List.of())));
        var decoded = List.of(new DecodedInstructions(functions.get(0), List.of(100L), ""),
            new DecodedInstructions(functions.get(1), List.of(200L), ""),
            new DecodedInstructions(functions.get(2), List.of(), "listing unavailable"));
        var result = ExportCoverage.build(model, source, decoded, actual, () -> false);
        require(result.functions().size() == 3 && result.unknownSignatureFunctions() == 1, "unknown signature population");
        require(result.functions().get(2).types() == null && !result.functions().get(2).signature().recovered(),
            "missing signature is not zero type coverage");
        require(result.functions().get(1).types().notEmittedNodes() == 1 &&
            !result.functions().get(1).signature().emitted(), "globally allocated types do not fill failed function coverage");
        require(result.functionTypeUnion().equals(new TypeCoverage(2, 2, 2, 1, 1, 0, 0, 1, 1)),
            "type union counts canonical roots rather than summing repeated function graphs");
        require(!result.functionTypePercentageApplicable(), "unknown function prevents whole-population type percentage");
        require(result.variables().recoveredVariables() == 2 && result.variables().emittedVariables() == 1,
            "failed declaration remains in variable totals, global excluded");
        require(result.recoveredGlobalsKnown() && result.recoveredGlobals().equals(List.of(global)),
            "globals retained separately with explicitly recovered scope");
        require(result.functions().getFirst().signature().debuggerCallRestriction().equals("fixture ABI restriction") &&
            result.functions().getFirst().signature().emittedEffectiveCallingConvention().equals("effective") &&
            result.functions().getFirst().signature().recordedCallingConvention().equals("recorded"),
            "actual post-policy restrictions retained separately from recovered convention");
        require(result.functions().stream().allMatch(f -> f.typeProvenance().equals("UNKNOWN_PER_TYPE")),
            "signature source does not fabricate provenance of every reachable type");
        require(ExportCoverage.build(model, source, decoded.reversed(), actual, () -> false).equals(result), "deterministic assembly");
        var noModel = ExportCoverage.build(null, null, List.of(), new ExportEmission(new TypeGraph(List.of()), Map.of(), lines,
            List.of(new FunctionEmission(functions.getFirst(), null, List.of()))), () -> false);
        require(!noModel.recoveredGlobalsKnown() && noModel.unknownSignatureFunctions() == 1 &&
            noModel.sourceUnion().unavailableInstructionFunctions() == 1, "missing model/source/listing are explicit");
        AtomicInteger checkpoints = new AtomicInteger();
        ExportCoverage.build(model, source, decoded, actual, () -> { checkpoints.incrementAndGet(); return false; });
        for (int stop = 1; stop <= checkpoints.get(); stop++) {
            final int limit = stop;
            AtomicInteger calls = new AtomicInteger();
            try {
                ExportCoverage.build(model, source, decoded, actual, () -> calls.incrementAndGet() >= limit);
                throw new AssertionError("ignored cancellation at " + stop);
            }
            catch (CancellationException expected) { }
        }
        require(checkpoints.get() != 0, "all assembly cancellation checkpoints exercised");
        System.out.println("export-coverage-assembly=PASS cancellation-points=" + checkpoints.get());
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

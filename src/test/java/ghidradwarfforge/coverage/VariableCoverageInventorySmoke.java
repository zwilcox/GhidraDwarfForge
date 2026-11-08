package ghidradwarfforge.coverage;

import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;

import ghidradwarfforge.coverage.ExportEmission.*;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.dwarf.Dwarf5LocationLists.PlannedRange;
import ghidradwarfforge.dwarf.DwarfLocationExpression.AddressOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.LexicalScopeModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.*;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Hand-counted recovered/emitted populations, including unknown and absent declarations. */
public final class VariableCoverageInventorySmoke {
    private static int checks;
    private static final TypeRef TYPE = new TypeRef("int");
    private static final TypeGraph GRAPH = new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED)));
    private static final Expression EXPR = new Expression(List.of(new AddressOperation(4096)));
    private static final ExpressionLocation LOCATION = new ExpressionLocation(EXPR);
    private static final NoLocation OMITTED = new NoLocation("UNASSIGNED", "no proven full value");

    public static void main(String[] args) {
        var body = List.of(new FunctionRange(100, 10), new FunctionRange(120, 10));
        var block = List.of(new FunctionRange(103, 4), new FunctionRange(122, 3));
        var function = new FunctionSymbol("f", 100, body);
        var failedFunction = new FunctionSymbol("failed", 200, 6);
        var signature = signature("f", 100, List.of(new Parameter("arg", TYPE, false), new Parameter("arg", TYPE, false)),
            List.of(local("outer", "USER_DEFINED"), local("inner", "IMPORTED"),
                local("unknown", "DECOMPILER"), local("dropped", "ANALYSIS")));
        var failed = signature("failed", 200, List.of(new Parameter("hidden", TYPE, false)), List.of());
        var scope = new LexicalScopeModel(100, body,
            List.of(new LexicalScopeModel.Block("inner", "", block)),
            List.of(new LexicalScopeModel.Local("outer", "", "value"),
                new LexicalScopeModel.Local("inner", "inner", "value")), "explicit lexical fixture");
        var evidence = new Evidence(Confidence.ANALYSIS, "independent unavailable prefix");
        var unavailable = new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "entry value unproved");
        var storage = new VariableStorageModel(List.of(new VariableLocation("f", 100, "inner", VariableKind.LOCAL, 4,
            List.of(new LocationRange(103, 104, unavailable, evidence),
                new LocationRange(104, 107, new MemoryStorage(4096), new Evidence(Confidence.IMPORTED, "saved range")),
                new LocationRange(122, 125, new MemoryStorage(4096), evidence)))));
        var model = new ProgramTypeModel(GRAPH, List.of(signature, failed),
            List.of(new GlobalVariable("unrelated", 9000, 4, TYPE, false, "USER_DEFINED")), storage,
            List.of(new FunctionStaticVariable("root_static", 4096, 4, TYPE, 100, "EXPLICIT_STATIC_BINDING: USER_DEFINED"),
                new FunctionStaticVariable("nested_static", 4100, 4, TYPE, 100, "IMPORTED", "inner"),
                new FunctionStaticVariable("lost_static", 4104, 4, TYPE, 200, "USER_DEFINED")), List.of(), List.of(scope));
        var moving = new ListLocation(12, List.of(
            new PlannedRange(new LocationRange(104, 106, new MemoryStorage(4096), evidence), EXPR),
            new PlannedRange(new LocationRange(120, 124, new MemoryStorage(4096), evidence), EXPR)));
        var variables = List.of(
            emitted(Kind.PARAMETER, 0, "arg", "arg", "", LOCATION),
            emitted(Kind.PARAMETER, 1, "arg", "arg", "", OMITTED),
            emitted(Kind.LOCAL, -1, "outer", "value", "", LOCATION),
            emitted(Kind.LOCAL, -1, "inner", "value", "inner", moving),
            emitted(Kind.LOCAL, -1, "unknown", "unknown", "", OMITTED),
            emitted(Kind.FUNCTION_STATIC, -1, "root_static", "root_static", "", LOCATION),
            emitted(Kind.FUNCTION_STATIC, -1, "nested_static", "nested_static", "inner", LOCATION));
        var actual = emission(List.of(new FunctionEmission(function, signature, variables),
            new FunctionEmission(failedFunction, null, List.of())));
        var inventory = VariableCoverageInventory.build(model, actual, () -> false);
        require(inventory.totals().equals(new VariableCoverageTotals(10, 7, 5, 6, 4, 80L, 51L, "")),
            "independently hand-counted ten declarations, globals excluded, failed denominators retained");
        var first = inventory.functions().getFirst();
        require(first.variables().size() == 8 && first.totals().knownScopeBytes() == 74,
            "discontiguous bodies use actual ranges, not enclosing spans");
        require(first.variables().get(0).identity().parameterOrdinal() == 0 &&
            first.variables().get(1).identity().parameterOrdinal() == 1, "duplicate parameter names retain distinct ordinals");
        require(first.variables().getFirst().declarationProvenance().subject().equals("SIGNATURE"),
            "signature source is not mislabeled as per-parameter provenance");
        var inner = named(first, "inner");
        require(inner.displayName().equals("value") && inner.identity().block().equals("inner") &&
            named(first, "outer").displayName().equals("value"), "shadowed display names remain distinct declarations");
        require(inner.location().knownScopeBytes() == 7 && inner.location().coveredScopeBytes() == 4,
            "list locations clipped by independently evidenced lexical owner");
        require(inner.storageEvidence().size() == 3 && inner.storageEvidence().getFirst().category().equals("ANALYSIS") &&
            inner.storageEvidence().getFirst().omissionReason().equals("UNKNOWN_LIFETIME"),
            "unavailable prefix, range-specific provenance and omission remain visible");
        var root = named(first, "root_static");
        require(!root.location().scopeComplete() && root.location().hasFullValueLocation() &&
            root.identity().staticAddress() == 4096, "static memory address is not proof of visibility");
        require(root.declarationProvenance().category().equals("UNKNOWN") &&
            root.declarationProvenance().source().equals("EXPLICIT_STATIC_BINDING: USER_DEFINED"),
            "compound diagnostic is preserved without guessing its category");
        require(named(first, "nested_static").location().knownScopeBytes() == 7,
            "explicit block static has evidenced visibility");
        require(named(first, "dropped").omissionReason().equals("DECLARATION_NOT_EMITTED") &&
            named(first, "unknown").omissionReason().equals("UNASSIGNED"), "absent declaration differs from missing location");
        require(inventory.functions().get(1).variables().stream().allMatch(v ->
            v.omissionReason().equals("SIGNATURE_NOT_EMITTED") && !v.location().declarationEmitted()),
            "failed function retains parameter and static population");
        require(inventory.byKind().get(Kind.PARAMETER).recoveredVariables() == 3 &&
            inventory.byKind().get(Kind.LOCAL).recoveredVariables() == 4 &&
            inventory.byKind().get(Kind.FUNCTION_STATIC).recoveredVariables() == 3, "per-kind denominators partition the population");
        require(VariableCoverageInventory.build(model, actual, () -> false).equals(inventory), "deterministic repeat");
        var unknown = VariableCoverageInventory.build(null,
            emission(List.of(new FunctionEmission(function, null, List.of()))), () -> false);
        require(!unknown.functions().getFirst().recoveredSignatureKnown() && !unknown.totals().variablePercentageApplicable(),
            "missing recovered signature is explicitly unknown, not a proven empty population");
        var emptySignature = signature("empty", 300, List.of(), List.of());
        var emptyModel = new ProgramTypeModel(GRAPH, List.of(emptySignature), List.of());
        var empty = VariableCoverageInventory.build(emptyModel, emission(List.of(
            new FunctionEmission(new FunctionSymbol("empty", 300, 1), emptySignature, List.of()))), () -> false);
        require(empty.functions().getFirst().recoveredSignatureKnown() && !empty.totals().variablePercentageApplicable(),
            "known empty population remains distinct from unavailable recovery");
        rejected(() -> VariableCoverageInventory.build(null, actual, () -> false), "unmatched emitted declarations rejected");
        rejected(() -> VariableCoverageInventory.build(model, emission(List.of(actual.functions().getFirst())), () -> false),
            "unmatched recovered function cannot disappear from totals");
        rejected(() -> VariableCoverageInventory.build(model, emission(List.of(actual.functions().getFirst(),
            actual.functions().getFirst())), () -> false), "duplicate aliases cannot inflate totals");
        rejected(() -> VariableCoverageInventory.build(model, emission(List.of(new FunctionEmission(
            new FunctionSymbol("f", 100, 30), signature, variables), actual.functions().get(1))), () -> false),
            "stale lexical body evidence is rejected");
        var extra = new ArrayList<>(variables);
        extra.add(emitted(Kind.LOCAL, -1, "extra", "extra", "", LOCATION));
        rejected(() -> VariableCoverageInventory.build(model, emission(List.of(new FunctionEmission(function, signature, extra),
            actual.functions().get(1))), () -> false), "unexpected emitted declaration rejected");
        require(new ArrayList<>(inventory.byKind().keySet()).equals(List.of(Kind.PARAMETER, Kind.LOCAL, Kind.FUNCTION_STATIC)),
            "per-kind serialization order is stable across JVM map seeds");
        immutable(() -> inventory.byKind().clear());
        immutable(() -> first.variables().clear());
        immutable(() -> inner.storageEvidence().clear());
        var duplicateSignature = signature("duplicate", 400, List.of(), List.of(local("same", "ANALYSIS"), local("same", "ANALYSIS")));
        var duplicateModel = new ProgramTypeModel(GRAPH, List.of(duplicateSignature), List.of());
        rejected(() -> VariableCoverageInventory.build(duplicateModel, emission(List.of(new FunctionEmission(
            new FunctionSymbol("duplicate", 400, 4), null, List.of()))), () -> false),
            "duplicate recovered identities rejected even when declarations are absent");
        AtomicInteger checkpoints = new AtomicInteger();
        VariableCoverageInventory.build(model, actual, () -> { checkpoints.incrementAndGet(); return false; });
        for (int stop = 1; stop <= checkpoints.get(); stop++) {
            final int limit = stop;
            AtomicInteger calls = new AtomicInteger();
            try {
                VariableCoverageInventory.build(model, actual, () -> calls.incrementAndGet() >= limit);
                throw new AssertionError("ignored cancellation at " + limit);
            }
            catch (CancellationException expected) { }
        }
        require(checkpoints.get() > 100, "cancellation at every indexing/join/aggregation checkpoint");
        System.out.println("variable-coverage-inventory=PASS checks=" + checks + " cancellation-points=" + checkpoints.get());
    }

    private static VariableCoverageInventory.Variable named(VariableCoverageInventory.FunctionInventory function, String name) {
        return function.variables().stream().filter(v -> v.identity().internalName().equals(name)).findFirst().orElseThrow();
    }

    private static LocalVariable local(String name, String source) {
        return new LocalVariable(name, 4, TYPE, 0, false, source);
    }

    private static FunctionSignature signature(String name, long address, List<Parameter> params, List<LocalVariable> locals) {
        return new FunctionSignature(name, address, TYPE, params, locals, false, false, "default", "USER_DEFINED");
    }

    private static VariableEmission emitted(Kind kind, int ordinal, String name, String display, String block, Location location) {
        return new VariableEmission(kind, ordinal, name, display, block, TYPE, false, false, location);
    }

    private static ExportEmission emission(List<FunctionEmission> functions) {
        return new ExportEmission(GRAPH, Map.of("int", List.of()),
            Dwarf5LineTable.buildWithPlan("fixture.c", ".", 8, ByteOrder.LITTLE_ENDIAN, List.of(), List.of()), functions);
    }

    private static void rejected(Runnable task, String message) {
        try { task.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError(message);
    }

    private static void immutable(Runnable mutation) {
        try { mutation.run(); }
        catch (UnsupportedOperationException expected) { checks++; return; }
        throw new AssertionError("mutable inventory");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}

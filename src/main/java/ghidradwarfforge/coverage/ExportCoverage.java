package ghidradwarfforge.coverage;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.coverage.ExportEmission.FunctionEmission;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.ProgramTypeModel.GlobalVariable;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/**
 * Successful-production scorecard assembly. This is not a report wire format or
 * permission to publish artifacts. Run inside staging, before pair publication.
 */
public record ExportCoverage(List<Function> functions, SourceCoverageInventory.Union sourceUnion,
        VariableCoverageTotals variables, Map<ExportEmission.Kind, VariableCoverageTotals> variablesByKind,
        TypeCoverage functionTypeUnion, long unknownSignatureFunctions, List<GlobalVariable> recoveredGlobals,
        boolean recoveredGlobalsKnown) {
    public ExportCoverage {
        functions = List.copyOf(functions);
        Objects.requireNonNull(sourceUnion);
        Objects.requireNonNull(variables);
        // Preserve enum ordering across JVM seeds, as in the underlying inventory.
        var ordered = new java.util.EnumMap<ExportEmission.Kind, VariableCoverageTotals>(ExportEmission.Kind.class);
        for (var kind : ExportEmission.Kind.values()) ordered.put(kind, Objects.requireNonNull(variablesByKind.get(kind)));
        variablesByKind = java.util.Collections.unmodifiableMap(ordered);
        Objects.requireNonNull(functionTypeUnion);
        if (unknownSignatureFunctions < 0 || unknownSignatureFunctions > functions.size()) {
            throw new IllegalArgumentException("invalid unknown signature population");
        }
        recoveredGlobals = List.copyOf(recoveredGlobals);
        if (!recoveredGlobalsKnown && !recoveredGlobals.isEmpty()) {
            throw new IllegalArgumentException("unknown globals cannot supply a partial inventory");
        }
    }

    public record SignatureEvidence(boolean recovered, boolean emitted, String source,
            String recordedCallingConvention, String emittedEffectiveCallingConvention,
            String debuggerCallRestriction) { }

    /** Null types mean unavailable recovery, not a known empty or unresolved type graph. */
    public record Function(FunctionSymbol function, SourceCoverageInventory.FunctionInventory source,
            VariableCoverageInventory.FunctionInventory variables, TypeCoverage types,
            SignatureEvidence signature, String typeProvenance) { }

    public boolean functionTypePercentageApplicable() {
        return unknownSignatureFunctions == 0 && functionTypeUnion.applicable();
    }

    public static ExportCoverage build(ProgramTypeModel recovered, SyntheticSourceFile source,
            List<DecodedInstructions> decoded, ExportEmission actual, BooleanSupplier cancelled) {
        check(cancelled);
        Objects.requireNonNull(actual);
        List<FunctionSymbol> selected = new ArrayList<>();
        for (var function : actual.functions()) {
            check(cancelled);
            selected.add(function.function());
        }
        var sourceInventory = SourceCoverageInventory.build(selected, decoded, source, actual.lines(), cancelled);
        var variableInventory = VariableCoverageInventory.build(recovered, actual, cancelled);
        var typeIndex = new TypeCoverageIndex(recovered == null ? new TypeGraph(List.of()) : recovered.types(),
            actual.typeReferences(), cancelled);
        Map<Long, FunctionSignature> signatures = new HashMap<>();
        if (recovered != null) {
            for (var signature : recovered.functions()) {
                check(cancelled);
                if (signatures.put(signature.address(), signature) != null) {
                    throw new IllegalArgumentException("duplicate recovered signature");
                }
            }
        }
        List<Function> functions = new ArrayList<>();
        List<TypeRef> allRecovered = new ArrayList<>();
        List<TypeRef> allEmitted = new ArrayList<>();
        long unknown = 0;
        for (int ordinal = 0; ordinal < actual.functions().size(); ordinal++) {
            check(cancelled);
            FunctionEmission emitted = actual.functions().get(ordinal);
            var symbol = emitted.function();
            var variable = variableInventory.functions().get(ordinal);
            var lines = sourceInventory.functions().get(ordinal);
            if (!symbol.equals(variable.function()) || !symbol.equals(lines.function())) {
                throw new IllegalArgumentException("coverage inventories disagree on function identity");
            }
            var signature = signatures.get(symbol.address());
            TypeCoverage types = null;
            if (signature == null) {
                unknown++;
            }
            else {
                List<TypeRef> roots = new ArrayList<>();
                roots.add(signature.returnType());
                for (var declaration : variable.variables()) {
                    check(cancelled);
                    roots.add(declaration.recoveredType());
                }
                var emittedRoots = emitted.typeRoots();
                types = typeIndex.measure(roots, emittedRoots, cancelled);
                allRecovered.addAll(roots);
                allEmitted.addAll(emittedRoots);
            }
            var emittedSignature = emitted.signature();
            var evidence = new SignatureEvidence(signature != null, emittedSignature != null,
                signature == null ? "" : signature.signatureSource(),
                signature == null ? "" : signature.callingConvention(),
                emittedSignature == null ? "" : emittedSignature.effectiveCallingConvention(),
                emittedSignature == null ? "" : emittedSignature.debuggerCallRestriction());
            functions.add(new Function(symbol, lines, variable, types, evidence, "UNKNOWN_PER_TYPE"));
        }
        TypeCoverage union = typeIndex.measure(allRecovered, allEmitted, cancelled);
        check(cancelled);
        return new ExportCoverage(functions, sourceInventory.observedUnion(), variableInventory.totals(),
            variableInventory.byKind(), union, unknown, recovered == null ? List.of() : recovered.globals(), recovered != null);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("export coverage assembly cancelled");
    }
}

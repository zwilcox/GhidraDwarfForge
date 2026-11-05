package ghidradwarfforge.coverage;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import ghidradwarfforge.coverage.ExportEmission.FunctionEmission;
import ghidradwarfforge.coverage.ExportEmission.Kind;
import ghidradwarfforge.coverage.ExportEmission.NoLocation;
import ghidradwarfforge.coverage.ExportEmission.VariableEmission;
import ghidradwarfforge.coverage.LocationCoverage.Visibility;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.LexicalScopeModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.ProgramTypeModel.FunctionStaticVariable;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Joins recovered populations to successful emission without deriving scope from storage. */
public record VariableCoverageInventory(List<FunctionInventory> functions,
        VariableCoverageTotals totals, Map<Kind, VariableCoverageTotals> byKind) {
    public VariableCoverageInventory {
        functions = List.copyOf(functions);
        Objects.requireNonNull(totals);
        byKind = immutableTotals(byKind);
    }

    /** Export-local identity. Local names are not proof of identity across curation/renames. */
    public record Identity(Kind kind, int parameterOrdinal, String internalName, String block,
            Long staticAddress) { }

    /** Category applies only to the named subject; signature provenance is not parameter provenance. */
    public record Provenance(String category, String source, String subject) { }

    public record StorageEvidence(long start, long end, String category, String source,
            String omissionReason, String diagnostic) { }

    public record Variable(Identity identity, String displayName, TypeRef recoveredType,
            TypeRef emittedType, Provenance declarationProvenance, List<StorageEvidence> storageEvidence,
            LocationCoverage location, String omissionReason, String diagnostic) {
        public Variable {
            storageEvidence = List.copyOf(storageEvidence);
        }
    }

    public record FunctionInventory(FunctionSymbol function, boolean recoveredSignatureKnown,
            List<Variable> variables, VariableCoverageTotals totals,
            Map<Kind, VariableCoverageTotals> byKind) {
        public FunctionInventory {
            variables = List.copyOf(variables);
            byKind = immutableTotals(byKind);
        }
    }

    private record StorageKey(long function, VariableKind kind, String name) { }
    private record EmissionKey(Kind kind, int ordinal, String name, String block) {
        static EmissionKey of(VariableEmission variable) {
            return of(variable.kind(), variable.parameterOrdinal(), variable.internalName(), variable.block());
        }

        static EmissionKey of(Kind kind, int ordinal, String name, String block) {
            return new EmissionKey(kind, ordinal, kind == Kind.PARAMETER ? "" : name, block);
        }
    }

    private record ScopeIndex(LexicalScopeModel model, Map<String, LexicalScopeModel.Local> locals,
            Map<String, List<FunctionRange>> blocks) { }

    public static VariableCoverageInventory build(ProgramTypeModel recovered, ExportEmission emission,
            BooleanSupplier cancelled) {
        Objects.requireNonNull(emission);
        check(cancelled);
        Map<Long, FunctionSignature> signatures = new HashMap<>();
        Map<Long, List<FunctionStaticVariable>> statics = new HashMap<>();
        Map<Long, ScopeIndex> scopes = new HashMap<>();
        Map<StorageKey, List<StorageEvidence>> storage = new HashMap<>();
        if (recovered != null) {
            for (var signature : recovered.functions()) {
                check(cancelled);
                unique(signatures, signature.address(), signature, "recovered function");
            }
            for (var variable : recovered.functionStatics()) {
                check(cancelled);
                statics.computeIfAbsent(variable.ownerAddress(), unused -> new ArrayList<>()).add(variable);
            }
            for (var scope : recovered.lexicalScopes()) {
                check(cancelled);
                Map<String, LexicalScopeModel.Local> locals = new HashMap<>();
                Map<String, List<FunctionRange>> blocks = new HashMap<>();
                blocks.put("", scope.body());
                for (var local : scope.locals()) {
                    check(cancelled);
                    unique(locals, local.savedName(), local, "scoped local");
                }
                for (var block : scope.blocks()) {
                    check(cancelled);
                    unique(blocks, block.id(), block.ranges(), "lexical block");
                }
                unique(scopes, scope.functionAddress(), new ScopeIndex(scope, locals, blocks), "scope");
            }
            for (VariableLocation variable : recovered.variableStorage().variables()) {
                check(cancelled);
                List<StorageEvidence> evidence = new ArrayList<>();
                for (var range : variable.locations()) {
                    check(cancelled);
                    var omitted = range.storage() instanceof UnavailableStorage unavailable ? unavailable : null;
                    evidence.add(new StorageEvidence(range.start(), range.end(), range.evidence().confidence().name(),
                        range.evidence().source(), omitted == null ? "" : omitted.reason().name(),
                        omitted == null ? "" : omitted.diagnostic()));
                }
                unique(storage, new StorageKey(variable.functionAddress(), variable.kind(), variable.name()),
                    List.copyOf(evidence), "variable storage");
            }
        }
        List<FunctionInventory> functions = new ArrayList<>();
        List<Variable> all = new ArrayList<>();
        Map<Long, FunctionSymbol> owners = new HashMap<>();
        for (FunctionEmission actual : emission.functions()) {
            check(cancelled);
            FunctionSymbol function = actual.function();
            unique(owners, function.address(), function, "emitted primary function");
            FunctionSignature signature = signatures.remove(function.address());
            if (signature != null && !signature.name().equals(function.name())) {
                throw invalid("recovered/emitted function identity differs");
            }
            if (signature == null && (actual.signature() != null || !actual.variables().isEmpty())) {
                throw invalid("emitted declarations have no recovered signature");
            }
            ScopeIndex scope = scopes.get(function.address());
            if (scope != null && !scope.model().body().equals(function.ranges())) {
                throw invalid("recovered scope body differs from emitted function");
            }
            Map<EmissionKey, VariableEmission> emitted = new LinkedHashMap<>();
            for (var variable : actual.variables()) {
                check(cancelled);
                unique(emitted, EmissionKey.of(variable), variable, "emitted variable");
            }
            List<Variable> variables = new ArrayList<>();
            if (signature != null) {
                for (int ordinal = 0; ordinal < signature.parameters().size(); ordinal++) {
                    check(cancelled);
                    var parameter = signature.parameters().get(ordinal);
                    variables.add(variable(new Identity(Kind.PARAMETER, ordinal, parameter.name(), "", null),
                        parameter.name(), parameter.type(), provenance(signature.signatureSource(), "SIGNATURE"),
                        storage.getOrDefault(new StorageKey(function.address(), VariableKind.PARAMETER, parameter.name()), List.of()),
                        actual, emitted, function.ranges(),
                        new Visibility(function.ranges(), true, "FORMAL_PARAMETER_SCOPE"), cancelled));
                }
                for (var local : signature.locals()) {
                    check(cancelled);
                    var binding = scope == null ? null : scope.locals().get(local.name());
                    String block = binding == null ? "" : binding.block();
                    List<FunctionRange> owner = block.isEmpty() ? function.ranges() : scope.blocks().get(block);
                    Visibility visibility = binding == null ? unknownVisibility() :
                        new Visibility(scope.blocks().get(block), true, scope.model().evidence());
                    variables.add(variable(new Identity(Kind.LOCAL, -1, local.name(), block, null),
                        binding == null ? local.name() : binding.displayName(), local.type(), provenance(local.source(), "LOCAL_DECLARATION"),
                        storage.getOrDefault(new StorageKey(function.address(), VariableKind.LOCAL, local.name()), List.of()),
                        actual, emitted, owner, visibility, cancelled));
                }
                for (var variable : statics.getOrDefault(function.address(), List.of())) {
                    check(cancelled);
                    List<FunctionRange> owner = variable.block().isEmpty() ? function.ranges() :
                        Objects.requireNonNull(scope, "static scope").blocks().get(variable.block());
                    Visibility visibility = variable.block().isEmpty() ? unknownVisibility() :
                        new Visibility(owner, true, scope.model().evidence());
                    variables.add(variable(new Identity(Kind.FUNCTION_STATIC, -1, variable.name(), variable.block(), variable.address()),
                        variable.name(), variable.type(), provenance(variable.source(), "STATIC_DECLARATION"), List.of(),
                        actual, emitted, owner, visibility, cancelled));
                }
            }
            if (!emitted.isEmpty()) throw invalid("emitted variable has no recovered declaration");
            var recoveredKeys = new HashSet<EmissionKey>();
            for (var variable : variables) {
                check(cancelled);
                var id = variable.identity();
                if (!recoveredKeys.add(EmissionKey.of(id.kind(), id.parameterOrdinal(), id.internalName(), id.block()))) {
                    throw invalid("ambiguous recovered declaration");
                }
            }
            all.addAll(variables);
            functions.add(new FunctionInventory(function, signature != null, variables,
                totals(variables, cancelled), totalsByKind(variables, cancelled)));
        }
        if (!signatures.isEmpty()) throw invalid("recovered function missing from emitted primary inventory");
        return new VariableCoverageInventory(functions, totals(all, cancelled), totalsByKind(all, cancelled));
    }

    private static Variable variable(Identity identity, String displayName, TypeRef type, Provenance provenance,
            List<StorageEvidence> storage, FunctionEmission function, Map<EmissionKey, VariableEmission> emitted,
            List<FunctionRange> owner, Visibility visibility, BooleanSupplier cancelled) {
        VariableEmission actual = emitted.remove(EmissionKey.of(identity.kind(), identity.parameterOrdinal(),
            identity.internalName(), identity.block()));
        if (actual != null && (!actual.internalName().equals(identity.internalName()) ||
                !actual.displayName().equals(displayName))) {
            throw invalid("recovered/emitted declaration identity differs");
        }
        var location = LocationCoverage.measure(actual == null ? null : actual.location(), owner, visibility, cancelled);
        String reason = "";
        String diagnostic = "";
        if (actual == null) {
            reason = function.signature() == null ? "SIGNATURE_NOT_EMITTED" : "DECLARATION_NOT_EMITTED";
            diagnostic = "Recovered declaration is absent from the successful producer inventory";
        }
        else if (actual.location() instanceof NoLocation omitted) {
            reason = omitted.reason();
            diagnostic = omitted.diagnostic();
        }
        else if (!location.hasFullValueLocation()) {
            reason = "NO_LOCATION_INSIDE_SCOPE";
            diagnostic = "Emitted storage has no extent inside its owner and known visibility";
        }
        return new Variable(identity, displayName, type, actual == null ? null : actual.type(), provenance,
            storage, location, reason, diagnostic);
    }

    private static Provenance provenance(String source, String subject) {
        // Compound extractor diagnostics are preserved verbatim, never guessed from keywords.
        String category = switch (source) {
            case "USER_DEFINED", "IMPORTED", "ANALYSIS", "DECOMPILER" -> source;
            default -> "UNKNOWN";
        };
        return new Provenance(category, source, subject);
    }

    private static Map<Kind, VariableCoverageTotals> immutableTotals(Map<Kind, VariableCoverageTotals> totals) {
        Map<Kind, VariableCoverageTotals> ordered = new EnumMap<>(Kind.class);
        for (Kind kind : Kind.values()) ordered.put(kind, Objects.requireNonNull(totals.get(kind)));
        return Collections.unmodifiableMap(ordered);
    }

    private static Visibility unknownVisibility() {
        return new Visibility(List.of(), false, "NO_EXPLICIT_VISIBILITY_EVIDENCE");
    }

    private static VariableCoverageTotals totals(List<Variable> variables, BooleanSupplier cancelled) {
        List<LocationCoverage> locations = new ArrayList<>();
        for (var variable : variables) {
            check(cancelled);
            locations.add(variable.location());
        }
        return VariableCoverageTotals.measure(locations, cancelled);
    }

    private static Map<Kind, VariableCoverageTotals> totalsByKind(List<Variable> variables, BooleanSupplier cancelled) {
        Map<Kind, List<Variable>> groups = new EnumMap<>(Kind.class);
        for (Kind kind : Kind.values()) groups.put(kind, new ArrayList<>());
        for (var variable : variables) {
            check(cancelled);
            groups.get(variable.identity().kind()).add(variable);
        }
        Map<Kind, VariableCoverageTotals> result = new EnumMap<>(Kind.class);
        for (Kind kind : Kind.values()) result.put(kind, totals(groups.get(kind), cancelled));
        return result;
    }

    private static <K, V> void unique(Map<K, V> map, K key, V value, String subject) {
        if (map.putIfAbsent(key, value) != null) throw invalid("ambiguous " + subject);
    }

    private static IllegalArgumentException invalid(String message) {
        return new IllegalArgumentException(message);
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("variable inventory cancelled");
    }
}

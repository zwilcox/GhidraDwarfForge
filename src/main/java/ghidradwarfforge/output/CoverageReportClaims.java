package ghidradwarfforge.output;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.BooleanSupplier;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission.Kind;
import ghidradwarfforge.coverage.LocationCoverage;
import ghidradwarfforge.coverage.SourceCoverageIndex;
import ghidradwarfforge.coverage.SourceCoverageInventory;
import ghidradwarfforge.coverage.TypeCoverage;
import ghidradwarfforge.coverage.TypeGraphEvidence;
import ghidradwarfforge.coverage.VariableCoverageInventory;
import ghidradwarfforge.coverage.VariableCoverageTotals;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.ProgramTypeModel.GlobalVariable;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/**
 * Structurally consistent reported metrics, not verified original/source/DWARF
 * facts or attachment authority. No referenced artifact is opened. Type-union
 * counts cannot establish canonical graph identity without the producer graph.
 */
public record CoverageReportClaims(CoverageReportJson.Profile profile, ExportCoverage coverage,
        CoverageTypeEvidence typeEvidence) {
    /** Legacy definition one remains byte-compatible and has no individual graph evidence. */
    public CoverageReportClaims(CoverageReportJson.Profile profile, ExportCoverage coverage) { this(profile, coverage, null); }
    public int definitionVersion() { return typeEvidence == null ? 1 : 2; }
    public CoverageReportClaims {
        java.util.Objects.requireNonNull(profile);
        java.util.Objects.requireNonNull(coverage);
    }

    public static CoverageReportClaims read(Path input, BooleanSupplier cancelled) throws IOException {
        ReportJsonReader.checkCancelled(cancelled);
        return read(Files.newInputStream(input), cancelled, ReportJsonReader.DEFAULT_LIMITS);
    }

    /** Package-private owned-stream and small-budget seam; no referenced paths are accessed. */
    static CoverageReportClaims read(InputStream input, BooleanSupplier cancelled, ReportJsonReader.Limits limits) throws IOException {
        CoverageReportClaims result;
        try (var json = new JsonReader(new ReportJsonReader(input, cancelled, limits))) {
            json.setLenient(false);
            result = parse(new Parser(json, cancelled, limits));
            if (json.peek() != JsonToken.END_DOCUMENT) throw new IOException("trailing coverage content");
        }
        ReportJsonReader.checkCancelled(cancelled);
        return result;
    }

    /** Embedded decoding shares the root report's stream and total value budget. */
    static CoverageReportClaims read(ReportValueReader parent) throws IOException {
        return parse(new Parser(parent));
    }

    private static CoverageReportClaims parse(Parser parser) throws IOException {
        try {
            return parser.document();
        }
        catch (IllegalArgumentException | ArithmeticException malformed) {
            throw new IOException("invalid coverage claims: " + malformed.getMessage(), malformed);
        }
    }

    private record VariableKey(Kind kind, int ordinal, String name, String block) { }
    private record StorageRange(long start, long end, int detail) { }
    private record OwnedVariable(long owner, VariableCoverageInventory.Variable variable, List<StorageRange> storage) { }
    private record FunctionFields(FunctionSymbol symbol, SourceCoverageInventory.FunctionInventory source,
            ExportCoverage.SignatureEvidence signature, TypeCoverage types, VariableCoverageTotals variables,
            Map<Kind, VariableCoverageTotals> byKind, String typeProvenance) { }
    private record Summary(long functions, long unknownSignatures, boolean globalsKnown, long globals,
            SourceCoverageInventory.Union source, VariableCoverageTotals variables,
            Map<Kind, VariableCoverageTotals> byKind, TypeCoverage types) { }

    private static final class Parser extends ReportValueReader {
        private static final Set<String> ROOT = Set.of("definitionVersion", "addressModel", "profile", "summary",
            "functions", "variables", "recoveredGlobals", "storageEvidenceDetails");
        private static final List<String> TYPE_FIELDS = List.of("recoveredRoots", "emittedRoots", "opaqueFreeEmittedRoots",
            "recoveredNodes", "resolvedEmittedNodes", "opaqueEmittedNodes", "notEmittedNodes", "implicitVoidNodes", "emittedImplicitVoidNodes");
        private static final Set<String> VARIABLE_TOTALS = Set.of("recoveredVariables", "emittedVariables", "variablesWithLocation",
            "knownScopeVariables", "unknownScopeVariables", "knownScopeBytes", "coveredScopeBytes", "extentUnavailableReason");
        private static final Set<String> CATEGORIES = Set.of("USER_DEFINED", "IMPORTED", "ANALYSIS", "DECOMPILER");

        Parser(JsonReader json, BooleanSupplier cancelled, ReportJsonReader.Limits limits) { super(json, cancelled, limits, ValuePopulation.COVERAGE); }
        Parser(ReportValueReader parent) { super(parent, ValuePopulation.COVERAGE); }

        CoverageReportClaims document() throws IOException {
            Map<String, Object> root = new HashMap<>();
            object("coverage", ROOT, Set.of("typeNodes", "functionTypeRoots"), name -> root.put(name, switch (name) {
                case "definitionVersion" -> integer();
                case "addressModel" -> text(true);
                case "profile" -> profile();
                case "summary" -> summary();
                case "functions" -> list(this::function);
                case "variables" -> list(this::variable);
                case "recoveredGlobals" -> list(this::global);
                case "storageEvidenceDetails" -> storageDetails();
                case "typeNodes" -> list(this::typeNode);
                case "functionTypeRoots" -> typeRoots();
                default -> throw new AssertionError();
            }));
            int definition = get(root, "definitionVersion");
            require(definition == 1 || definition == 2, "unsupported metric definition");
            require((definition == 2) == root.containsKey("typeNodes") &&
                (definition == 2) == root.containsKey("functionTypeRoots"), "type evidence differs from definition version");
            require(root.get("addressModel").equals("ELF_LINK_TIME"), "unsupported address model");
            Summary summary = get(root, "summary");
            List<FunctionFields> functions = get(root, "functions");
            List<OwnedVariable> variables = get(root, "variables");
            List<GlobalVariable> globals = get(root, "recoveredGlobals");
            List<CoverageReportJson.StorageDetail> details = get(root, "storageEvidenceDetails");
            boolean[] usedDetails = new boolean[details.size()];
            require(summary.functions() == functions.size() && summary.globals() == globals.size(), "summary cardinalities");
            Map<Long, FunctionFields> owners = new HashMap<>();
            for (var function : functions) {
                check();
                require(owners.putIfAbsent(function.symbol().address(), function) == null, "duplicate primary/alias entry");
            }
            Map<Long, List<VariableCoverageInventory.Variable>> grouped = new HashMap<>();
            Map<Long, Set<VariableKey>> keys = new HashMap<>();
            List<LocationCoverage> allLocations = new ArrayList<>();
            Map<Kind, List<LocationCoverage>> allKinds = groups();
            for (var row : variables) {
                check();
                var owner = owners.get(row.owner());
                require(owner != null, "variable owner is missing");
                var variable = resolveStorage(row, details, usedDetails);
                var identity = variable.identity();
                var key = new VariableKey(identity.kind(), identity.parameterOrdinal(),
                    identity.kind() == Kind.PARAMETER ? "" : identity.internalName(), identity.block());
                require(keys.computeIfAbsent(row.owner(), unused -> new HashSet<>()).add(key), "duplicate variable identity");
                require(containsRanges(owner.symbol().ranges(), variable.location().knownScopeRanges()) &&
                    containsRanges(owner.symbol().ranges(), variable.location().locatedRanges()), "variable ranges outside function");
                require(owner.signature().recovered(), "variable without recovered signature");
                require(owner.signature().emitted() || !variable.location().declarationEmitted(), "emitted variable without emitted signature");
                if (identity.kind() == Kind.PARAMETER) {
                    var expectedScope = LocationCoverage.measure(null, List.of(),
                        new LocationCoverage.Visibility(owner.symbol().ranges(), true, "FORMAL_PARAMETER_SCOPE"), cancelled);
                    require(variable.location().scopeComplete() && variable.location().knownScopeRanges().equals(expectedScope.knownScopeRanges()),
                        "formal scope differs from function body");
                }
                if (identity.kind() == Kind.FUNCTION_STATIC && identity.block().isEmpty()) {
                    require(!variable.location().scopeComplete(), "root static invents visibility");
                }
                grouped.computeIfAbsent(row.owner(), unused -> new ArrayList<>()).add(variable);
                allLocations.add(variable.location());
                allKinds.get(identity.kind()).add(variable.location());
            }
            for (boolean used : usedDetails) { check(); require(used, "unreferenced storage evidence detail"); }
            List<ExportCoverage.Function> result = new ArrayList<>();
            var decoded = new TreeSet<Long>();
            var anchored = new TreeSet<Long>();
            var visible = new TreeSet<Long>();
            long unknownSignatures = 0;
            long unknownInstructions = 0;
            long unknownTokens = 0;
            for (var function : functions) {
                check();
                List<VariableCoverageInventory.Variable> locals = grouped.getOrDefault(function.symbol().address(), List.of());
                List<LocationCoverage> locations = new ArrayList<>();
                var byKind = groups();
                var ordinals = new TreeSet<Integer>();
                for (var variable : locals) {
                    check();
                    locations.add(variable.location());
                    byKind.get(variable.identity().kind()).add(variable.location());
                    if (variable.identity().kind() == Kind.PARAMETER) ordinals.add(variable.identity().parameterOrdinal());
                }
                int expectedOrdinal = 0;
                for (int ordinal : ordinals) require(ordinal == expectedOrdinal++, "noncontiguous parameter ordinals");
                require(VariableCoverageTotals.measure(locations, cancelled).equals(function.variables()), "function variable totals");
                require(totals(byKind).equals(function.byKind()), "function per-kind totals");
                var source = function.source();
                if (!source.instructionUnavailableReason().isEmpty()) unknownInstructions++;
                if (!source.tokenUnavailableReason().isEmpty()) unknownTokens++;
                if (source.observedPoints() != null) {
                    add(decoded, source.observedPoints().decoded());
                    add(anchored, source.observedPoints().anchored());
                    add(visible, source.observedPoints().lineVisible());
                }
                if (!function.signature().recovered()) unknownSignatures++;
                result.add(new ExportCoverage.Function(function.symbol(), source,
                    new VariableCoverageInventory.FunctionInventory(function.symbol(), function.signature().recovered(),
                        locals, function.variables(), function.byKind()), function.types(), function.signature(), function.typeProvenance()));
            }
            validateTypeUnion(functions, summary.types());
            require(summary.unknownSignatures() == unknownSignatures, "unknown signature count");
            require(summary.source().equals(new SourceCoverageInventory.Union(functions.size(), unknownInstructions, unknownTokens,
                decoded.size(), anchored.size(), visible.size())), "source union counts");
            require(summary.variables().equals(VariableCoverageTotals.measure(allLocations, cancelled)), "aggregate variable totals");
            require(summary.byKind().equals(totals(allKinds)), "aggregate per-kind totals");
            var coverage = new ExportCoverage(result, summary.source(), summary.variables(),
                summary.byKind(), summary.types(), unknownSignatures, globals, summary.globalsKnown());
            CoverageTypeEvidence evidence = null;
            if (definition == 2) {
                evidence = new CoverageTypeEvidence(TypeGraphEvidence.of(get(root, "typeNodes"), cancelled), get(root, "functionTypeRoots"));
                evidence.validate(coverage, cancelled);
            }
            return new CoverageReportClaims(get(root, "profile"), coverage, evidence);
        }

        private TypeGraphEvidence.Node typeNode() throws IOException {
            var row = fields("type node", Set.of("key", "name", "definitionKind", "byteSize", "kind", "emitted",
                "recoveredReferences", "emittedReferences", "diagnostic"), name -> switch (name) {
                    case "byteSize" -> decimal();
                    case "emitted" -> flag();
                    case "recoveredReferences", "emittedReferences" -> typeReferences();
                    case "diagnostic" -> text(false);
                    default -> text(true);
                });
            return new TypeGraphEvidence.Node(get(row, "key"), get(row, "name"), get(row, "definitionKind"),
                get(row, "byteSize"), TypeGraphEvidence.Kind.valueOf(get(row, "kind")), get(row, "emitted"),
                get(row, "recoveredReferences"), get(row, "emittedReferences"), get(row, "diagnostic"));
        }

        private Map<String, Integer> typeReferences() throws IOException {
            var result = new java.util.TreeMap<String, Integer>();
            array(() -> {
                var edge = fields("type reference", Set.of("key", "count"), name -> name.equals("key") ? text(true) : decimal());
                long count = get(edge, "count");
                require(count > 0 && count <= Integer.MAX_VALUE, "invalid type edge count");
                require(result.put(get(edge, "key"), (int) count) == null, "duplicate type edge");
            });
            return result;
        }

        private Map<Long, CoverageTypeEvidence.Roots> typeRoots() throws IOException {
            var result = new java.util.TreeMap<Long, CoverageTypeEvidence.Roots>();
            array(() -> {
                var row = fields("function type roots", Set.of("entry", "recovered", "emitted"), name ->
                    name.equals("entry") ? supportedAddress() : list(() -> new TypeRef(text(true))));
                require(result.put(get(row, "entry"), new CoverageTypeEvidence.Roots(get(row, "recovered"), get(row, "emitted"))) == null,
                    "duplicate type root owner");
            });
            return result;
        }

        private CoverageReportJson.Profile profile() throws IOException {
            var fields = fields("profile", Set.of("languageId", "compilerSpecId"), name -> text(true));
            return new CoverageReportJson.Profile(get(fields, "languageId"), get(fields, "compilerSpecId"));
        }

        private Summary summary() throws IOException {
            var fields = fields("coverage summary", Set.of("functions", "unknownSignatureFunctions", "recoveredGlobalsKnown",
                "recoveredGlobals", "source", "variables", "variablesByKind", "functionTypes"), name -> switch (name) {
                    case "recoveredGlobalsKnown" -> flag();
                    case "source" -> sourceUnion();
                    case "variables" -> variableTotals();
                    case "variablesByKind" -> byKind();
                    case "functionTypes" -> types();
                    default -> decimal();
                });
            return new Summary(get(fields, "functions"), get(fields, "unknownSignatureFunctions"), get(fields, "recoveredGlobalsKnown"),
                get(fields, "recoveredGlobals"), get(fields, "source"), get(fields, "variables"), get(fields, "variablesByKind"), get(fields, "functionTypes"));
        }

        private FunctionFields function() throws IOException {
            var fields = fields("coverage function", Set.of("entry", "name", "namespace", "ranges", "source", "signature",
                "typeProvenance", "types", "variables", "variablesByKind"), name -> switch (name) {
                    case "entry" -> supportedAddress();
                    case "name", "typeProvenance" -> text(true);
                    case "namespace" -> list(() -> text(true));
                    case "ranges" -> ranges(false);
                    case "source" -> source();
                    case "signature" -> signature();
                    case "types" -> nullable(this::types);
                    case "variables" -> variableTotals();
                    case "variablesByKind" -> byKind();
                    default -> throw new AssertionError();
                });
            var symbol = new FunctionSymbol(get(fields, "name"), get(fields, "entry"), get(fields, "ranges"), get(fields, "namespace"));
            require(contains(symbol.ranges(), symbol.address()), "function body lacks its entry");
            Map<String, Object> rawSource = get(fields, "source");
            List<Long> decoded = get(rawSource, "decodedStarts");
            List<Long> anchors = get(rawSource, "anchoredStarts");
            List<Long> visible = get(rawSource, "lineVisibleStarts");
            require((rawSource.get("decodedInstructions") == null) == (decoded == null) &&
                (rawSource.get("anchoredInstructions") == null) == (anchors == null) &&
                (rawSource.get("lineVisibleInstructions") == null) == (visible == null), "source array availability differs from counts");
            SourceCoverageIndex.Points points = null;
            if (decoded != null) {
                require(visible != null, "known listing needs line visibility");
                for (long point : decoded) { check(); require(contains(symbol.ranges(), point), "instruction outside function"); }
                require(subset(visible, decoded) && (anchors == null || subset(anchors, visible)), "source points are not nested subsets");
                points = new SourceCoverageIndex.Points(decoded, anchors == null ? List.of() : anchors, visible);
            }
            var source = new SourceCoverageInventory.FunctionInventory(symbol, get(rawSource, "disposition"), get(rawSource, "diagnostic"),
                get(rawSource, "decodedInstructions"), get(rawSource, "anchoredInstructions"), get(rawSource, "lineVisibleInstructions"),
                get(rawSource, "instructionUnavailableReason"), get(rawSource, "tokenUnavailableReason"), points);
            var signature = (ExportCoverage.SignatureEvidence) fields.get("signature");
            TypeCoverage types = get(fields, "types");
            require(signature.recovered() == (types != null), "type coverage availability differs from signature");
            require(!source.disposition().equals("FAILED") || !signature.emitted(), "failed source has emitted signature");
            if (types != null) {
                require(types.recoveredRoots() > 0, "recovered signature lacks return root");
                require(signature.emitted() ? types.emittedRoots() > 0 : types.emittedRoots() == 0 && types.emittedNodes() == 0 &&
                    types.emittedImplicitVoidNodes() == 0, "signature/type emission differs");
            }
            require(fields.get("typeProvenance").equals("UNKNOWN_PER_TYPE"), "unsupported per-type provenance");
            return new FunctionFields(symbol, source, signature, types, get(fields, "variables"), get(fields, "variablesByKind"), get(fields, "typeProvenance"));
        }

        private Map<String, Object> source() throws IOException {
            var fields = fields("source metrics", Set.of("disposition", "diagnostic", "decodedInstructions", "anchoredInstructions",
                "lineVisibleInstructions", "instructionUnavailableReason", "tokenUnavailableReason", "decodedStarts", "anchoredStarts", "lineVisibleStarts"),
                name -> switch (name) {
                    case "decodedInstructions", "anchoredInstructions", "lineVisibleInstructions" -> nullable(this::decimal);
                    case "decodedStarts", "anchoredStarts", "lineVisibleStarts" -> nullable(this::addresses);
                    default -> text(false);
                });
            require(Set.of("DECOMPILED", "FAILED", "OMITTED", "UNAVAILABLE").contains(fields.get("disposition")), "unknown source disposition");
            if (fields.get("disposition").equals("DECOMPILED")) require(fields.get("diagnostic").equals(""), "decompiled source has failure diagnostic");
            else require(!((String) fields.get("diagnostic")).isBlank(), "missing source disposition diagnostic");
            for (String name : List.of("instructionUnavailableReason", "tokenUnavailableReason")) {
                String reason = get(fields, name);
                require(reason.isEmpty() || !reason.isBlank(), "blank source evidence reason");
            }
            return fields;
        }

        private ExportCoverage.SignatureEvidence signature() throws IOException {
            var fields = fields("signature evidence", Set.of("recovered", "emitted", "source", "recordedCallingConvention",
                "emittedEffectiveCallingConvention", "debuggerCallRestriction"), name ->
                name.equals("recovered") || name.equals("emitted") ? flag() : text(false));
            boolean recovered = get(fields, "recovered");
            boolean emitted = get(fields, "emitted");
            require(!emitted || recovered, "emitted signature has no recovered population");
            if (!recovered) require(fields.get("source").equals("") && fields.get("recordedCallingConvention").equals(""), "unknown signature has recovered facts");
            if (!emitted) require(fields.get("emittedEffectiveCallingConvention").equals("") && fields.get("debuggerCallRestriction").equals(""), "unemitted signature has emitted ABI facts");
            return new ExportCoverage.SignatureEvidence(recovered, emitted, get(fields, "source"), get(fields, "recordedCallingConvention"),
                get(fields, "emittedEffectiveCallingConvention"), get(fields, "debuggerCallRestriction"));
        }

        private SourceCoverageInventory.Union sourceUnion() throws IOException {
            var fields = fields("source union", Set.of("functions", "unavailableInstructionFunctions", "unavailableTokenFunctions",
                "decodedInstructions", "anchoredInstructions", "lineVisibleInstructions"), name -> decimal());
            return new SourceCoverageInventory.Union(get(fields, "functions"), get(fields, "unavailableInstructionFunctions"),
                get(fields, "unavailableTokenFunctions"), get(fields, "decodedInstructions"), get(fields, "anchoredInstructions"), get(fields, "lineVisibleInstructions"));
        }

        private TypeCoverage types() throws IOException {
            long[] values = new long[TYPE_FIELDS.size()];
            object("type coverage", Set.copyOf(TYPE_FIELDS), name -> values[TYPE_FIELDS.indexOf(name)] = decimal());
            return new TypeCoverage(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8]);
        }

        private VariableCoverageTotals variableTotals() throws IOException {
            var fields = fields("variable totals", VARIABLE_TOTALS, name -> switch (name) {
                case "extentUnavailableReason" -> text(false);
                case "knownScopeBytes", "coveredScopeBytes" -> nullable(this::decimal);
                default -> decimal();
            });
            return new VariableCoverageTotals(get(fields, "recoveredVariables"), get(fields, "emittedVariables"), get(fields, "variablesWithLocation"),
                get(fields, "knownScopeVariables"), get(fields, "unknownScopeVariables"), get(fields, "knownScopeBytes"), get(fields, "coveredScopeBytes"),
                get(fields, "extentUnavailableReason"));
        }

        private Map<Kind, VariableCoverageTotals> byKind() throws IOException {
            Map<Kind, VariableCoverageTotals> result = new EnumMap<>(Kind.class);
            object("variable kinds", Set.of("PARAMETER", "LOCAL", "FUNCTION_STATIC"), name -> result.put(Kind.valueOf(name), variableTotals()));
            return result;
        }

        private OwnedVariable variable() throws IOException {
            var fields = fields("coverage variable", Set.of("function", "kind", "parameterOrdinal", "internalName", "displayName", "block",
                "staticAddress", "recoveredType", "emittedType", "declarationProvenance", "storageEvidence", "location", "omissionReason", "diagnostic"),
                name -> switch (name) {
                    case "function" -> supportedAddress();
                    case "staticAddress" -> nullable(this::supportedAddress);
                    case "parameterOrdinal" -> nullable(this::decimal);
                    case "recoveredType" -> text(true);
                    case "emittedType" -> nullable(() -> text(true));
                    case "declarationProvenance" -> provenance();
                    case "storageEvidence" -> storageEvidence();
                    case "location" -> location();
                    default -> text(false);
                });
            Kind kind = Kind.valueOf(get(fields, "kind"));
            Long ordinal = get(fields, "parameterOrdinal");
            Long address = get(fields, "staticAddress");
            String name = get(fields, "internalName");
            String display = get(fields, "displayName");
            String block = get(fields, "block");
            require((kind == Kind.PARAMETER) == (ordinal != null) && (kind == Kind.FUNCTION_STATIC) == (address != null), "variable kind/identity mismatch");
            if (kind == Kind.PARAMETER) require(block.isEmpty(), "formal parameter has lexical block");
            else require(!name.isBlank() && !display.isBlank(), "missing variable name");
            LocationCoverage location = get(fields, "location");
            String emittedType = get(fields, "emittedType");
            require(location.declarationEmitted() == (emittedType != null), "declaration/type availability differs");
            String reason = get(fields, "omissionReason");
            String diagnostic = get(fields, "diagnostic");
            require(location.hasFullValueLocation() ? reason.isEmpty() && diagnostic.isEmpty() : !reason.isBlank() && !diagnostic.isBlank(),
                "location/omission reason differs");
            if (!location.declarationEmitted()) require(Set.of("SIGNATURE_NOT_EMITTED", "DECLARATION_NOT_EMITTED").contains(reason), "missing declaration reason");
            VariableCoverageInventory.Provenance provenance = get(fields, "declarationProvenance");
            String subject = switch (kind) { case PARAMETER -> "SIGNATURE"; case LOCAL -> "LOCAL_DECLARATION"; case FUNCTION_STATIC -> "STATIC_DECLARATION"; };
            require(provenance.subject().equals(subject), "provenance subject differs from declaration kind");
            List<StorageRange> storage = get(fields, "storageEvidence");
            if (kind == Kind.FUNCTION_STATIC) require(storage.isEmpty(), "static has unexpected automatic storage evidence");
            return new OwnedVariable(get(fields, "function"), new VariableCoverageInventory.Variable(
                new VariableCoverageInventory.Identity(kind, ordinal == null ? -1 : Math.toIntExact(ordinal), name, block, address),
                display, new TypeRef(get(fields, "recoveredType")), emittedType == null ? null : new TypeRef(emittedType), provenance,
                List.of(), location, reason, diagnostic), storage);
        }

        private VariableCoverageInventory.Provenance provenance() throws IOException {
            var fields = fields("declaration provenance", Set.of("category", "source", "subject"), name -> text(false));
            String source = get(fields, "source");
            require(fields.get("category").equals(CATEGORIES.contains(source) ? source : "UNKNOWN"), "provenance category differs from source");
            return new VariableCoverageInventory.Provenance(get(fields, "category"), source, get(fields, "subject"));
        }

        private List<CoverageReportJson.StorageDetail> storageDetails() throws IOException {
            Set<CoverageReportJson.StorageDetail> unique = new HashSet<>();
            return list(() -> {
                var fields = fields("storage evidence detail", Set.of("category", "source", "omissionReason", "diagnostic"), name -> text(false));
                require(CATEGORIES.contains(fields.get("category")), "invalid storage category");
                require(!((String) fields.get("source")).isBlank(), "missing storage evidence source");
                require(((String) fields.get("omissionReason")).isEmpty() == ((String) fields.get("diagnostic")).isEmpty(),
                    "storage omission reason/diagnostic differ");
                var detail = new CoverageReportJson.StorageDetail(get(fields, "category"), get(fields, "source"),
                    get(fields, "omissionReason"), get(fields, "diagnostic"));
                require(unique.add(detail), "duplicate storage evidence detail");
                return detail;
            });
        }

        private List<StorageRange> storageEvidence() throws IOException {
            List<StorageRange> result = list(() -> {
                long[] tuple = new long[3];
                int[] position = {0};
                array(() -> {
                    require(position[0] < 3, "storage range has more than three fields");
                    tuple[position[0]] = position[0] == 2 ? decimal() : supportedAddress();
                    position[0]++;
                });
                require(position[0] == 3 && tuple[1] > tuple[0], "expected storage start/end/detail tuple");
                return new StorageRange(tuple[0], tuple[1], Math.toIntExact(tuple[2]));
            });
            long end = -1;
            for (var range : result) { check(); require(range.start() >= end, "overlapping storage evidence"); end = range.end(); }
            return result;
        }

        private VariableCoverageInventory.Variable resolveStorage(OwnedVariable row,
                List<CoverageReportJson.StorageDetail> details, boolean[] used) throws IOException {
            var evidence = new ArrayList<VariableCoverageInventory.StorageEvidence>(row.storage().size());
            for (var range : row.storage()) {
                check();
                require(range.detail() < details.size(), "storage evidence reference is missing");
                var detail = details.get(range.detail());
                used[range.detail()] = true;
                evidence.add(new VariableCoverageInventory.StorageEvidence(range.start(), range.end(), detail.category(),
                    detail.source(), detail.omissionReason(), detail.diagnostic()));
            }
            var variable = row.variable();
            return new VariableCoverageInventory.Variable(variable.identity(), variable.displayName(), variable.recoveredType(),
                variable.emittedType(), variable.declarationProvenance(), evidence, variable.location(), variable.omissionReason(), variable.diagnostic());
        }

        private LocationCoverage location() throws IOException {
            var fields = fields("location coverage", Set.of("declarationEmitted", "scopeStatus", "scopeEvidence", "knownScopeRanges",
                "locatedRanges", "knownScopeBytes", "coveredScopeBytes", "locatedBytes"), name -> switch (name) {
                    case "declarationEmitted" -> flag();
                    case "scopeStatus", "scopeEvidence" -> text(true);
                    case "knownScopeRanges", "locatedRanges" -> ranges(true);
                    default -> decimal();
                });
            String status = get(fields, "scopeStatus");
            require(status.equals("KNOWN") || status.equals("UNKNOWN"), "invalid scope status");
            List<FunctionRange> known = get(fields, "knownScopeRanges");
            List<FunctionRange> located = get(fields, "locatedRanges");
            long knownBytes = bytes(known);
            long locatedBytes = bytes(located);
            long covered = intersectionBytes(known, located);
            require(knownBytes == (Long) fields.get("knownScopeBytes") && locatedBytes == (Long) fields.get("locatedBytes") &&
                covered == (Long) fields.get("coveredScopeBytes"), "location range counts differ");
            return new LocationCoverage(get(fields, "declarationEmitted"), status.equals("KNOWN"), get(fields, "scopeEvidence"),
                known, located, knownBytes, covered, locatedBytes);
        }

        private GlobalVariable global() throws IOException {
            var fields = fields("recovered global", Set.of("name", "namespace", "address", "byteSize", "type", "source", "declaration"),
                name -> switch (name) {
                    case "namespace" -> list(() -> text(true));
                    case "address" -> supportedAddress();
                    case "byteSize" -> decimal();
                    case "declaration" -> flag();
                    case "source" -> text(false);
                    default -> text(true);
                });
            return new GlobalVariable(get(fields, "name"), get(fields, "address"), get(fields, "byteSize"), new TypeRef(get(fields, "type")),
                get(fields, "declaration"), get(fields, "source"), get(fields, "namespace"));
        }

        private List<FunctionRange> ranges(boolean canonicalUnion) throws IOException {
            var result = list(() -> {
                List<Long> pair = new ArrayList<>(2);
                array(() -> {
                    require(pair.size() < 2, "range has more than two endpoints");
                    pair.add(supportedAddress());
                });
                require(pair.size() == 2 && pair.get(1) > pair.get(0), "expected positive half-open range");
                return new FunctionRange(pair.get(0), pair.get(1) - pair.get(0));
            });
            long end = -1;
            for (var range : result) {
                check();
                require(canonicalUnion ? range.address() > end : range.address() >= end, "ranges overlap or union is not canonical");
                end = range.endExclusive();
            }
            return result;
        }

        private List<Long> addresses() throws IOException {
            List<Long> result = list(this::supportedAddress);
            long previous = -1;
            for (long address : result) { check(); require(address > previous, "instruction starts are not sorted/unique"); previous = address; }
            return result;
        }

        private long supportedAddress() throws IOException {
            long value = address();
            require(value >= 0, "coverage address outside supported domain");
            return value;
        }

        private long decimal() throws IOException {
            String spelling = text(true);
            require(spelling.matches("0|[1-9][0-9]{0,18}"), "noncanonical exact decimal count");
            return Long.parseLong(spelling);
        }

        private boolean flag() throws IOException {
            String value = text(true);
            require(value.equals("YES") || value.equals("NO"), "expected YES/NO flag");
            return value.equals("YES");
        }

        private Map<String, Object> fields(String description, Set<String> expected, NamedValue reader) throws IOException {
            Map<String, Object> result = new HashMap<>();
            object(description, expected, name -> result.put(name, reader.read(name)));
            return result;
        }

        private <T> List<T> list(NullableReader<T> reader) throws IOException {
            List<T> values = new ArrayList<>();
            array(() -> values.add(reader.read()));
            return List.copyOf(values);
        }

        private Map<Kind, List<LocationCoverage>> groups() {
            Map<Kind, List<LocationCoverage>> result = new EnumMap<>(Kind.class);
            for (Kind kind : Kind.values()) result.put(kind, new ArrayList<>());
            return result;
        }

        private Map<Kind, VariableCoverageTotals> totals(Map<Kind, List<LocationCoverage>> values) {
            Map<Kind, VariableCoverageTotals> result = new EnumMap<>(Kind.class);
            for (Kind kind : Kind.values()) result.put(kind, VariableCoverageTotals.measure(values.get(kind), cancelled));
            return result;
        }

        private void add(Set<Long> destination, List<Long> source) { for (long value : source) { check(); destination.add(value); } }
        private long bytes(List<FunctionRange> ranges) {
            long result = 0;
            for (var range : ranges) { check(); result = Math.addExact(result, range.size()); }
            return result;
        }

        private long intersectionBytes(List<FunctionRange> first, List<FunctionRange> second) {
            long result = 0;
            int a = 0;
            int b = 0;
            while (a < first.size() && b < second.size()) {
                check();
                var left = first.get(a);
                var right = second.get(b);
                long start = Math.max(left.address(), right.address());
                long end = Math.min(left.endExclusive(), right.endExclusive());
                if (start < end) result = Math.addExact(result, end - start);
                if (left.endExclusive() <= right.endExclusive()) a++;
                else b++;
            }
            return result;
        }

        private boolean subset(List<Long> part, List<Long> whole) {
            int cursor = 0;
            for (long value : part) {
                check();
                while (cursor < whole.size() && whole.get(cursor) < value) cursor++;
                if (cursor == whole.size() || whole.get(cursor) != value) return false;
            }
            return true;
        }

        /** Reject impossible unions without pretending counts prove canonical graph identities. */
        private void validateTypeUnion(List<FunctionFields> functions, TypeCoverage union) throws IOException {
            long[] maximum = new long[9];
            long[] upper = new long[9];
            for (var function : functions) {
                check();
                if (function.types() == null) continue;
                long[] counts = typeCounts(function.types());
                for (int i = 0; i < counts.length; i++) {
                    maximum[i] = Math.max(maximum[i], counts[i]);
                    upper[i] = counts[i] > Long.MAX_VALUE - upper[i] ? Long.MAX_VALUE : upper[i] + counts[i];
                }
            }
            maximum[6] = 0; // A type absent for one function may be emitted by another.
            long[] counts = typeCounts(union);
            for (int i = 0; i < counts.length; i++) {
                require(maximum[i] <= counts[i] && counts[i] <= upper[i], "type union outside per-function bounds");
            }
        }

        private static long[] typeCounts(TypeCoverage value) {
            return new long[] {value.recoveredRoots(), value.emittedRoots(), value.opaqueFreeEmittedRoots(),
                value.recoveredNodes(), value.resolvedEmittedNodes(), value.opaqueEmittedNodes(), value.notEmittedNodes(),
                value.implicitVoidNodes(), value.emittedImplicitVoidNodes()};
        }

        private boolean containsRanges(List<FunctionRange> outer, List<FunctionRange> inner) {
            for (var child : inner) {
                check();
                int low = 0;
                int high = outer.size();
                while (low < high) {
                    int middle = (low + high) >>> 1;
                    if (outer.get(middle).address() <= child.address()) low = middle + 1;
                    else high = middle;
                }
                int cursor = low - 1;
                if (cursor < 0 || !outer.get(cursor).contains(child.address())) return false;
                long end = outer.get(cursor).endExclusive();
                while (end < child.endExclusive()) {
                    check();
                    if (++cursor == outer.size() || outer.get(cursor).address() != end) return false;
                    end = outer.get(cursor).endExclusive();
                }
            }
            return true;
        }

        private boolean contains(List<FunctionRange> ranges, long point) {
            int low = 0;
            int high = ranges.size();
            while (low < high) {
                int middle = (low + high) >>> 1;
                if (ranges.get(middle).address() <= point) low = middle + 1;
                else high = middle;
            }
            return low != 0 && ranges.get(low - 1).contains(point);
        }

        private void check() { ReportJsonReader.checkCancelled(cancelled); }
        private static void require(boolean condition, String message) throws IOException { if (!condition) throw invalid(message); }
        @SuppressWarnings("unchecked") private static <T> T get(Map<String, Object> fields, String name) { return (T) fields.get(name); }
        @FunctionalInterface private interface NamedValue { Object read(String name) throws IOException; }
    }
}

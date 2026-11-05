package ghidradwarfforge.coverage;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;

import com.google.gson.GsonBuilder;

import ghidradwarfforge.coverage.ExportEmission.*;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.*;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.LexicalScopeModel;
import ghidradwarfforge.types.ProgramTypeModel.*;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Actual producer facts; Python separately inspects DWARF and runs the fixture. */
public final class EmissionEvidenceSmoke {
    public static void main(String[] args) throws Exception {
        if (args.length != 5 && !(args.length == 6 && args[5].equals("--export-only"))) {
            throw new IllegalArgumentException("consumer producer input output nm-symbols [--export-only]");
        }
        Path input = Path.of(args[2]);
        Path output = Path.of(args[3]);
        byte[] original = Files.readAllBytes(input);
        Map<String, Long> symbols = new LinkedHashMap<>();
        for (String line : Files.readAllLines(Path.of(args[4]))) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length >= 3 && fields[0].matches("[0-9a-fA-F]+")) {
                symbols.put(fields[fields.length - 1], Long.parseLong(fields[0], 16));
            }
        }
        long entry = symbols.get("observed");
        long moved = symbols.get("observed_moved");
        long end = symbols.get("observed_end");
        TypeRef scalar = new TypeRef("u64");
        TypeRef voidType = new TypeRef("void");
        TypeRef opaquePointer = new TypeRef("opaque-pointer");
        TypeRef node = new TypeRef("node");
        var graph = new TypeGraph(List.of(new VoidType("void"),
            new BaseType("u64", "uint64_t", 8, BaseEncoding.UNSIGNED),
            new OpaqueType("opaque", "OpaquePayload", 0, "fixture has no target definition"),
            new IndirectionType("opaque-pointer", "OpaquePayload *", 8, IndirectionKind.POINTER,
                new TypeRef("opaque")),
            new AggregateType("node", "Node", 8, AggregateKind.STRUCTURE,
                List.of(new Member("next", new TypeRef("node-pointer"), 0))),
            new IndirectionType("node-pointer", "Node *", 8, IndirectionKind.POINTER, node)));
        List<LocalVariable> locals = new ArrayList<>();
        for (String name : List.of("moving", "late", "partial", "mixed", "no_storage")) {
            locals.add(new LocalVariable(name, 8, scalar, 0, true, "USER_DEFINED"));
        }
        locals.add(new LocalVariable("opaque_pointer", 8, opaquePointer, 0, false, "USER_DEFINED"));
        locals.add(new LocalVariable("recursive", 8, node, 0, false, "USER_DEFINED"));
        var signature = new FunctionSignature("observed", entry, scalar,
            List.of(new Parameter("x", scalar, false)), locals, false, false, "default", "USER_DEFINED");
        var failed = new FunctionSignature("failed", symbols.get("failed"), scalar,
            List.of(new Parameter("hidden", scalar, false)), List.of(), false, false, "default", "USER_DEFINED");
        var empty = new FunctionSignature("empty", symbols.get("empty"), voidType,
            List.of(), List.of(), false, false, "default", "USER_DEFINED");
        var registers = TargetRegisterMap.forTarget("x86_64");
        var evidence = new Evidence(Confidence.USER_DEFINED, "fixture instruction and register oracle");
        var rdi = registers.register("RDI", 0, 64);
        var rax = registers.register("RAX", 0, 64);
        var half = registers.register("RAX", 0, 32);
        var storage = new VariableStorageModel(List.of(
            new VariableLocation("observed", entry, "x", VariableKind.PARAMETER, 8,
                List.of(new LocationRange(entry, end, rdi, evidence))),
            new VariableLocation("observed", entry, "moving", VariableKind.LOCAL, 8,
                List.of(new LocationRange(entry, moved, rdi, evidence), new LocationRange(moved, end, rax, evidence))),
            new VariableLocation("observed", entry, "late", VariableKind.LOCAL, 8,
                List.of(new LocationRange(entry, moved,
                    new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "fixture has no entry storage proof"), evidence),
                    new LocationRange(moved, end, rax, evidence))),
            new VariableLocation("observed", entry, "partial", VariableKind.LOCAL, 8,
                List.of(new LocationRange(entry, end, half, evidence))),
            new VariableLocation("observed", entry, "mixed", VariableKind.LOCAL, 8,
                List.of(new LocationRange(entry, moved, rdi, evidence), new LocationRange(moved, end, half, evidence)))));
        var scopes = new LexicalScopeModel(entry,
            List.of(new MinimalDwarfSidecarExporter.FunctionRange(entry, end - entry)), List.of(),
            List.of(new LexicalScopeModel.Local("moving", "", "moving"),
                new LexicalScopeModel.Local("late", "", "late")), "explicit fixture root visibility");
        var model = new ProgramTypeModel(graph, List.of(signature, failed, empty), List.of(), storage,
            List.of(new FunctionStaticVariable("counter", symbols.get("counter"), 8, scalar, entry, "USER_DEFINED")),
            List.of(), List.of(scopes));
        List<FunctionSymbol> functions = List.of(new FunctionSymbol("observed", entry, end - entry),
            new FunctionSymbol("failed", symbols.get("failed"), symbols.get("failed_end") - symbols.get("failed")),
            new FunctionSymbol("empty", symbols.get("empty"), symbols.get("empty_end") - symbols.get("empty")));
        var source = SyntheticSourceFile.build("emission fixture", "curated fixture", List.of(
            new FunctionText("observed", entry, "uint64_t observed(uint64_t x)\n{\n    x = x;\n    return x;\n}\n", null,
                List.of(new RelativeLine(2, List.of(entry)), new RelativeLine(3, List.of(moved)),
                    new RelativeLine(4, List.of(symbols.get("observed_return"))))),
            new FunctionText("failed", symbols.get("failed"), null, "controlled unavailable source"),
            new FunctionText("empty", symbols.get("empty"), "void empty(void)\n{\n    return;\n}\n", null,
                List.of(new RelativeLine(3, List.of(symbols.get("empty")))))));
        var exporter = new MinimalDwarfSidecarExporter();
        var result = exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, source, model);
        Files.write(Path.of(output + ".c"), source.utf8());
        if (args.length == 6) {
            // This branch intentionally uses only the parent revision's API.
            System.out.println("emission-export-only=PASS");
            return;
        }
        var facts = result.emission();
        require(facts.functions().size() == 3 && facts.typeReferences().size() == 6, "complete emitted inventories");
        var observed = facts.functions().stream().filter(f -> f.function().name().equals("observed")).findFirst().orElseThrow();
        require(observed.variables().size() == 9, "parameter, seven locals, function static");
        Map<String, VariableEmission> variables = new LinkedHashMap<>();
        observed.variables().forEach(v -> variables.put(v.internalName(), v));
        require(variables.get("x").location() instanceof ExpressionLocation &&
            variables.get("x").parameterOrdinal() == 0, "actual formal expression");
        require(variables.get("moving").location() instanceof ListLocation list && list.ranges().size() == 2,
            "actual referenced changing list");
        require(variables.get("counter").kind() == Kind.FUNCTION_STATIC &&
            variables.get("counter").location() instanceof ExpressionLocation, "actual static memory expression");
        for (String name : List.of("partial", "mixed", "no_storage", "opaque_pointer", "recursive")) {
            require(variables.get(name).location() instanceof NoLocation, "actual absent location " + name);
        }
        var types = new TypeCoverageIndex(facts.types(), facts.typeReferences(), () -> false);
        Map<String, TypeCoverage> counts = new LinkedHashMap<>();
        Map<String, LocationCoverage> locationCounts = new LinkedHashMap<>();
        for (var variable : observed.variables()) {
            var binding = variable.kind() == Kind.LOCAL ? scopes.local(variable.internalName()) : null;
            var visibility = variable.kind() == Kind.PARAMETER
                ? new LocationCoverage.Visibility(observed.function().ranges(), true, "formal parameter scope")
                : binding != null
                    ? new LocationCoverage.Visibility(scopes.visibility(binding), true, scopes.evidence())
                    : new LocationCoverage.Visibility(List.of(), false, "no explicit visibility evidence");
            locationCounts.put(variable.internalName(), LocationCoverage.measure(variable.location(),
                observed.function().ranges(), visibility, () -> false));
        }
        require(locationCounts.get("late").knownScopeBytes() == end - entry &&
            locationCounts.get("late").coveredScopeBytes() == end - moved,
            "unknown storage prefix remains inside evidenced scope denominator");
        require(locationCounts.get("moving").coveredScopeBytes() == end - entry,
            "changing locations cover the known scope without double counting");
        require(locationCounts.get("counter").hasFullValueLocation() &&
            !locationCounts.get("counter").percentageApplicable(), "static storage does not invent lexical visibility");
        counts.put("observed", types.measure(observed.typeRoots(), observed.typeRoots(), () -> false));
        require(counts.get("observed").equals(new TypeCoverage(3, 3, 2, 5, 4, 1, 0, 0, 0)),
            "actual recursive/opaque emitted type graph");
        for (FunctionEmission function : facts.functions()) {
            if (function.function().name().equals("failed")) {
                require(function.signature() == null && function.variables().isEmpty() && function.typeRoots().isEmpty(),
                    "failed function does not inherit allocated types or variables");
                counts.put("failed", types.measure(List.of(scalar), function.typeRoots(), () -> false));
                require(counts.get("failed").equals(new TypeCoverage(1, 0, 0, 1, 0, 0, 1, 0, 0)), "failed denominator retained");
                locationCounts.put("failed::hidden", LocationCoverage.measure(null, List.of(),
                    new LocationCoverage.Visibility(function.function().ranges(), true, "recovered formal parameter scope"),
                    () -> false));
            }
            if (function.function().name().equals("empty")) {
                counts.put("empty", types.measure(List.of(voidType), function.typeRoots(), () -> false));
                require(counts.get("empty").equals(new TypeCoverage(1, 1, 1, 0, 0, 0, 0, 1, 1)), "implicit void from producer");
            }
        }
        var gson = new GsonBuilder().setPrettyPrinting().serializeNulls().create();
        var variableTotals = VariableCoverageTotals.measure(new ArrayList<>(locationCounts.values()), () -> false);
        require(variableTotals.equals(new VariableCoverageTotals(10, 9, 4, 4, 6,
            3 * (end - entry) + symbols.get("failed_end") - symbols.get("failed"),
            2 * (end - entry) + end - moved, "")), "actual emission and recovered-scope totals");
        var inventory = VariableCoverageInventory.build(model, facts, () -> false);
        require(inventory.totals().equals(variableTotals), "automatic recovered/emitted inventory matches independent fixture totals");
        for (var function : inventory.functions()) {
            for (var variable : function.variables()) {
                String key = function.function().name().equals("failed") ? "failed::hidden" : variable.identity().internalName();
                var independent = locationCounts.get(key);
                require(independent != null && variable.location().knownScopeBytes() == independent.knownScopeBytes() &&
                    variable.location().coveredScopeBytes() == independent.coveredScopeBytes() &&
                    variable.location().locatedRanges().equals(independent.locatedRanges()) &&
                    variable.location().scopeComplete() == independent.scopeComplete(), "automatic inventory extent " + key);
            }
        }
        List<DecodedInstructions> decoded = new ArrayList<>();
        for (var function : facts.functions()) {
            var symbol = function.function();
            List<Long> starts = switch (symbol.name()) {
                case "observed" -> List.of(entry, moved, symbols.get("observed_return"));
                case "failed" -> List.of(symbols.get("failed"), symbols.get("failed") + 5);
                case "empty" -> List.of(symbols.get("empty"));
                default -> throw new AssertionError("unexpected fixture function");
            };
            decoded.add(new DecodedInstructions(symbol, starts, ""));
        }
        var sourceInventory = SourceCoverageInventory.build(facts.functions().stream().map(FunctionEmission::function).toList(),
            decoded, source, facts.lines(), () -> false);
        require(sourceInventory.observedUnion().equals(new SourceCoverageInventory.Union(3, 0, 0, 6, 2, 4)),
            "fixture instruction/token/visibility union; Python independently checks disassembly and line bytes");
        var coverage = ExportCoverage.build(model, source, decoded, facts, () -> false);
        require(coverage.variables().equals(variableTotals) && coverage.sourceUnion().equals(sourceInventory.observedUnion()),
            "assembled scorecards preserve independent inventory populations");
        require(coverage.functionTypeUnion().equals(new TypeCoverage(4, 4, 3, 5, 4, 1, 0, 1, 1)),
            "function type union deduplicates shared and failed roots; implicit void remains separate");
        for (var function : coverage.functions()) {
            require(function.types().equals(counts.get(function.function().name())), "assembled per-function canonical types");
        }
        Files.writeString(Path.of(output + ".coverage.json"), ghidradwarfforge.output.CoverageReportJson.write(coverage,
            new ghidradwarfforge.output.CoverageReportJson.Profile("x86:LE:64:default", "gcc"), () -> false));
        var claims = ghidradwarfforge.output.CoverageReportClaims.read(Path.of(output + ".coverage.json"), () -> false);
        require(claims.coverage().equals(coverage), "strict coverage claims roundtrip preserves assembled metrics");
        require(ghidradwarfforge.output.CoverageReportJson.write(claims.coverage(), claims.profile(), () -> false)
            .equals(Files.readString(Path.of(output + ".coverage.json"))), "strict coverage roundtrip preserves exact payload bytes");
        Path sourcePath = Path.of(output + ".c");
        var report = ghidradwarfforge.output.ExportReport.completed(result.target(), result.libdwarfVersion(),
            input, ghidradwarfforge.output.FileDigests.read(input).sha256(),
            output, ghidradwarfforge.output.FileDigests.read(output).sha256(),
            sourcePath, ghidradwarfforge.output.FileDigests.read(sourcePath).sha256(),
            result.functionCount(), result.sectionNames(), source, model, List.of(), List.of());
        String reportJson = report.toJsonWithCoverage(claims, () -> false);
        Path reportPath = Path.of(output + ".report.json");
        Files.writeString(reportPath, reportJson);
        var reportClaims = ghidradwarfforge.output.ExportReportClaims.readWithCoverage(reportPath, () -> false);
        require(reportClaims.coverage().equals(claims), "full schema-two report preserves native metric claims");
        require(reportClaims.claims().status() == ghidradwarfforge.output.ExportReport.Status.PARTIAL &&
            reportClaims.claims().validationStatus() == ghidradwarfforge.output.ExportReport.ValidationStatus.NOT_RUN,
            "scorecards never upgrade failure/validation status");
        require(report.toJsonWithCoverage(claims, () -> false).equals(reportJson), "deterministic full report bytes");
        Files.writeString(Path.of(output + ".evidence.json"), gson.toJson(
            Map.of("emission", facts, "types", counts, "locations", locationCounts, "variableTotals", variableTotals, "variableInventory", inventory, "sourceInventory", sourceInventory, "coverage", coverage)) + "\n");
        Path cancelled = Path.of(output + ".cancelled");
        byte[] previous = "previous artifact".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Files.write(cancelled, previous);
        try {
            exporter.export(input, cancelled, Path.of(args[0]), Path.of(args[1]), functions, source, model,
                output.getFileName() + ".c", () -> Arrays.stream(Thread.currentThread().getStackTrace())
                    .anyMatch(frame -> frame.getMethodName().equals("populateTypes")));
            throw new AssertionError("native-phase cancellation ignored");
        }
        catch (CancellationException expected) {
            require(Arrays.equals(previous, Files.readAllBytes(cancelled)), "cancelled native phase preserves prior artifact");
        }
        byte[] first = Files.readAllBytes(output);
        var repeated = exporter.export(input, output, Path.of(args[0]), Path.of(args[1]), functions, source, model);
        require(Arrays.equals(first, Files.readAllBytes(output)), "deterministic repeat after native cancellation");
        require(gson.toJson(repeated.emission()).equals(gson.toJson(facts)), "deterministic emission evidence");
        require(Arrays.equals(original, Files.readAllBytes(input)), "original input unchanged");
        System.out.println("emission-evidence-native=PASS");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

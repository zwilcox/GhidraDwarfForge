package ghidradwarfforge.output;

import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission;
import ghidradwarfforge.coverage.ExportEmission.*;
import ghidradwarfforge.dwarf.Dwarf5LineTable;
import ghidradwarfforge.dwarf.DwarfLocationExpression.AddressOperation;
import ghidradwarfforge.dwarf.DwarfLocationExpression.Expression;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;
import ghidradwarfforge.types.LexicalScopeModel;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.*;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.*;

/** Cross-field counterexamples. These are reported claims, not proof of a real exported artifact. */
public final class CoverageReportClaimsBoundarySmoke {
    private static final CoverageReportJson.Profile PROFILE = new CoverageReportJson.Profile("x86:LE:64:default", "gcc");
    private static int checks;

    public static void main(String[] args) throws Exception {
        ownership();
        signatures();
        staticsAndDeclarations();
        sourceEvidence();
        typeUnionBounds();
        pathRead();
        System.out.println("coverage-report-claims-boundary=PASS checks=" + checks);
    }

    private static void ownership() throws Exception {
        var original = fixture(Kind.PARAMETER, true, true, true, false, false);
        var adjacent = original.deepCopy();
        function(adjacent).add("ranges", ranges(0x100, 0x104, 0x104, 0x108, 0x108, 0x110));
        var accepted = parse(adjacent);
        require(accepted.coverage().functions().getFirst().function().ranges().size() == 3,
            "adjacent body fragments retained independently");
        require(accepted.coverage().variables().knownScopeBytes() == 16,
            "whole formal scope spans adjacent fragments without double counting");
        reject(original, "variable ranges outside function", d -> scope(d, 0xff, 0x110));
        reject(original, "variable ranges outside function", d -> scope(d, 0x100, 0x111));
        reject(adjacent, "variable ranges outside function", d ->
            function(d).add("ranges", ranges(0x100, 0x104, 0x108, 0x110)));
        reject(original, "variable ranges outside function", d -> {
            function(d).add("ranges", ranges(0x100, 0x104, 0x108, 0x110));
            scope(d, 0x106, 0x109);
        });
        reject(original, "formal scope differs from function body", d -> scope(d, 0x100, 0x104));
        reject(original, "formal scope differs from function body", d -> location(d).addProperty("scopeStatus", "UNKNOWN"));
        reject(original, "ranges overlap or union is not canonical", d ->
            location(d).add("knownScopeRanges", ranges(0x100, 0x108, 0x108, 0x110)));
        reject(original, "expected positive half-open range", d -> location(d).add("knownScopeRanges", ranges(0x100, 0x100)));
        reject(original, "ranges overlap or union is not canonical", d ->
            function(d).add("ranges", ranges(0x100, 0x108, 0x104, 0x110)));

        var located = fixture(Kind.LOCAL, true, true, true, true, false);
        require(parse(located).coverage().variables().unknownScopeVariables() == 1,
            "available storage does not prove local lexical visibility");
        reject(located, "variable ranges outside function", d -> {
            location(d).add("locatedRanges", ranges(0xff, 0x110));
            location(d).addProperty("locatedBytes", "17");
        });
        reject(located, "variable ranges outside function", d ->
            function(d).add("ranges", ranges(0x100, 0x104, 0x108, 0x110)));
        reject(located, "location range counts differ", d -> location(d).addProperty("locatedBytes", "15"));
        reject(located, "location range counts differ", d -> location(d).addProperty("coveredScopeBytes", "1"));
        reject(located, "invalid scope status", d -> location(d).addProperty("scopeStatus", "PROVEN"));

        var duplicate = original.deepCopy();
        var alias = function(duplicate).deepCopy();
        alias.addProperty("name", "alias");
        duplicate.getAsJsonArray("functions").add(alias);
        duplicate.getAsJsonObject("summary").addProperty("functions", "2");
        reject(duplicate, "duplicate primary/alias entry", d -> { });
        reject(original, "summary cardinalities", d -> d.getAsJsonObject("summary").addProperty("recoveredGlobals", "1"));
        reject(original, "unknown signature count", d -> d.getAsJsonObject("summary").addProperty("unknownSignatureFunctions", "1"));
    }

    private static void signatures() throws Exception {
        var unknown = fixture(Kind.PARAMETER, false, false, false, false, false);
        require(parse(unknown).coverage().unknownSignatureFunctions() == 1 && unknown.getAsJsonArray("variables").isEmpty(),
            "unknown signature differs from known empty recovery");
        reject(unknown, "emitted signature has no recovered population", d -> signature(d).addProperty("emitted", "YES"));
        reject(unknown, "unknown signature has recovered facts", d -> signature(d).addProperty("source", "ANALYSIS"));
        reject(unknown, "unknown signature has recovered facts", d -> signature(d).addProperty("recordedCallingConvention", "cdecl"));
        for (String field : List.of("emittedEffectiveCallingConvention", "debuggerCallRestriction")) {
            reject(unknown, "unemitted signature has emitted ABI facts", d -> signature(d).addProperty(field, "invented"));
        }

        var omitted = fixture(Kind.PARAMETER, true, false, false, false, false);
        require(parse(omitted).coverage().variables().recoveredVariables() == 1 &&
            parse(omitted).coverage().variables().emittedVariables() == 0, "recovered declaration survives omitted signature");
        require(variable(omitted).get("omissionReason").getAsString().equals("SIGNATURE_NOT_EMITTED"),
            "signature omission is explicit");
        reject(omitted, "missing declaration reason", d -> variable(d).addProperty("omissionReason", "UNKNOWN"));
        reject(omitted, "declaration/type availability differs", d -> variable(d).addProperty("emittedType", "int"));
        reject(omitted, "type coverage availability differs from signature", d -> function(d).add("types", JsonNull.INSTANCE));
        reject(unknown, "type coverage availability differs from signature", d -> function(d).add("types", types(omitted).deepCopy()));
        reject(omitted, "signature/type emission differs", d -> types(d).addProperty("emittedRoots", "1"));
        reject(omitted, "signature/type emission differs", d -> {
            types(d).addProperty("resolvedEmittedNodes", "1");
            types(d).addProperty("notEmittedNodes", "0");
        });
        reject(omitted, "signature/type emission differs", d -> {
            types(d).addProperty("implicitVoidNodes", "1");
            types(d).addProperty("emittedImplicitVoidNodes", "1");
        });
        reject(omitted, "recovered signature lacks return root", d -> types(d).addProperty("recoveredRoots", "0"));

        var emitted = fixture(Kind.PARAMETER, true, true, true, false, false);
        reject(emitted, "signature/type emission differs", d -> {
            types(d).addProperty("emittedRoots", "0");
            types(d).addProperty("opaqueFreeEmittedRoots", "0");
        });
        reject(emitted, "emitted variable without emitted signature", d -> {
            signature(d).addProperty("emitted", "NO");
            signature(d).addProperty("emittedEffectiveCallingConvention", "");
            signature(d).addProperty("debuggerCallRestriction", "");
            function(d).add("types", types(omitted).deepCopy());
        });
        var declarationOmitted = fixture(Kind.PARAMETER, true, true, false, false, false);
        require(parse(declarationOmitted).coverage().variables().emittedVariables() == 0 &&
            variable(declarationOmitted).get("omissionReason").getAsString().equals("DECLARATION_NOT_EMITTED"),
            "a signature can be emitted without all recovered declarations");
        var failed = omitted.deepCopy();
        source(failed).addProperty("disposition", "FAILED");
        source(failed).addProperty("diagnostic", "decompiler failed");
        require(parse(failed).coverage().functions().getFirst().source().disposition().equals("FAILED"),
            "failed source with symbol-only emission remains a valid report");
        reject(failed, "failed source has emitted signature", d -> signature(d).addProperty("emitted", "YES"));
    }

    private static void staticsAndDeclarations() throws Exception {
        var root = fixture(Kind.FUNCTION_STATIC, true, true, true, false, false);
        require(parse(root).coverage().variables().unknownScopeVariables() == 1, "root static has no invented lexical scope");
        var block = fixture(Kind.FUNCTION_STATIC, true, true, true, true, true);
        require(parse(block).coverage().variables().knownScopeBytes() == 4 &&
            parse(block).coverage().variables().coveredScopeBytes() == 4, "block static has explicit four-byte visibility");
        reject(block, "root static invents visibility", d -> variable(d).addProperty("block", ""));
        reject(root, "static has unexpected automatic storage evidence", d ->
            variable(d).getAsJsonArray("storageEvidence").add(JsonParser.parseString("[\"0x100\",\"0x104\",\"0\"]")));
        reject(root, "variable kind/identity mismatch", d -> variable(d).add("staticAddress", JsonNull.INSTANCE));
        reject(root, "variable kind/identity mismatch", d -> variable(d).addProperty("parameterOrdinal", "0"));
        for (String field : List.of("internalName", "displayName")) {
            reject(root, "missing variable name", d -> variable(d).addProperty(field, " "));
        }
        reject(root, "declaration/type availability differs", d -> variable(d).add("emittedType", JsonNull.INSTANCE));
        var parameter = fixture(Kind.PARAMETER, true, true, true, false, false);
        reject(parameter, "variable kind/identity mismatch", d -> variable(d).addProperty("staticAddress", "0x2000"));
        reject(parameter, "variable kind/identity mismatch", d -> variable(d).add("parameterOrdinal", JsonNull.INSTANCE));
        reject(parameter, "formal parameter has lexical block", d -> variable(d).addProperty("block", "block"));
        for (String field : List.of("omissionReason", "diagnostic")) {
            reject(root, "location/omission reason differs", d -> variable(d).addProperty(field, " "));
            reject(block, "location/omission reason differs", d -> variable(d).addProperty(field, "unexpected"));
        }
    }

    private static void sourceEvidence() throws Exception {
        var known = JsonParser.parseString(CoverageReportJson.write(CoverageReportClaimsSmoke.knownFixture(), PROFILE, () -> false)).getAsJsonObject();
        for (String field : List.of("anchoredStarts", "lineVisibleStarts")) {
            reject(known, "source array availability differs from counts", d -> source(d).add(field, JsonNull.INSTANCE));
        }
        reject(known, "known listing needs line visibility", d -> {
            source(d).add("lineVisibleStarts", JsonNull.INSTANCE);
            source(d).add("lineVisibleInstructions", JsonNull.INSTANCE);
        });
        for (String field : List.of("instructionUnavailableReason", "tokenUnavailableReason")) {
            reject(known, "blank source evidence reason", d -> source(d).addProperty(field, " "));
        }
        reject(known, "missing source disposition diagnostic", d -> {
            source(d).addProperty("disposition", "FAILED");
            source(d).addProperty("diagnostic", " ");
        });
        reject(known, "source points are not nested subsets", d -> source(d).add("lineVisibleStarts", rangesOfPoints(0x65)));
        reject(known, "instruction outside function", d -> source(d).add("decodedStarts", rangesOfPoints(0x63, 0x66)));
        reject(known, "instruction outside function", d -> source(d).add("decodedStarts", rangesOfPoints(0x64, 0x68)));
        var noTokens = known.deepCopy();
        source(noTokens).add("anchoredStarts", JsonNull.INSTANCE);
        source(noTokens).add("anchoredInstructions", JsonNull.INSTANCE);
        source(noTokens).addProperty("tokenUnavailableReason", "TOKEN_ADDRESSES_UNAVAILABLE");
        noTokens.getAsJsonObject("summary").getAsJsonObject("source").addProperty("unavailableTokenFunctions", "1");
        noTokens.getAsJsonObject("summary").getAsJsonObject("source").addProperty("anchoredInstructions", "0");
        var parsed = parse(noTokens).coverage();
        require(parsed.functions().getFirst().source().anchoredInstructions() == null &&
            parsed.sourceUnion().anchoredInstructions() == 0 && !parsed.sourceUnion().tokenPercentageApplicable(),
            "missing token anchors remain unavailable, not a measured zero-percent result");
    }

    private static void typeUnionBounds() throws Exception {
        // Definition one carries counts, not a graph: large overlapping populations may have
        // a representable union even when the sum of per-function upper bounds overflows.
        var document = JsonParser.parseString(CoverageReportJson.write(CoverageReportJsonSmoke.fixture(), PROFILE, () -> false)).getAsJsonObject();
        for (var function : document.getAsJsonArray("functions")) {
            var types = function.getAsJsonObject().getAsJsonObject("types");
            types.addProperty("recoveredNodes", Long.toString(Long.MAX_VALUE - 1));
            types.addProperty("resolvedEmittedNodes", Long.toString(Long.MAX_VALUE - 1));
        }
        var totals = document.getAsJsonObject("summary").getAsJsonObject("functionTypes");
        totals.addProperty("recoveredNodes", Long.toString(Long.MAX_VALUE));
        totals.addProperty("resolvedEmittedNodes", Long.toString(Long.MAX_VALUE));
        CoverageReportClaims accepted;
        try { accepted = parse(document); }
        catch (IOException rejected) { throw new AssertionError("valid type union rejected after summing upper bounds", rejected); }
        require(accepted.coverage().functionTypeUnion().recoveredNodes() == Long.MAX_VALUE,
            "representable union is not rejected by overflowing per-function sum");
        reject(document, "type union outside per-function bounds", d -> {
            var types = d.getAsJsonObject("summary").getAsJsonObject("functionTypes");
            types.addProperty("recoveredNodes", Long.toString(Long.MAX_VALUE - 2));
            types.addProperty("resolvedEmittedNodes", Long.toString(Long.MAX_VALUE - 2));
        });
        var small = fixture(Kind.LOCAL, true, true, true, false, false);
        reject(small, "type union outside per-function bounds", d -> {
            var types = d.getAsJsonObject("summary").getAsJsonObject("functionTypes");
            types.addProperty("recoveredNodes", "2");
            types.addProperty("resolvedEmittedNodes", "2");
        });
    }

    private static void pathRead() throws Exception {
        var document = fixture(Kind.LOCAL, true, true, true, true, false);
        var path = Files.createTempFile("forge-claims-boundaries-", ".json");
        try {
            Files.writeString(path, document.toString());
            byte[] original = Files.readAllBytes(path);
            require(CoverageReportClaims.read(path, () -> false).equals(parse(document)), "public file reader preserves semantic claims");
            require(java.util.Arrays.equals(original, Files.readAllBytes(path)), "report input remains unchanged");
        }
        finally { Files.delete(path); }
    }

    private static JsonObject fixture(Kind kind, boolean recovered, boolean signatureEmitted,
            boolean declarationEmitted, boolean located, boolean block) throws Exception {
        var type = new TypeRef("int");
        var graph = new TypeGraph(List.of(new BaseType("int", "int", 4, BaseEncoding.SIGNED)));
        var symbol = new FunctionSymbol("f", 0x100, 16);
        String blockId = block ? "block" : "";
        var signature = new FunctionSignature("f", 0x100, type,
            kind == Kind.PARAMETER ? List.of(new Parameter("value", type, false)) : List.of(),
            kind == Kind.LOCAL ? List.of(new LocalVariable("value", 4, type, 0, false, "USER_DEFINED")) : List.of(),
            false, false, "default", "USER_DEFINED");
        var statics = kind == Kind.FUNCTION_STATIC ?
            List.of(new FunctionStaticVariable("value", 0x2000, 4, type, 0x100, "USER_DEFINED", blockId)) : List.<FunctionStaticVariable>of();
        var scopes = block ? List.of(new LexicalScopeModel(0x100, symbol.ranges(),
            List.of(new LexicalScopeModel.Block("block", "", List.of(new FunctionRange(0x104, 4)))), List.of(), "LEXICAL_BLOCK")) : List.<LexicalScopeModel>of();
        var model = recovered ? new ProgramTypeModel(graph, List.of(signature), List.of(),
            new VariableStorageModel(List.of()), statics, List.of(), scopes) : null;
        Location location = located ? new ExpressionLocation(new Expression(List.of(new AddressOperation(0x2000)))) :
            new NoLocation("UNASSIGNED", "no proven location");
        var declarations = declarationEmitted ? List.of(new VariableEmission(kind, kind == Kind.PARAMETER ? 0 : -1,
            "value", "value", blockId, type, false, false, location)) : List.<VariableEmission>of();
        var lines = Dwarf5LineTable.buildWithPlan("fixture.c", ".", 8, ByteOrder.LITTLE_ENDIAN, List.of(symbol), List.of());
        var actual = new ExportEmission(graph, signatureEmitted ? Map.of("int", List.of()) : Map.of(), lines,
            List.of(new FunctionEmission(symbol, signatureEmitted ? signature : null, declarations)));
        var coverage = ExportCoverage.build(model, null, List.of(), actual, () -> false);
        var result = JsonParser.parseString(CoverageReportJson.write(coverage, PROFILE, () -> false)).getAsJsonObject();
        require(parse(result).coverage().equals(coverage), "valid fixture round-trips: " + kind + "/" + recovered + "/" + signatureEmitted);
        return result;
    }

    private static void scope(JsonObject document, long start, long end) {
        location(document).add("knownScopeRanges", ranges(start, end));
        location(document).addProperty("knownScopeBytes", Long.toString(end - start));
    }

    private static JsonArray ranges(long... points) {
        var result = new JsonArray();
        for (int i = 0; i < points.length; i += 2) result.add(rangesOfPoints(points[i], points[i + 1]));
        return result;
    }

    private static JsonArray rangesOfPoints(long... points) {
        var result = new JsonArray();
        for (long point : points) result.add("0x" + Long.toHexString(point));
        return result;
    }

    private static JsonObject function(JsonObject d) { return d.getAsJsonArray("functions").get(0).getAsJsonObject(); }
    private static JsonObject variable(JsonObject d) { return d.getAsJsonArray("variables").get(0).getAsJsonObject(); }
    private static JsonObject location(JsonObject d) { return variable(d).getAsJsonObject("location"); }
    private static JsonObject signature(JsonObject d) { return function(d).getAsJsonObject("signature"); }
    private static JsonObject types(JsonObject d) { return function(d).getAsJsonObject("types"); }
    private static JsonObject source(JsonObject d) { return function(d).getAsJsonObject("source"); }

    private static CoverageReportClaims parse(JsonObject document) throws IOException {
        return CoverageReportClaims.read(new ByteArrayInputStream(document.toString().getBytes(StandardCharsets.UTF_8)),
            () -> false, ReportJsonReader.DEFAULT_LIMITS);
    }

    private static void reject(JsonObject original, String diagnostic, Consumer<JsonObject> change) throws Exception {
        var document = original.deepCopy();
        change.accept(document);
        try {
            parse(document);
            throw new AssertionError("accepted inconsistent report: " + diagnostic);
        }
        catch (IOException expected) {
            require(expected.getMessage().contains(diagnostic), "expected " + diagnostic + ", got " + expected.getMessage());
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}

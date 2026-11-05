package ghidradwarfforge.output;

import java.io.IOException;
import java.io.Writer;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.function.BooleanSupplier;

import com.google.gson.stream.JsonWriter;

import ghidradwarfforge.coverage.ExportCoverage;
import ghidradwarfforge.coverage.ExportEmission.Kind;
import ghidradwarfforge.coverage.SourceCoverageInventory;
import ghidradwarfforge.coverage.TypeCoverage;
import ghidradwarfforge.coverage.VariableCoverageInventory;
import ghidradwarfforge.coverage.VariableCoverageTotals;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange;

/**
 * Proposed metric-definition-one payload for report schema two. Counts are exact
 * canonical decimal strings, addresses are canonical hexadecimal strings, and
 * YES/NO flags keep the existing strict lexical report grammar unchanged.
 * Production prepares and strictly reads the full report before artifact publication.
 */
public final class CoverageReportJson {
    public static final int DEFINITION_VERSION = 1;
    static final long MAX_BYTES = 64L * 1024 * 1024;

    public record Profile(String languageId, String compilerSpecId) {
        public Profile {
            if (languageId == null || languageId.isBlank() || compilerSpecId == null || compilerSpecId.isBlank()) {
                throw new IllegalArgumentException("coverage requires explicit language and compiler profile");
            }
        }
    }

    private final JsonWriter json;
    private final BooleanSupplier cancelled;
    private final Map<StorageDetail, Integer> storageDetails = new LinkedHashMap<>();

    /** Exact repeated evidence text, shared without dropping individual range boundaries. */
    record StorageDetail(String category, String source, String omissionReason, String diagnostic) { }

    private CoverageReportJson(JsonWriter json, BooleanSupplier cancelled) {
        this.json = json;
        this.cancelled = cancelled;
    }

    public static String write(ExportCoverage coverage, Profile profile, BooleanSupplier cancelled) throws IOException {
        return write(coverage, profile, cancelled, MAX_BYTES);
    }

    static String write(ExportCoverage coverage, Profile profile, BooleanSupplier cancelled, long byteLimit) throws IOException {
        Objects.requireNonNull(coverage);
        Objects.requireNonNull(profile);
        check(cancelled);
        var output = new BoundedWriter(byteLimit, cancelled);
        try (var json = new JsonWriter(output)) {
            json.setSerializeNulls(true);
            new CoverageReportJson(json, cancelled).document(coverage, profile);
        }
        check(cancelled);
        return output.result();
    }

    /** Writes one value into the enclosing report's bounded stream. */
    static void writeTo(JsonWriter json, CoverageReportClaims claims, BooleanSupplier cancelled) throws IOException {
        new CoverageReportJson(json, cancelled).document(claims.coverage(), claims.profile());
    }

    private void document(ExportCoverage coverage, Profile profile) throws IOException {
        json.beginObject();
        json.name("definitionVersion").value(DEFINITION_VERSION);
        text("addressModel", "ELF_LINK_TIME");
        json.name("profile").beginObject();
        text("languageId", profile.languageId());
        text("compilerSpecId", profile.compilerSpecId());
        json.endObject();
        json.name("summary").beginObject();
        number("functions", (long) coverage.functions().size());
        number("unknownSignatureFunctions", coverage.unknownSignatureFunctions());
        flag("recoveredGlobalsKnown", coverage.recoveredGlobalsKnown());
        number("recoveredGlobals", (long) coverage.recoveredGlobals().size());
        json.name("source");
        sourceUnion(coverage.sourceUnion());
        json.name("variables");
        variables(coverage.variables());
        json.name("variablesByKind").beginObject();
        for (Kind kind : Kind.values()) {
            json.name(kind.name());
            variables(coverage.variablesByKind().get(kind));
        }
        json.endObject();
        json.name("functionTypes");
        types(coverage.functionTypeUnion());
        json.endObject();
        json.name("functions").beginArray();
        for (var function : coverage.functions()) {
            check(cancelled);
            json.beginObject();
            address("entry", function.function().address());
            text("name", function.function().name());
            strings("namespace", function.function().namespacePath());
            ranges("ranges", function.function().ranges());
            json.name("source");
            source(function.source());
            json.name("signature").beginObject();
            flag("recovered", function.signature().recovered());
            flag("emitted", function.signature().emitted());
            text("source", function.signature().source());
            text("recordedCallingConvention", function.signature().recordedCallingConvention());
            text("emittedEffectiveCallingConvention", function.signature().emittedEffectiveCallingConvention());
            text("debuggerCallRestriction", function.signature().debuggerCallRestriction());
            json.endObject();
            text("typeProvenance", function.typeProvenance());
            json.name("types");
            types(function.types());
            json.name("variables");
            variables(function.variables().totals());
            json.name("variablesByKind").beginObject();
            for (Kind kind : Kind.values()) {
                json.name(kind.name());
                variables(function.variables().byKind().get(kind));
            }
            json.endObject();
            json.endObject();
        }
        json.endArray();
        // Flat variable rows keep ranges and evidence within the existing depth budget.
        json.name("variables").beginArray();
        for (var function : coverage.functions()) {
            for (var variable : function.variables().variables()) {
                check(cancelled);
                variable(function.function().address(), variable);
            }
        }
        json.endArray();
        json.name("recoveredGlobals").beginArray();
        for (var global : coverage.recoveredGlobals()) {
            check(cancelled);
            json.beginObject();
            text("name", global.name());
            strings("namespace", global.namespace());
            address("address", global.address());
            number("byteSize", global.size());
            text("type", global.type().key());
            text("source", global.source());
            flag("declaration", global.declaration());
            json.endObject();
        }
        json.endArray();
        json.name("storageEvidenceDetails").beginArray();
        for (var detail : storageDetails.keySet()) {
            check(cancelled);
            json.beginObject();
            text("category", detail.category());
            text("source", detail.source());
            text("omissionReason", detail.omissionReason());
            text("diagnostic", detail.diagnostic());
            json.endObject();
        }
        json.endArray();
        json.endObject();
    }

    private void source(SourceCoverageInventory.FunctionInventory source) throws IOException {
        json.beginObject();
        text("disposition", source.disposition());
        text("diagnostic", source.diagnostic());
        number("decodedInstructions", source.decodedInstructions());
        number("anchoredInstructions", source.anchoredInstructions());
        number("lineVisibleInstructions", source.lineVisibleInstructions());
        text("instructionUnavailableReason", source.instructionUnavailableReason());
        text("tokenUnavailableReason", source.tokenUnavailableReason());
        var points = source.observedPoints();
        addresses("decodedStarts", points == null ? null : points.decoded());
        addresses("anchoredStarts", source.anchoredInstructions() == null ? null : points.anchored());
        addresses("lineVisibleStarts", points == null ? null : points.lineVisible());
        json.endObject();
    }

    private void sourceUnion(SourceCoverageInventory.Union union) throws IOException {
        json.beginObject();
        number("functions", union.functions());
        number("unavailableInstructionFunctions", union.unavailableInstructionFunctions());
        number("unavailableTokenFunctions", union.unavailableTokenFunctions());
        number("decodedInstructions", union.decodedInstructions());
        number("anchoredInstructions", union.anchoredInstructions());
        number("lineVisibleInstructions", union.lineVisibleInstructions());
        json.endObject();
    }

    private void variable(long owner, VariableCoverageInventory.Variable variable) throws IOException {
        json.beginObject();
        var identity = variable.identity();
        address("function", owner);
        text("kind", identity.kind().name());
        number("parameterOrdinal", identity.parameterOrdinal() < 0 ? null : (long) identity.parameterOrdinal());
        text("internalName", identity.internalName());
        text("displayName", variable.displayName());
        text("block", identity.block());
        address("staticAddress", identity.staticAddress());
        text("recoveredType", variable.recoveredType().key());
        text("emittedType", variable.emittedType() == null ? null : variable.emittedType().key());
        json.name("declarationProvenance").beginObject();
        text("category", variable.declarationProvenance().category());
        text("source", variable.declarationProvenance().source());
        text("subject", variable.declarationProvenance().subject());
        json.endObject();
        json.name("storageEvidence").beginArray();
        for (var evidence : variable.storageEvidence()) {
            check(cancelled);
            var detail = new StorageDetail(evidence.category(), evidence.source(), evidence.omissionReason(), evidence.diagnostic());
            Integer index = storageDetails.get(detail);
            if (index == null) {
                if (storageDetails.size() == ReportJsonReader.DEFAULT_LIMITS.arrayItems()) {
                    throw new IOException("storage evidence dictionary exceeds array budget");
                }
                index = storageDetails.size();
                storageDetails.put(detail, index);
            }
            json.beginArray().value(hex(evidence.start())).value(hex(evidence.end())).value(Integer.toString(index)).endArray();
        }
        json.endArray();
        json.name("location").beginObject();
        var location = variable.location();
        flag("declarationEmitted", location.declarationEmitted());
        text("scopeStatus", location.scopeComplete() ? "KNOWN" : "UNKNOWN");
        text("scopeEvidence", location.scopeEvidence());
        ranges("knownScopeRanges", location.knownScopeRanges());
        ranges("locatedRanges", location.locatedRanges());
        number("knownScopeBytes", location.knownScopeBytes());
        number("coveredScopeBytes", location.coveredScopeBytes());
        number("locatedBytes", location.locatedBytes());
        json.endObject();
        text("omissionReason", variable.omissionReason());
        text("diagnostic", variable.diagnostic());
        json.endObject();
    }

    private void variables(VariableCoverageTotals totals) throws IOException {
        json.beginObject();
        number("recoveredVariables", totals.recoveredVariables());
        number("emittedVariables", totals.emittedVariables());
        number("variablesWithLocation", totals.variablesWithLocation());
        number("knownScopeVariables", totals.knownScopeVariables());
        number("unknownScopeVariables", totals.unknownScopeVariables());
        number("knownScopeBytes", totals.knownScopeBytes());
        number("coveredScopeBytes", totals.coveredScopeBytes());
        text("extentUnavailableReason", totals.extentUnavailableReason());
        json.endObject();
    }

    private void types(TypeCoverage types) throws IOException {
        if (types == null) {
            json.nullValue();
            return;
        }
        json.beginObject();
        number("recoveredRoots", types.recoveredRoots());
        number("emittedRoots", types.emittedRoots());
        number("opaqueFreeEmittedRoots", types.opaqueFreeEmittedRoots());
        number("recoveredNodes", types.recoveredNodes());
        number("resolvedEmittedNodes", types.resolvedEmittedNodes());
        number("opaqueEmittedNodes", types.opaqueEmittedNodes());
        number("notEmittedNodes", types.notEmittedNodes());
        number("implicitVoidNodes", types.implicitVoidNodes());
        number("emittedImplicitVoidNodes", types.emittedImplicitVoidNodes());
        json.endObject();
    }

    private void strings(String name, List<String> values) throws IOException {
        json.name(name).beginArray();
        for (String value : values) {
            check(cancelled);
            checkText(value);
            json.value(value);
        }
        json.endArray();
    }

    private void ranges(String name, List<FunctionRange> ranges) throws IOException {
        json.name(name).beginArray();
        for (var range : ranges) {
            check(cancelled);
            json.beginArray().value(hex(range.address())).value(hex(range.endExclusive())).endArray();
        }
        json.endArray();
    }

    private void addresses(String name, List<Long> addresses) throws IOException {
        json.name(name);
        if (addresses == null) {
            json.nullValue();
            return;
        }
        json.beginArray();
        for (long address : addresses) {
            check(cancelled);
            json.value(hex(address));
        }
        json.endArray();
    }

    private void number(String name, Long value) throws IOException {
        check(cancelled);
        if (value != null && value < 0) throw new IllegalArgumentException("negative coverage count");
        json.name(name).value(value == null ? null : Long.toString(value));
    }

    private void address(String name, Long value) throws IOException {
        check(cancelled);
        json.name(name).value(value == null ? null : hex(value));
    }

    private static String hex(long address) {
        if (address < 0) throw new IllegalArgumentException("coverage address outside supported domain");
        return "0x" + Long.toHexString(address);
    }

    private void flag(String name, boolean value) throws IOException {
        text(name, value ? "YES" : "NO");
    }

    private void text(String name, String value) throws IOException {
        check(cancelled);
        checkText(value);
        json.name(name).value(value);
    }

    private static void checkText(String value) throws IOException {
        if (value != null && value.length() > ReportJsonReader.DEFAULT_LIMITS.stringUnits()) {
            throw new IOException("coverage string exceeds UTF-16 unit budget");
        }
    }

    private static void check(BooleanSupplier cancelled) {
        if (cancelled.getAsBoolean()) throw new CancellationException("coverage serialization cancelled");
    }

    /** Counts actual UTF-8 bytes before appending, including surrogate pairs split across writes. */
    static final class BoundedWriter extends Writer {
        private final StringBuilder output = new StringBuilder();
        private final BooleanSupplier cancelled;
        private final long limit;
        private long bytes;
        private boolean highSurrogate;

        BoundedWriter(long limit, BooleanSupplier cancelled) {
            if (limit < 1 || limit > MAX_BYTES) throw new IllegalArgumentException("invalid coverage byte budget");
            this.limit = limit;
            this.cancelled = cancelled;
        }

        @Override
        public void write(char[] characters, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, characters.length);
            for (int index = offset; index < offset + length; index++) {
                if ((index - offset) % 1024 == 0) check(cancelled);
                char value = characters[index];
                int additional;
                if (highSurrogate) {
                    if (!Character.isLowSurrogate(value)) throw new IOException("unpaired coverage surrogate");
                    highSurrogate = false;
                    additional = 0; // Its four bytes were reserved at the high surrogate.
                }
                else if (Character.isLowSurrogate(value)) {
                    throw new IOException("unpaired coverage surrogate");
                }
                else if (Character.isHighSurrogate(value)) {
                    highSurrogate = true;
                    additional = 4;
                }
                else additional = value <= 0x7f ? 1 : value <= 0x7ff ? 2 : 3;
                if (additional > limit - bytes) throw new IOException("coverage exceeds UTF-8 byte budget " + limit);
                bytes += additional;
                output.append(value);
            }
        }

        @Override
        public void flush() { check(cancelled); }

        @Override
        public void close() throws IOException {
            check(cancelled);
            if (highSurrogate) throw new IOException("unpaired coverage surrogate");
        }

        String result() throws IOException {
            if (highSurrogate) throw new IOException("unpaired coverage surrogate");
            return output.toString();
        }
    }
}

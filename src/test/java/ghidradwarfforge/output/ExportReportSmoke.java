package ghidradwarfforge.output;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import ghidradwarfforge.GhidraFunctionSymbols.SkipReason;
import ghidradwarfforge.GhidraFunctionSymbols.SkippedFunction;
import ghidradwarfforge.locations.VariableStorageModel;
import ghidradwarfforge.locations.VariableStorageModel.Confidence;
import ghidradwarfforge.locations.VariableStorageModel.Evidence;
import ghidradwarfforge.locations.VariableStorageModel.LocationRange;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.locations.VariableStorageModel.VariableKind;
import ghidradwarfforge.locations.VariableStorageModel.VariableLocation;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.source.SyntheticSourceFile.RelativeLine;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.ProgramTypeModel.LocalVariable;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.BaseEncoding;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.OpaqueType;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.TypeNode;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Native-independent structured report, ordering, and JSON escaping smoke test. */
public final class ExportReportSmoke {
    private static final String A_HASH = "a".repeat(64);
    private static final String B_HASH = "b".repeat(64);
    private static final String C_HASH = "c".repeat(64);

    private ExportReportSmoke() {
    }

    public static void main(String[] args) {
        TypeRef signedInt = new TypeRef("builtin:int32");
        List<TypeNode> nodes = new ArrayList<>(List.of(
            new OpaqueType("opaque", "odd\"type", 0, "unsupported\nshape"),
            new BaseType(signedInt.key(), "int", 4, BaseEncoding.SIGNED)));
        TypeGraph types = new TypeGraph(nodes);
        FunctionSignature signature = new FunctionSignature("ok", 0x1000, signedInt,
            List.of(new Parameter("argument", signedInt, false)),
            List.of(new LocalVariable("local", 4, signedInt, 0, false, "ANALYSIS")),
            false, false, "default", "ANALYSIS");
        VariableLocation unavailable = new VariableLocation("ok", 0x1000, "argument",
            VariableKind.PARAMETER, 4, List.of(new LocationRange(0x1000, 0x1010,
                new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME,
                    "lifetime is unknown"),
                new Evidence(Confidence.ANALYSIS, "fixture"))));
        ProgramTypeModel typeModel = new ProgramTypeModel(types, List.of(signature),
            List.of(), new VariableStorageModel(List.of(unavailable)));
        SyntheticSourceFile source = SyntheticSourceFile.build("fixture", "x86:LE:64",
            List.of(
                new FunctionText("failed", 0x2000, null, "bad \"decompile\"\nresult"),
                new FunctionText("ok", 0x1000, "int ok(int argument) {\n return argument;\n}\n",
                    null, List.of(new RelativeLine(2, List.of(0x1004L))))));
        List<SkippedFunction> skipped = new ArrayList<>(List.of(
            new SkippedFunction("zeta", SkipReason.THUNK),
            new SkippedFunction("alpha", SkipReason.EXTERNAL_IMPORT)));
        List<String> diagnostics = new ArrayList<>(List.of("z diagnostic", "a diagnostic",
            "a diagnostic"));

        ExportReport first = report(typeModel, source, skipped, diagnostics);
        Collections.reverse(nodes);
        Collections.reverse(skipped);
        Collections.reverse(diagnostics);
        ExportReport second = report(typeModel, source, skipped, diagnostics);
        if (first.status() != ExportReport.Status.PARTIAL ||
                !first.toJson().equals(second.toJson())) {
            throw new AssertionError("report status/order is not deterministic");
        }
        String json = first.toJson();
        requireContains(json, "\"schemaVersion\":1,\"status\":\"PARTIAL\"");
        requireContains(json, "\"functionsExported\":2");
        requireContains(json, "\"functionsFailed\":1");
        requireContains(json, "\"functionsSkipped\":2");
        requireContains(json, "\"omittedLocationRanges\":1");
        requireContains(json, "\"name\":\"failed\",\"address\":\"0x2000\"," +
            "\"diagnostic\":\"bad \\\"decompile\\\"\\nresult\"");
        requireContains(json, "\"name\":\"alpha\",\"reason\":\"EXTERNAL_IMPORT\"");
        requireContains(json, "\"reason\":\"UNKNOWN_LIFETIME\"");
        requireContains(json, "\"name\":\"odd\\\"type\"," +
            "\"diagnostic\":\"unsupported\\nshape\"");
        requireContains(json, "\"diagnostics\":[\"a diagnostic\",\"z diagnostic\"]");
        requireContains(json, "\"validation\":{\"status\":\"NOT_RUN\"}");
        requireContains(json, "\"native\":{\"libdwarfVersion\":\"2.3.2\"}");

        ExportReport fatal = ExportReport.terminal(ExportReport.Status.FATAL,
            new IllegalStateException("unsafe \"value\"\nline"));
        String expectedFatal = "{\"schemaVersion\":1,\"status\":\"FATAL\"," +
            "\"target\":null,\"artifacts\":null,\"counts\":null,\"sections\":[]," +
            "\"failedFunctions\":[],\"skippedFunctions\":[],\"omittedLocations\":[]," +
            "\"unsupportedConstructs\":[],\"diagnostics\":[]," +
            "\"validation\":{\"status\":\"NOT_RUN\"}," +
            "\"native\":{\"libdwarfVersion\":null}," +
            "\"failure\":{\"type\":\"java.lang.IllegalStateException\"," +
            "\"message\":\"unsafe \\\"value\\\"\\nline\"}}";
        if (!fatal.toJson().equals(expectedFatal)) {
            throw new AssertionError("fatal JSON changed:\n" + fatal.toJson());
        }
        SyntheticSourceFile cleanSource = SyntheticSourceFile.build("fixture", "x86:LE:64",
            List.of(new FunctionText("ok", 0x1000, "int ok(void) {\n return 0;\n}\n",
                null, List.of())));
        ProgramTypeModel cleanModel = new ProgramTypeModel(
            new TypeGraph(List.of(new BaseType(signedInt.key(), "int", 4,
                BaseEncoding.SIGNED))),
            List.of(new FunctionSignature("ok", 0x1000, signedInt, List.of(), List.of(),
                false, false, "default", "ANALYSIS")), List.of());
        ExportReport clean = report(cleanModel, cleanSource, List.of(), List.of());
        if (clean.status() != ExportReport.Status.SUCCESS ||
                !clean.toJson().contains("\"status\":\"SUCCESS\"")) {
            throw new AssertionError("clean report is not successful");
        }
        ExportReport cancelled = ExportReport.terminal(ExportReport.Status.CANCELLED,
            new InterruptedException("cancelled by user"));
        if (!cancelled.toJson().contains("\"status\":\"CANCELLED\"") ||
                !cancelled.toJson().contains("\"message\":\"cancelled by user\"")) {
            throw new AssertionError("cancellation report is incomplete");
        }
        System.out.println("export-report-smoke=PASS");
    }

    private static ExportReport report(ProgramTypeModel typeModel,
            SyntheticSourceFile source, List<SkippedFunction> skipped,
            List<String> diagnostics) {
        return ExportReport.completed(new DwarfTarget("x86_64", "x86_64", 8, true),
            "2.3.2", Path.of("fixture.elf"), A_HASH, Path.of("fixture.elf.dbg"), B_HASH,
            Path.of("fixture.elf.dbg.c"), C_HASH, source.functions().size(),
            List.of(".debug_line", ".debug_abbrev", ".debug_info"), source, typeModel,
            skipped, diagnostics);
    }

    private static void requireContains(String value, String expected) {
        if (!value.contains(expected)) {
            throw new AssertionError("missing JSON fragment: " + expected + "\n" + value);
        }
    }
}

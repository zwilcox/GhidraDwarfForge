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

    public static void main(String[] args) throws Exception {
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
            List.of(), new VariableStorageModel(List.of(unavailable)), List.of(
                new ProgramTypeModel.FunctionStaticVariable("private_count", 0x3000, 4,
                    signedInt, 0x1000, "USER_DEFINED")));
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
        requireContains(json, "\"functionStaticVariables\":1");
        requireContains(json, "\"globalVariables\":0");
        requireContains(json, "\"name\":\"failed\",\"address\":\"0x2000\"," +
            "\"diagnostic\":\"bad \\\"decompile\\\"\\nresult\"");
        requireContains(json, "\"name\":\"alpha\",\"reason\":\"EXTERNAL_IMPORT\"");
        requireContains(json, "\"reason\":\"UNKNOWN_LIFETIME\"");
        requireContains(json, "\"name\":\"odd\\\"type\"," +
            "\"diagnostic\":\"unsupported\\nshape\"");
        requireContains(json, "\"diagnostics\":[\"a diagnostic\",\"z diagnostic\"]");
        requireContains(json, "\"validation\":{\"status\":\"NOT_RUN\"}");
        requireContains(json, "\"native\":{\"libdwarfVersion\":\"2.3.2\"}");

        ProgramTypeModel failedStaticModel = new ProgramTypeModel(types,
            List.of(signature, new FunctionSignature("failed", 0x2000, signedInt,
                List.of(), List.of(), false, false, "default", "USER_DEFINED")),
            typeModel.globals(), typeModel.variableStorage(), List.of(
                typeModel.functionStatics().get(0),
                new ProgramTypeModel.FunctionStaticVariable("failed_private", 0x3004, 4,
                    signedInt, 0x2000, "USER_DEFINED")));
        String failedStaticJson = report(failedStaticModel, source, skipped, diagnostics).toJson();
        requireContains(failedStaticJson, "\"functionStaticVariables\":1");
        requireContains(failedStaticJson, "Omitted function-owned static variable " +
            "failed_private at 0x3004; owning function at 0x2000 failed decompilation " +
            "and remains symbol-only");
        if (ghidradwarfforge.source.FunctionStaticPolicy.select(failedStaticModel, null)
                .exported().size() != 2) {
            throw new AssertionError("absent source was treated as a decompilation failure");
        }

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
        // Reports serialize path spelling without filesystem access or lexical
        // changes: a parent may no longer exist when an export is reported.
        Path unresolved = Path.of("unresolved-parent", "..", "fixture.elf");
        String pathReport = ExportReport.completed(
            new DwarfTarget("x86_64", "x86_64", 8, true, "x86"), "2.3.2",
            unresolved, A_HASH, unresolved, B_HASH, unresolved, C_HASH,
            source.functions().size(), List.of(".debug_info"), source, typeModel,
            skipped, diagnostics).toJson();
        requireContains(pathReport, "\"inputPath\":\"" +
            unresolved.toAbsolutePath().toString().replace("\\", "\\\\") + "\"");
        publicationWarnings(clean, first, fatal);
        textRoundTrips(cleanModel, cleanSource);
        terminalMessages();
        ExportReportContractSmoke.check();
        System.out.println("export-report-smoke=PASS");
    }

    private static com.google.gson.JsonObject decoded(String text) {
        // These writers emit compact JSON. Any literal C0 character is invalid
        // here, even if a permissive third-party parser would accept it.
        if (text.chars().anyMatch(character -> character < 0x20)) {
            throw new AssertionError("literal control character in compact report JSON");
        }
        byte[] bytes = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return com.google.gson.JsonParser.parseString(new String(bytes,
            java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
    }

    private static void textRoundTrips(ProgramTypeModel model, SyntheticSourceFile source) throws Exception {
        var values = new ArrayList<>(List.of("quote \" and backslash \\ and literal \\u001f",
            "\"},\"status\":\"SUCCESS\",\"injected\":\"value", "Unicode λ 😀 \u2028 \u2029"));
        for (int control = 0; control < 32; control++) values.add("before" + (char) control + "after");
        for (String value : values) {
            // POSIX permits controls other than NUL in a path component. Other
            // hosts still exercise every control in diagnostics and failures.
            String component = java.io.File.separatorChar == '/' && value.indexOf('\0') < 0
                ? value : "portable Unicode λ 😀";
            Path input = Path.of("unopened", component + ".elf");
            Path sidecar = Path.of("unopened", component + ".dbg");
            Path synthetic = Path.of("unopened", component + ".dbg.c");
            var report = ExportReport.completed(new DwarfTarget("x86_64", "x86_64", 8, true, "x86"),
                "2.3.2", input, A_HASH, sidecar, B_HASH, synthetic, C_HASH,
                source.functions().size(), List.of(".debug_info"), source, model, List.of(), List.of(value));
            String text = report.toJson();
            var json = decoded(text);
            if (!text.equals(report.toJson()) || !json.get("status").getAsString().equals("PARTIAL") ||
                    json.has("injected") || json.getAsJsonArray("diagnostics").size() != 1 ||
                    !json.getAsJsonArray("diagnostics").get(0).getAsString().equals(value)) {
                throw new AssertionError("report changed or reinterpreted diagnostic text");
            }
            var artifacts = json.getAsJsonObject("artifacts");
            if (!artifacts.get("inputPath").getAsString().equals(input.toAbsolutePath().toString()) ||
                    !artifacts.get("outputPath").getAsString().equals(sidecar.toAbsolutePath().toString()) ||
                    !artifacts.get("sourcePath").getAsString().equals(synthetic.toAbsolutePath().toString())) {
                throw new AssertionError("report changed selected artifact path spelling");
            }
            var detailed = ExportReportClaims.readDetailed(Path.of("unopened-report"), () -> false,
                ignored -> new java.io.ByteArrayInputStream(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                ReportJsonReader.DEFAULT_LIMITS, ExportReportClaims.DEFAULT_RETENTION);
            if (!detailed.inventories().diagnostics().equals(List.of(value)) ||
                    !detailed.claims().artifacts().inputPath().equals(input.toAbsolutePath().toString())) {
                throw new AssertionError("strict reader lost emitted text");
            }
            for (var status : List.of(ExportReport.Status.FATAL, ExportReport.Status.CANCELLED)) {
                var failure = decoded(ExportReport.terminal(status, new IllegalStateException(value)).toJson());
                if (!failure.get("status").getAsString().equals(status.name()) ||
                        !failure.getAsJsonObject("failure").get("message").getAsString().equals(value)) {
                    throw new AssertionError("terminal report changed diagnostic text or status");
                }
            }
        }
        System.out.println("export-report-text-roundtrips=PASS cases=" + values.size());
    }

    private static void publicationWarnings(ExportReport clean, ExportReport partial, ExportReport fatal) {
        String warning = "A staging directory needs cleanup";
        for (ExportReport completed : List.of(clean, partial)) {
            String before = completed.toJson();
            var expected = decoded(before);
            var messages = new com.google.gson.JsonArray();
            messages.add(warning);
            messages.addAll(expected.getAsJsonArray("diagnostics"));
            expected.add("diagnostics", messages);
            expected.getAsJsonObject("counts").addProperty("diagnostics", messages.size());
            expected.addProperty("status", "PARTIAL");

            var warned = completed.withPublicationWarning(warning);
            if (!expected.equals(decoded(warned.toJson())) ||
                    !expected.equals(decoded(warned.withPublicationWarning(warning).toJson())) ||
                    !before.equals(completed.toJson())) {
                throw new AssertionError("cleanup warning changed completed claims or appeared more than once");
            }
        }
        try {
            fatal.withPublicationWarning(warning);
            throw new AssertionError("failed export reported committed artifacts needing cleanup");
        }
        catch (IllegalStateException expected) { }
    }

    private static void terminalMessages() {
        for (var status : List.of(ExportReport.Status.FATAL, ExportReport.Status.CANCELLED)) {
            for (Throwable failure : List.of(new IllegalStateException((String) null),
                    new IllegalStateException(" \t\r\n"), new InterruptedException())) {
                var json = decoded(ExportReport.terminal(status, failure).toJson());
                var detail = json.getAsJsonObject("failure");
                if (!detail.get("message").getAsString().equals(failure.getClass().getName()) ||
                        !detail.get("type").getAsString().equals(failure.getClass().getName()) ||
                        !json.get("status").getAsString().equals(status.name())) {
                    throw new AssertionError("empty terminal message lost exception identity");
                }
            }
        }
        for (var status : List.of(ExportReport.Status.SUCCESS, ExportReport.Status.PARTIAL)) {
            try {
                ExportReport.terminal(status, new IllegalStateException("not a completed export"));
                throw new AssertionError("terminal failure claimed a completed export");
            }
            catch (IllegalArgumentException expected) { }
        }
    }

    private static ExportReport report(ProgramTypeModel typeModel,
            SyntheticSourceFile source, List<SkippedFunction> skipped,
            List<String> diagnostics) {
        return ExportReport.completed(new DwarfTarget("x86_64", "x86_64", 8, true, "x86"),
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

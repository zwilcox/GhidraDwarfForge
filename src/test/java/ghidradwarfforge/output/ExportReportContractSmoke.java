package ghidradwarfforge.output;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonParser;

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
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.TypeGraph;

/** Independent partial-status causes and report-model admission boundaries. */
final class ExportReportContractSmoke {
    private static final String HASH = "0123456789aBcDeF".repeat(4);
    private static final Path UNOPENED = Path.of("unopened", "fixture");
    private static final TypeGraph.TypeRef INTEGER = new TypeGraph.TypeRef("int");
    private static int checks;

    static void check() throws Exception {
        for (var target : List.of(new DwarfTarget("x86_64", "x86_64", 8, true, "x86"),
                new DwarfTarget("mips", "mips", 4, false, "MIPS"))) {
            for (int mask = 0; mask < 32; mask++) status(target, mask);
        }
        modelBoundaries();
        System.out.println("export-report-contracts=PASS status-cases=64 checks=" + checks);
    }

    private static void status(DwarfTarget target, int mask) throws Exception {
        boolean failed = (mask & 1) != 0;
        boolean skipped = (mask & 2) != 0;
        boolean unavailable = (mask & 4) != 0;
        boolean opaque = (mask & 8) != 0;
        boolean diagnostic = (mask & 16) != 0;
        var nodes = new ArrayList<TypeGraph.TypeNode>();
        nodes.add(new TypeGraph.BaseType(INTEGER.key(), "int", 4, TypeGraph.BaseEncoding.SIGNED));
        if (opaque) nodes.add(new TypeGraph.OpaqueType("unknown", "unknown", 0, "unproved layout"));
        var signature = new ProgramTypeModel.FunctionSignature("work", 0x1000, INTEGER, List.of(),
            unavailable ? List.of(new ProgramTypeModel.LocalVariable("value", 4, INTEGER, 0, false, "USER_DEFINED")) : List.of(),
            false, false, "default", "USER_DEFINED");
        var locations = new VariableStorageModel(unavailable ? List.of(new VariableLocation("work", 0x1000,
            "value", VariableKind.LOCAL, 4, List.of(new LocationRange(0x1000, 0x1010,
                new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "unproved lifetime"),
                new Evidence(Confidence.USER_DEFINED, "saved identity only"))))) : List.of());
        var model = new ProgramTypeModel(new TypeGraph(nodes), List.of(signature), List.of(), locations);
        var source = SyntheticSourceFile.build("fixture", "report-only", List.of(failed
            ? new SyntheticSourceFile.FunctionText("work", 0x1000, null, "decompiler failure")
            : new SyntheticSourceFile.FunctionText("work", 0x1000,
                "int work(void) {\n" + (unavailable ? " int value;\n" : "") + " return 0;\n}\n", null,
                List.of(new SyntheticSourceFile.RelativeLine(unavailable ? 3 : 2, List.of(0x1004L))))));
        var skippedFunctions = new ArrayList<SkippedFunction>();
        if (skipped) skippedFunctions.add(new SkippedFunction("external", SkipReason.EXTERNAL_IMPORT));
        var diagnostics = new ArrayList<String>();
        if (diagnostic) diagnostics.addAll(List.of("analyst note", "analyst note"));
        var sections = new ArrayList<>(List.of(".debug_line", ".debug_info", ".debug_line"));
        var report = completed(target, source, model, 1, sections, skippedFunctions, diagnostics);
        String text = report.toJson();
        var document = JsonParser.parseString(text).getAsJsonObject();
        var expectedStatus = mask == 0 ? ExportReport.Status.SUCCESS : ExportReport.Status.PARTIAL;
        require(report.status() == expectedStatus && document.get("status").getAsString().equals(expectedStatus.name()),
            "independent partial-status cause was lost: " + mask);
        var expected = Map.ofEntries(Map.entry("functionsExported", 1), Map.entry("functionsDecompiled", failed ? 0 : 1),
            Map.entry("functionsFailed", failed ? 1 : 0), Map.entry("functionsSkipped", skipped ? 1 : 0),
            Map.entry("functionSignatures", 1), Map.entry("parameters", 0), Map.entry("localVariables", unavailable ? 1 : 0),
            Map.entry("globalVariables", 0), Map.entry("functionStaticVariables", 0), Map.entry("canonicalTypes", opaque ? 2 : 1),
            Map.entry("defensibleVariableLocations", 0), Map.entry("omittedLocationRanges", unavailable ? 1 : 0),
            // The function declaration and return statement have distinct mappings.
            Map.entry("mappedSourceLines", failed ? 0 : 2), Map.entry("unsupportedConstructs", opaque ? 1 : 0),
            Map.entry("diagnostics", diagnostic ? 1 : 0));
        var counts = document.getAsJsonObject("counts");
        require(counts.keySet().equals(expected.keySet()), "report lost or invented a count category");
        for (var count : expected.entrySet()) {
            require(counts.get(count.getKey()).getAsInt() == count.getValue(),
                "wrong count for status mask " + mask + ": " + count.getKey() + "=" + counts.get(count.getKey()));
        }
        var read = ExportReportClaims.readDetailed(UNOPENED, () -> false,
            ignored -> new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8)),
            ReportJsonReader.DEFAULT_LIMITS, ExportReportClaims.DEFAULT_RETENTION);
        require(read.claims().status() == expectedStatus && read.claims().validationStatus() == ExportReport.ValidationStatus.NOT_RUN,
            "reader upgraded an export report to validation authority");
        require(read.inventories().diagnostics().equals(diagnostic ? List.of("analyst note") : List.of()),
            "diagnostic deduplication changed its meaning");
        require(read.claims().target().addressBits() == (target.name().equals("mips") ? 32 : 64) &&
            read.claims().target().byteOrder().equals(target.name().equals("mips") ? "BIG_ENDIAN" : "LITTLE_ENDIAN"),
            "target identity was normalized to the host");
        diagnostics.clear(); skippedFunctions.clear(); sections.clear(); nodes.clear();
        require(report.toJson().equals(text), "caller mutation changed a completed report");
    }

    private static ExportReport completed(DwarfTarget target, SyntheticSourceFile source, ProgramTypeModel model,
            int count, List<String> sections, List<SkippedFunction> skipped, List<String> diagnostics) {
        return ExportReport.completed(target, "reported version", UNOPENED, HASH, UNOPENED, HASH,
            UNOPENED, HASH, count, sections, source, model, skipped, diagnostics);
    }

    private static void modelBoundaries() throws Exception {
        // Counts are independent nonnegative claims, not arithmetic evidence of
        // validation. Test each field without inventing relationships among them.
        int[] fields = new int[15];
        for (int i = 0; i < fields.length; i++) fields[i] = i + 1;
        for (int field = 0; field < fields.length; field++) {
            for (int value : new int[] {0, 1, Integer.MAX_VALUE}) {
                int[] values = fields.clone(); values[field] = value;
                require(Arrays.equals(values, values(counts(values))), "count boundary changed or fields were reordered");
            }
            for (int value : new int[] {-1, Integer.MIN_VALUE}) {
                int[] values = fields.clone(); values[field] = value;
                reject(() -> counts(values));
            }
        }
        for (int bits : new int[] {Integer.MIN_VALUE, -1, 0, 8, 16, 24, 31, 33, 63, 65, Integer.MAX_VALUE}) {
            reject(() -> new ExportReport.TargetInfo("target", bits, "BIG_ENDIAN"));
        }
        for (int bits : new int[] {32, 64}) {
            require(new ExportReport.TargetInfo("target", bits, "BIG_ENDIAN").addressBits() == bits, "valid address size rejected");
        }
        String[] valid = {"input", HASH, "output", HASH, "source", HASH};
        for (int field = 0; field < valid.length; field++) {
            for (String bad : new String[] {null, "", " \t\n"}) {
                String[] values = valid.clone(); values[field] = bad;
                reject(() -> artifacts(values));
            }
            if (field % 2 == 1) {
                for (String bad : List.of("a".repeat(63), "a".repeat(65), "g".repeat(64))) {
                    String[] values = valid.clone(); values[field] = bad;
                    reject(() -> artifacts(values));
                }
            }
        }
        require(artifacts(valid).sourceSha256().equals(HASH), "mixed-case SHA-256 claim changed");
        for (long[] range : List.of(new long[] {-1, 1}, new long[] {0, 0}, new long[] {4, 3},
                new long[] {Long.MAX_VALUE, Long.MAX_VALUE})) {
            reject(() -> omission(range[0], range[1]));
        }
        for (long[] range : List.of(new long[] {0, 1}, new long[] {Long.MAX_VALUE - 1, Long.MAX_VALUE})) {
            var value = omission(range[0], range[1]);
            require(value.startAddress() == range[0] && value.endAddress() == range[1], "omitted range was narrowed");
        }
        var target = new DwarfTarget("x86_64", "x86_64", 8, true, "x86");
        var source = SyntheticSourceFile.build("fixture", "report-only", List.of());
        var model = new ProgramTypeModel(new TypeGraph(List.of()), List.of(), List.of());
        reject(() -> completed(null, source, model, 0, List.of(), List.of(), List.of()));
        reject(() -> completed(target, null, model, 0, List.of(), List.of(), List.of()));
        reject(() -> completed(target, source, null, 0, List.of(), List.of(), List.of()));
        reject(() -> completed(target, source, model, -1, List.of(), List.of(), List.of()));
    }

    private static ExportReport.Counts counts(int[] v) {
        return new ExportReport.Counts(v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12], v[13], v[14]);
    }

    private static int[] values(ExportReport.Counts c) {
        return new int[] {c.functionsExported(), c.functionsDecompiled(), c.functionsFailed(), c.functionsSkipped(),
            c.functionSignatures(), c.parameters(), c.localVariables(), c.globalVariables(), c.functionStaticVariables(),
            c.canonicalTypes(), c.defensibleVariableLocations(), c.omittedLocationRanges(), c.mappedSourceLines(),
            c.unsupportedConstructs(), c.diagnostics()};
    }

    private static ExportReport.Artifacts artifacts(String[] v) {
        return new ExportReport.Artifacts(v[0], v[1], v[2], v[3], v[4], v[5]);
    }

    private static ExportReport.OmittedLocation omission(long start, long end) {
        return new ExportReport.OmittedLocation("work", "value", "LOCAL", start, end, "UNKNOWN_LIFETIME", "unproved lifetime");
    }

    private static void reject(Runnable action) {
        try { action.run(); }
        catch (IllegalArgumentException expected) { checks++; return; }
        throw new AssertionError("invalid export-report model was accepted");
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

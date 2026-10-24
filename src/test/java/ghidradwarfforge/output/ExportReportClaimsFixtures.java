package ghidradwarfforge.output;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
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
import ghidradwarfforge.source.SyntheticSourceFile.FunctionLines;
import ghidradwarfforge.source.SyntheticSourceFile.SourceLine;
import ghidradwarfforge.types.ProgramTypeModel;
import ghidradwarfforge.types.ProgramTypeModel.FunctionSignature;
import ghidradwarfforge.types.ProgramTypeModel.LocalVariable;
import ghidradwarfforge.types.TypeGraph;
import ghidradwarfforge.types.TypeGraph.BaseEncoding;
import ghidradwarfforge.types.TypeGraph.BaseType;
import ghidradwarfforge.types.TypeGraph.OpaqueType;
import ghidradwarfforge.types.TypeGraph.Parameter;
import ghidradwarfforge.types.TypeGraph.TypeRef;

/** Actual writer-generated fixtures, independent of the new reader's schema code. */
final class ExportReportClaimsFixtures {
    private ExportReportClaimsFixtures() {
    }

    static ExportReport completed(boolean partial) {
        TypeRef integer = new TypeRef("int");
        BaseType base = new BaseType(integer.key(), "int", 4, BaseEncoding.SIGNED);
        TypeGraph types = new TypeGraph(partial
            ? List.of(base, new OpaqueType("unknown", "odd\"type", 0, "unknown\nlayout"))
            : List.of(base));
        FunctionSignature signature = new FunctionSignature("good", 0x1000, integer,
            List.of(new Parameter("argument", integer, false)),
            List.of(new LocalVariable("local", 4, integer, 0, false, "ANALYSIS")),
            false, false, "default", "ANALYSIS");
        VariableStorageModel locations = new VariableStorageModel(partial ? List.of(
            new VariableLocation("good", 0x1000, "argument", VariableKind.PARAMETER, 4,
                List.of(new LocationRange(0x1000, 0x1010,
                    new UnavailableStorage(OmissionReason.UNKNOWN_LIFETIME, "unknown\tlifetime"),
                    new Evidence(Confidence.ANALYSIS, "fixture"))))) : List.of());
        ProgramTypeModel model = new ProgramTypeModel(types, List.of(signature), List.of(),
            locations, List.of(new ProgramTypeModel.FunctionStaticVariable("private", 0x2000,
                4, integer, 0x1000, "USER_DEFINED")));
        FunctionLines good = new FunctionLines("good", 0x1000, 1, 2, true, null);
        // The writer accepts any FunctionLines address; do not accidentally
        // strengthen this report contract into an ELF address-validity claim.
        FunctionLines bad = new FunctionLines("failed", Long.MIN_VALUE, 3, 4, false,
            "bad \"decompile\"\nresult 😀");
        SyntheticSourceFile source = new SyntheticSourceFile("fixture\n".getBytes(StandardCharsets.UTF_8),
            partial ? List.of(good, bad) : List.of(good), List.of(new SourceLine(1, List.of(0x1000L))));
        ExportReport report = ExportReport.completed(new DwarfTarget("x86_64", "x86_64", 8, true, "x86"),
            "reported version", Path.of("unopened", "..", "input.elf"), "A".repeat(64),
            Path.of("unopened", "output.dbg"), "b".repeat(64),
            Path.of("unopened", "output.dbg.c"), "C".repeat(64),
            99, List.of("", ".debug_info"), source, model,
            partial ? List.of(new SkippedFunction("external", SkipReason.EXTERNAL_IMPORT)) : List.of(),
            partial ? List.of("", "analyst \"message\"\\\n😀") : List.of());
        if (report.status() != (partial ? ExportReport.Status.PARTIAL : ExportReport.Status.SUCCESS)) {
            throw new AssertionError("writer fixture has wrong status");
        }
        return report;
    }

    static ExportReport terminal(ExportReport.Status status) {
        return ExportReport.terminal(status, new IllegalStateException("terminal \"message\"\n😀"));
    }
}

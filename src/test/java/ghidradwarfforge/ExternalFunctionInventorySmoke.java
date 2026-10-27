package ghidradwarfforge;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonParser;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.GhidraFunctionSymbols.ExtractionResult;
import ghidradwarfforge.GhidraFunctionSymbols.SkipReason;
import ghidradwarfforge.GhidraFunctionSymbols.SkippedFunction;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.output.ExportReport;
import ghidradwarfforge.source.SyntheticSourceFile;
import ghidradwarfforge.source.SyntheticSourceFile.FunctionText;
import ghidradwarfforge.types.ProgramTypeModel;

/** Actual pinned function iterators and omitted-inventory semantics; no DWARF producer. */
public final class ExternalFunctionInventorySmoke {
    private record Target(String language, String name) {
    }

    private ExternalFunctionInventorySmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(
                new Target("x86:LE:64:default", "x86_64"),
                new Target("AARCH64:LE:64:v8A", "aarch64"),
                new Target("ARM:LE:32:v8", "arm"),
                new Target("MIPS:BE:32:default", "mips"),
                new Target("MIPS:LE:32:default", "mipsel"))) {
            check(target);
        }
        System.out.println("external-function-inventory-smoke=PASS");
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(
            new LanguageID(target.language()));
        Object owner = new Object();
        var program = new ProgramDB("external-inventory", language,
            language.getDefaultCompilerSpec(), owner);
        int transaction = program.startTransaction("external inventory controls");
        try {
            var start = language.getDefaultSpace().getAddress(0x400000);
            program.getMemory().createInitializedBlock("code", start, 0x100,
                (byte) 0, TaskMonitor.DUMMY, false);
            Function local = function(program, "ordinary", 0x400000);
            var integer = new IntegerDataType(program.getDataTypeManager());
            local.setReturnType(integer, SourceType.USER_DEFINED);
            local.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true, SourceType.USER_DEFINED);
            var manager = program.getExternalManager();
            manager.addExtLocation("lib_a", "external_data", null, SourceType.USER_DEFINED)
                .setDataType(integer);
            var before = extract(program, new ArrayList<>());
            var beforeTypes = types(program, before, target);
            require(before.functions().size() == 1 && before.skippedFunctions().isEmpty(),
                "external DATA was treated as a function");
            require(report(program, target, before, beforeTypes, List.of()).status() ==
                ExportReport.Status.SUCCESS, "control without omitted functions is not successful");

            var library = manager.addExternalLibraryName("lib_z", SourceType.USER_DEFINED);
            Function first = manager.addExtFunction(library, "same", start.add(0x800),
                SourceType.IMPORTED, false).getFunction();
            Function duplicate = manager.addExtFunction(library, "same", start.add(0x804),
                SourceType.USER_DEFINED, false).getFunction();
            require(first.getID() != duplicate.getID() &&
                first.getName(true).equals(duplicate.getName(true)),
                "same-display-name external multiplicity control collapsed");
            Function otherLibrary = manager.addExtFunction("lib_a", "same", null,
                SourceType.USER_DEFINED).getFunction();
            var nested = program.getSymbolTable().createNameSpace(
                otherLibrary.getParentNamespace(), "nested", SourceType.USER_DEFINED);
            Function unreferenced = manager.addExtFunction(nested, "unreferenced", null,
                SourceType.USER_DEFINED).getFunction();
            require(unreferenced.getSymbol().getReferenceCount() == 0 &&
                unreferenced.getExternalLocation().getAddress() == null &&
                unreferenced.getEntryPoint().isExternalAddress(),
                "unreferenced external placeholder control is vacuous");
            var externalOnly = new StructureDataType("external_signature_only", 4,
                program.getDataTypeManager());
            unreferenced.setReturnType(externalOnly, SourceType.USER_DEFINED);
            unreferenced.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                true, SourceType.USER_DEFINED,
                new ParameterImpl("external_parameter", integer, program, SourceType.USER_DEFINED));
            unreferenced.setVarArgs(true);
            manager.addExtFunction("lib_a", "unknown_prototype", null, SourceType.IMPORTED);
            // Name provenance alone does not establish a prototype. These three
            // declarations have independently curated signature provenance.
            first.setReturnType(integer, SourceType.USER_DEFINED);
            duplicate.setReturnType(integer, SourceType.USER_DEFINED);
            otherLibrary.setReturnType(integer, SourceType.IMPORTED);
            var expected = List.of(
                new SkippedFunction("lib_a::nested::unreferenced", SkipReason.EXTERNAL_IMPORT),
                new SkippedFunction("lib_a::same", SkipReason.EXTERNAL_IMPORT),
                new SkippedFunction("lib_a::unknown_prototype", SkipReason.EXTERNAL_IMPORT),
                new SkippedFunction("lib_z::same", SkipReason.EXTERNAL_IMPORT),
                new SkippedFunction("lib_z::same", SkipReason.EXTERNAL_IMPORT));
            var diagnostics = new ArrayList<String>();
            var after = extract(program, diagnostics);
            require(after.functions().equals(before.functions()) &&
                after.skippedFunctions().equals(expected), "external inventory differs: " + after);
            var afterTypes = types(program, after, target);
            require(afterTypes.functions().equals(beforeTypes.functions()) &&
                afterTypes.globals().equals(beforeTypes.globals()) &&
                afterTypes.variableStorage().equals(beforeTypes.variableStorage()) &&
                afterTypes.functionStatics().equals(beforeTypes.functionStatics()),
                "external declarations changed definition or memory-location selection");
            var declarations = afterTypes.functionDeclarations();
            require(declarations.size() == 4 && declarations.stream()
                .noneMatch(row -> row.name().contains("unknown_prototype")) &&
                declarations.stream().map(row -> row.key()).distinct().count() == 4,
                "curated declarations lost identity or invented an unknown prototype");
            require(declarations.stream().filter(row -> row.name().equals("lib_z::same")).count() == 2,
                "same-display-name declarations were conflated");
            var declaration = declarations.get(0);
            require(declaration.name().equals("lib_a::nested::unreferenced") && declaration.variadic() &&
                declaration.signatureSource().equals("USER_DEFINED") &&
                afterTypes.types().byKey().get(declaration.returnType().key()).name().equals("external_signature_only") &&
                declaration.parameters().stream().anyMatch(parameter -> parameter.name().equals("external_parameter")),
                "unreferenced curated declaration lost its formal signature");
            require(types(program, after, target).equals(afterTypes), "declaration order is unstable");
            var report = report(program, target, after, beforeTypes, diagnostics);
            var json = JsonParser.parseString(report.toJson()).getAsJsonObject();
            require(report.status() == ExportReport.Status.PARTIAL &&
                json.getAsJsonObject("counts").get("functionsSkipped").getAsInt() == 5 &&
                json.getAsJsonObject("counts").get("functionsExported").getAsInt() == 1 &&
                json.getAsJsonObject("counts").get("functionSignatures").getAsInt() == 1 &&
                json.getAsJsonArray("skippedFunctions").size() == 5 &&
                json.getAsJsonArray("diagnostics").size() == 4,
                "external-only omissions did not preserve report multiplicity/status/counts");
            var repeatedDiagnostics = new ArrayList<String>();
            require(extract(program, repeatedDiagnostics).equals(after) &&
                diagnostics.equals(repeatedDiagnostics) &&
                report(program, target, after, beforeTypes, repeatedDiagnostics).toJson()
                    .equals(report.toJson()), "inventory/report order is unstable");

            // Two uncurated memory thunks remain distinct omissions from their external target.
            for (long offset : new long[] {0x400020, 0x400040}) {
                var stub = function(program, "stub_" + Long.toHexString(offset), offset);
                stub.getSymbol().setSource(SourceType.ANALYSIS);
                stub.setThunkedFunction(first);
            }
            var withThunks = extract(program, new ArrayList<>());
            require(withThunks.functions().equals(before.functions()) &&
                withThunks.skippedFunctions().size() == 7 &&
                withThunks.skippedFunctions().stream().filter(row -> row.reason() ==
                    SkipReason.EXTERNAL_IMPORT).toList().equals(expected) &&
                withThunks.skippedFunctions().stream().filter(row -> row.reason() ==
                    SkipReason.THUNK).count() == 2, "thunks and targets were merged");
            require(types(program, withThunks, target).equals(afterTypes),
                "memory thunks introduced additional declarations or changed types");
            AtomicInteger attempts = new AtomicInteger();
            var source = GhidraSyntheticSource.decompile(program, withThunks.functions(), 0,
                TaskMonitor.DUMMY, (decompiler, function, timeout, monitor) -> {
                    require(!function.isExternal() && !function.isThunk() &&
                        function.getID() == local.getID(), "external/thunk reached decompilation");
                    attempts.incrementAndGet();
                    return null; // Isolated per-definition failure; no native decompilation.
                });
            require(attempts.get() == 1 && source.functions().size() == 1 &&
                !source.functions().get(0).decompiled(), "decompilation selection changed");
            cancellation(program);
            System.out.println("external-function-inventory-target=PASS " + target.language());
        }
        finally {
            program.endTransaction(transaction, false);
            program.release(owner);
        }
    }

    private static void cancellation(ProgramDB program) throws Exception {
        // Three memory functions precede the external iterator. Abort during its second row.
        var marker = new CancelledException("external iteration control");
        var polls = new AtomicInteger();
        var monitor = new TaskMonitorAdapter(true) {
            @Override
            public void checkCancelled() throws CancelledException {
                if (polls.incrementAndGet() == 5) {
                    throw marker;
                }
            }
        };
        try {
            GhidraFunctionSymbols.extractDetailed(program, monitor, ignored -> { }, 0);
            throw new AssertionError("external iteration ignored cancellation");
        }
        catch (CancelledException expected) {
            require(expected == marker && polls.get() == 5, "cancellation identity changed");
        }
        var cancelled = new TaskMonitorAdapter(true);
        var emitted = new AtomicInteger();
        try {
            GhidraFunctionSymbols.extractDetailed(program, cancelled, diagnostic -> {
                if (diagnostic.startsWith("Skipped external/import")) {
                    emitted.incrementAndGet();
                    cancelled.cancel();
                }
            }, 0);
            throw new AssertionError("external diagnostic emission ignored cancellation");
        }
        catch (CancelledException expected) {
            require(emitted.get() == 1, "cancellation did not stop external diagnostics");
        }
    }

    private static ExtractionResult extract(ProgramDB program, List<String> diagnostics)
            throws Exception {
        return GhidraFunctionSymbols.extractDetailed(program, TaskMonitor.DUMMY,
            diagnostics::add, 0);
    }

    private static ProgramTypeModel types(ProgramDB program, ExtractionResult extracted,
            Target target) throws Exception {
        return GhidraTypeGraph.extract(program, extracted.functions(), target.name(), 0,
            TaskMonitor.DUMMY, message -> { throw new AssertionError(message); });
    }

    private static ExportReport report(ProgramDB program, Target target,
            ExtractionResult extracted, ProgramTypeModel model, List<String> diagnostics) {
        var language = program.getLanguage();
        var description = new DwarfTarget(target.name(), "test-only", language.getLanguageDescription()
            .getSize() / 8, !language.isBigEndian(), language.getProcessor().toString());
        var source = SyntheticSourceFile.build("external-inventory", target.language(), List.of(
            new FunctionText("ordinary", 0x400000, "int ordinary(void) { return 7; }\n", null)));
        return ExportReport.completed(description, "test-only", Path.of("original"), "a".repeat(64),
            Path.of("original.dbg"), "b".repeat(64), Path.of("original.dbg.c"), "c".repeat(64),
            extracted.functions().size(), List.of(), source, model, extracted.skippedFunctions(), diagnostics);
    }

    private static Function function(ProgramDB program, String name, long address) throws Exception {
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
        return program.getFunctionManager().createFunction(name, entry,
            new AddressSet(entry, entry.add(15)), SourceType.USER_DEFINED);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

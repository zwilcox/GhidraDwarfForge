package ghidradwarfforge;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonParser;
import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.nativeapi.DwarfTarget;
import ghidradwarfforge.output.ExportReport;
import ghidradwarfforge.output.ExportReportClaims;
import ghidradwarfforge.source.FunctionStaticPolicy;

/** Curated thunk identity and source omission, including immutable saved programs. */
public final class CuratedThunkSmoke {
    private record Target(String language, String map) { }
    private static int checks;

    private CuratedThunkSmoke() { }

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
        System.out.println("curated-thunk-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        Object owner = new Object();
        var program = new ProgramDB("curated-thunks", language, language.getDefaultCompilerSpec(), owner);
        var directory = Files.createTempDirectory("forge-curated-thunks-");
        var saved = directory.resolve("program.db");
        try {
            int transaction = program.startTransaction("thunk controls");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start, 0x2000,
                    (byte) 0, TaskMonitor.DUMMY, false);
                Function destination = function(program, "destination", 0x1000, SourceType.USER_DEFINED);
                destination.setReturnType(IntegerDataType.dataType, SourceType.USER_DEFINED);
                destination.replaceParameters(Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                    true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", IntegerDataType.dataType, program, SourceType.USER_DEFINED));
                Function curated = function(program, "analyst_gateway", 0x1100, SourceType.USER_DEFINED);
                curated.setThunkedFunction(destination);
                var namespace = program.getSymbolTable().createNameSpace(null, "analyst", SourceType.USER_DEFINED);
                curated.setParentNamespace(namespace);
                function(program, "automatic_gateway", 0x1200, SourceType.ANALYSIS).setThunkedFunction(destination);
                function(program, "imported_gateway", 0x1300, SourceType.IMPORTED).setThunkedFunction(destination);
                // Actual defined data in each function namespace, independent of decompiler output.
                for (Function function : List.of(destination, curated)) {
                    var address = start.add(function == destination ? 0x1000 : 0x1004);
                    program.getListing().createData(address, IntegerDataType.dataType);
                    program.getSymbolTable().createLabel(address, "owned_value", function, SourceType.USER_DEFINED);
                }
            }
            finally {
                program.endTransaction(transaction, true);
            }
            observe(program, target, directory);
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved));
            var mtime = Files.getLastModifiedTime(saved);
            Object reopenedOwner = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                observe(reopened, target, directory);
            }
            finally {
                if (reopened != null) {
                    reopened.release(reopenedOwner);
                }
                else {
                    handle.close();
                }
            }
            require(Arrays.equals(before, MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(saved))) &&
                mtime.equals(Files.getLastModifiedTime(saved)), "immutable program changed");
            System.out.println("curated-thunk-target=PASS " + target.language());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(directory.resolve("report.json"));
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static Function function(ProgramDB program, String name, long offset, SourceType source)
            throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
        return program.getFunctionManager().createFunction(name, address,
            new AddressSet(address, address.add(3)), source);
    }

    private static void observe(ProgramDB program, Target target, java.nio.file.Path directory) throws Exception {
        var diagnostics = new ArrayList<String>();
        var inventory = GhidraFunctionSymbols.extractDetailed(program, TaskMonitor.DUMMY, diagnostics::add, 0);
        require(inventory.functions().size() == 2 && inventory.skippedFunctions().size() == 2,
            "curated and automatic thunk inventory differs: " + inventory);
        var symbol = inventory.functions().stream().filter(row -> row.address() == 0x1100).findFirst().orElseThrow();
        require(symbol.qualifiedDisplayName().equals("analyst::analyst_gateway") && symbol.ranges().size() == 1 &&
            symbol.ranges().get(0).address() == 0x1100 && symbol.ranges().get(0).endExclusive() == 0x1104,
            "thunk lost its own name/body");
        require(inventory.skippedFunctions().stream().allMatch(row -> row.reason() ==
            GhidraFunctionSymbols.SkipReason.THUNK), "uncurated thunk selection changed");
        var attempts = new AtomicInteger();
        var decompilation = GhidraSyntheticSource.decompileDetailed(program, inventory.functions(), 0,
            TaskMonitor.DUMMY, (decompiler, function, timeout, monitor) -> {
                require(!function.isThunk() && function.getName().equals("destination"),
                    "thunk reached destination-substituting decompiler");
                attempts.incrementAndGet();
                return null;
            });
        var source = decompilation.source();
        require(attempts.get() == 1 && decompilation.recoveredReturns().isEmpty() &&
            decompilation.recoveredParameters().isEmpty(), "borrowed recovery evidence");
        require(source.functions().size() == 2 && source.mappedLines().isEmpty(), "unavailable source has line rows");
        var thunk = source.functions().stream().filter(row -> row.address() == 0x1100).findFirst().orElseThrow();
        var failed = source.functions().stream().filter(row -> row.address() == 0x1000).findFirst().orElseThrow();
        require(!thunk.decompiled() && thunk.failureDiagnostic() == null && thunk.omissionDiagnostic() != null,
            "intentional omission became failure");
        require(!failed.decompiled() && failed.failureDiagnostic() != null && failed.omissionDiagnostic() == null,
            "real decompilation failure changed");
        String text = new String(source.utf8(), StandardCharsets.UTF_8);
        require(text.contains("Synthetic source intentionally omitted for analyst_gateway") &&
            text.contains("Decompilation unavailable for destination"), "source diagnostics missing");
        var model = GhidraTypeGraph.extract(program, inventory.functions(), target.map(), 0,
            TaskMonitor.DUMMY, diagnostics::add);
        var signature = model.functions().stream().filter(row -> row.address() == 0x1100).findFirst().orElseThrow();
        require(signature.signatureSource().equals("USER_DEFINED") && signature.parameters().size() == 1 &&
            signature.parameters().get(0).name().equals("value") &&
            model.types().byKey().get(signature.returnType().key()).name().equals("int"), "formal signature lost");
        require(model.functionStatics().size() == 2, "static controls missing");
        require(model.functionRelations().thunks().size() == 1 &&
            model.functionRelations().thunks().getFirst().function().address() == 0x1100 &&
            model.functionRelations().thunks().getFirst().target().address() == 0x1000,
            "saved direct thunk relationship lost");
        var statics = FunctionStaticPolicy.select(model, source);
        require(statics.exported().size() == 1 && statics.exported().get(0).ownerAddress() == 0x1100 &&
            statics.diagnostics().size() == 1, "intentional omission suppressed curated static or retained failed owner");
        var language = program.getLanguage();
        var dwarfTarget = new DwarfTarget(target.map(), "test-only", language.getLanguageDescription().getSize() / 8,
            !language.isBigEndian(), language.getProcessor().toString());
        var report = ExportReport.completed(dwarfTarget, "test-only", directory.resolve("original"), "a".repeat(64),
            directory.resolve("original.dbg"), "b".repeat(64), directory.resolve("original.dbg.c"), "c".repeat(64),
            2, List.of(), source, model, inventory.skippedFunctions(), diagnostics);
        var json = JsonParser.parseString(report.toJson()).getAsJsonObject();
        require(report.status() == ExportReport.Status.PARTIAL &&
            json.getAsJsonObject("counts").get("functionsFailed").getAsInt() == 1 &&
            json.getAsJsonArray("failedFunctions").get(0).getAsJsonObject().get("name").getAsString().equals("destination"),
            "report confused omission with failure");
        boolean omittedSource = false;
        for (var row : json.getAsJsonArray("unsupportedConstructs")) {
            omittedSource |= row.getAsJsonObject().get("kind").getAsString().equals("OMITTED_SOURCE");
        }
        require(omittedSource, "report lost omission");
        var reportPath = directory.resolve("report.json");
        Files.writeString(reportPath, report.toJson());
        require(ExportReportClaims.read(reportPath) != null, "report claims rejected intentional omission");
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            GhidraSyntheticSource.decompile(program, List.of(symbol), 0, cancelled);
            throw new AssertionError("thunk-only source ignored cancellation");
        }
        catch (CancelledException expected) {
            checks++;
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

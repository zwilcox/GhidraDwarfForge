package ghidradwarfforge;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Default-name custom storage still needs parameter and return ABI equivalence. */
public final class CustomCallStorageSmoke {
    private record Target(String language, String map, String alternateReturn) { }
    private record Expected(long entry, String name, String restriction) { }
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(new Target("x86:LE:64:default", "x86_64", "ECX"),
                new Target("x86:LE:32:default", "x86", "ECX"),
                new Target("AARCH64:LE:64:v8A", "aarch64", "w1"),
                new Target("ARM:LE:32:v7", "arm", "r1"),
                new Target("MIPS:BE:32:default", "mips", "v1"),
                new Target("MIPS:LE:32:default", "mipsel", "v1"))) {
            check(target);
        }
        System.out.println("custom-call-storage-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        var compiler = target.map().equals("x86_64") || target.map().equals("x86")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) : language.getDefaultCompilerSpec();
        Object owner = new Object();
        var program = new ProgramDB("custom-call-storage", language, compiler, owner);
        var expected = new ArrayList<Expected>();
        try {
            int transaction = program.startTransaction("custom storage controls");
            try {
                var start = language.getDefaultSpace().getAddress(0x1000);
                program.getMemory().createInitializedBlock("code", start, 0x1000, (byte) 0, TaskMonitor.DUMMY, false);
                for (String role : List.of("dynamic", "equivalent", "swapped", "return_mismatch", "void_return",
                        "variadic", "unknown", "aggregate", "unassigned")) {
                    long entry = 0x1000 + expected.size() * 0x20;
                    var address = language.getDefaultSpace().getAddress(entry);
                    var function = program.getFunctionManager().createFunction(role, address,
                        new AddressSet(address, address.add(3)), SourceType.USER_DEFINED);
                    var external = program.getExternalManager().addExtFunction("library", role, null,
                        SourceType.USER_DEFINED).getFunction();
                    prepare(program, function, target, role);
                    prepare(program, external, target, role);
                    String reason = switch (role) {
                        case "dynamic", "equivalent", "void_return" -> "";
                        case "swapped" -> "parameter 0 storage";
                        case "return_mismatch" -> "return storage";
                        case "variadic" -> "variadic";
                        case "unknown" -> "resolved default";
                        case "aggregate" -> "type";
                        default -> "storage";
                    };
                    expected.add(new Expected(entry, role, reason));
                }
            }
            finally {
                program.endTransaction(transaction, true);
            }
            observe(program, target, expected);
            var saved = Files.createTempDirectory("forge-custom-call-").resolve("program.db");
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] bytes = Files.readAllBytes(saved);
            var mtime = Files.getLastModifiedTime(saved);
            Object immutableOwner = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB immutable = null;
            try {
                immutable = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, immutableOwner);
                observe(immutable, target, expected);
            }
            finally {
                if (immutable == null) handle.close();
                else immutable.release(immutableOwner);
            }
            require(Arrays.equals(bytes, Files.readAllBytes(saved)) && mtime.equals(Files.getLastModifiedTime(saved)),
                "immutable database changed");
            System.out.println("custom-call-storage-target=PASS " + target.language());
        }
        finally {
            program.release(owner);
        }
    }

    private static void prepare(ProgramDB program, Function function, Target target, String role) throws Exception {
        String convention = program.getCompilerSpec().getDefaultCallingConvention().getName();
        DataType result = role.equals("void_return") ? VoidDataType.dataType : IntegerDataType.dataType;
        function.updateFunction(convention, new ReturnParameterImpl(result, program),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("first", IntegerDataType.dataType, program),
            new ParameterImpl("second", IntegerDataType.dataType, program));
        if (role.equals("dynamic")) return;
        function.setCustomVariableStorage(true);
        if (role.equals("swapped")) {
            Parameter[] old = function.getParameters();
            function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                new ParameterImpl("first", IntegerDataType.dataType, old[1].getVariableStorage(), program),
                new ParameterImpl("second", IntegerDataType.dataType, old[0].getVariableStorage(), program));
        }
        else if (role.equals("return_mismatch")) {
            function.setReturn(IntegerDataType.dataType,
                new VariableStorage(program, program.getRegister(target.alternateReturn())), SourceType.USER_DEFINED);
        }
        else if (role.equals("variadic")) function.setVarArgs(true);
        else if (role.equals("unknown")) function.setCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING);
        else if (role.equals("aggregate")) {
            var aggregate = new StructureDataType("aggregate", 0);
            aggregate.add(IntegerDataType.dataType, "field", null);
            function.getParameter(0).setDataType(aggregate, function.getParameter(0).getVariableStorage(),
                true, SourceType.USER_DEFINED);
        }
        else if (role.equals("unassigned")) {
            function.getParameter(0).setDataType(IntegerDataType.dataType, VariableStorage.UNASSIGNED_STORAGE,
                true, SourceType.USER_DEFINED);
        }
    }

    private static void observe(ProgramDB program, Target target, List<Expected> expected) throws Exception {
        var symbols = expected.stream().map(row -> new FunctionSymbol(row.name(), row.entry(), 4)).toList();
        var diagnostics = new ArrayList<String>();
        var model = GhidraTypeGraph.extract(program, symbols, target.map(), 0, TaskMonitor.DUMMY, diagnostics::add);
        require(model.functions().size() == expected.size() && model.functionDeclarations().size() == expected.size(),
            "signature count changed");
        for (Expected row : expected) {
            var signature = model.functions().stream().filter(s -> s.name().equals(row.name())).findFirst().orElseThrow();
            var declaration = model.functionDeclarations().stream().filter(s -> s.name().equals("library::" + row.name()))
                .findFirst().orElseThrow();
            boolean blocked = !row.restriction().isEmpty();
            require(!signature.nonDefaultCallingConvention() && !declaration.nonDefaultCallingConvention(),
                "custom restriction mislabeled as nondefault convention");
            require(signature.debuggerCallsDisabled() == blocked && declaration.debuggerCallsDisabled() == blocked,
                "wrong call policy " + row + ": " + signature.debuggerCallRestriction());
            require(signature.debuggerCallRestriction().contains(row.restriction()) &&
                signature.debuggerCallRestriction().equals(declaration.debuggerCallRestriction()),
                "wrong restriction " + row + ": " + signature.debuggerCallRestriction());
            require(signature.parameters().size() == 2 && declaration.parameters().size() == 2 &&
                signature.signatureSource().equals("USER_DEFINED"), "signature metadata lost");
        }
        require(diagnostics.stream().filter(s -> s.startsWith("Debugger-injected calls disabled for ")).count() == 12,
            "restriction diagnostic multiplicity changed");
        var repeated = new ArrayList<String>();
        require(model.equals(GhidraTypeGraph.extract(program, symbols, target.map(), 0, TaskMonitor.DUMMY,
            repeated::add)) && diagnostics.equals(repeated), "nondeterministic extraction");
        var cancelled = new TaskMonitorAdapter(true);
        cancelled.cancel();
        try {
            GhidraCustomCallStorage.restriction(program, program.getFunctionManager().getFunctions(true).next(), cancelled);
            throw new AssertionError("cancel ignored");
        }
        catch (CancelledException expectedCancellation) {
            checks++;
        }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

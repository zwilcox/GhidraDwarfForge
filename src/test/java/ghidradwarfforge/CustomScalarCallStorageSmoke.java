package ghidradwarfforge;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/** Additional custom-storage restrictions only; an empty result is not general ABI certification. */
public final class CustomScalarCallStorageSmoke {
    private static int checks;

    private CustomScalarCallStorageSmoke() { }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        run();
    }

    static void run() throws Exception {
        checks = 0;
        for (String id : List.of("x86:LE:64:default", "x86:LE:32:default", "AARCH64:LE:64:v8A",
                "ARM:LE:32:v7", "MIPS:BE:32:default", "MIPS:LE:32:default")) {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(id));
            var compiler = id.startsWith("x86:") ? language.getCompilerSpecByID(new CompilerSpecID("gcc")) :
                language.getDefaultCompilerSpec();
            Object owner = new Object();
            var program = new ProgramDB("custom-scalar", language, compiler, owner);
            int transaction = program.startTransaction("explicit scalar storage fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var function = program.getFunctionManager().createFunction("scalar", entry,
                    new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
                var manager = program.getDataTypeManager();
                var state = new EnumDataType(CategoryPath.ROOT, "State", 4, manager);
                state.add("READY", 1);
                state.add("ERROR", -1);
                var scalarTypes = List.<DataType>of(IntegerDataType.dataType, FloatDataType.dataType,
                    DoubleDataType.dataType, BooleanDataType.dataType, new PointerDataType(ByteDataType.dataType, manager), state);
                for (DataType base : scalarTypes) {
                    for (int aliases : new int[] {0, 1, 65}) {
                        DataType type = base;
                        for (int index = 0; index < aliases; index++) {
                            type = new TypedefDataType(CategoryPath.ROOT, base.getName() + "_alias_" + aliases + "_" + index,
                                type, manager);
                        }
                        prepare(program, function, type, type, 1);
                        observe(program, function, "");
                    }
                }
                var aggregate = new StructureDataType("Aggregate", 0, manager);
                aggregate.add(IntegerDataType.dataType, "field", null);
                for (DataType unclassified : List.of(aggregate, Undefined4DataType.dataType)) {
                    prepare(program, function, IntegerDataType.dataType, IntegerDataType.dataType, 1);
                    function.getParameter(0).setDataType(unclassified, function.getParameter(0).getVariableStorage(),
                        true, SourceType.USER_DEFINED);
                    require(function.getParameter(0).getFormalDataType().isEquivalent(unclassified),
                        "explicit unsupported parameter type must be preserved");
                    observe(program, function, "custom parameter 0 type has no validated debugger ABI classification");
                    prepare(program, function, IntegerDataType.dataType, IntegerDataType.dataType, 1);
                    function.setReturn(unclassified, function.getReturn().getVariableStorage(), SourceType.USER_DEFINED);
                    require(function.getReturn().getFormalDataType().isEquivalent(unclassified),
                        "explicit unsupported return type must be preserved");
                    observe(program, function, "custom return type has no validated debugger ABI classification");
                }
                prepare(program, function, IntegerDataType.dataType, IntegerDataType.dataType, 1);
                for (var convention : compiler.getCallingConventions()) {
                    if (convention.getName().equals(compiler.getDefaultCallingConvention().getName())) continue;
                    function.setCallingConvention(convention.getName());
                    observe(program, function, "custom storage has no resolved default calling-convention model");
                }
                prepare(program, function, IntegerDataType.dataType, IntegerDataType.dataType, 3);
                var cancelled = new TaskMonitorAdapter(true) {
                    private int polls;
                    @Override
                    public void checkCancelled() throws CancelledException {
                        if (++polls == 3) cancel();
                        super.checkCancelled();
                    }
                };
                long before = program.getModificationNumber();
                try {
                    GhidraCustomCallStorage.restriction(program, function, cancelled);
                    throw new AssertionError("classification ignored mid-signature cancellation");
                }
                catch (CancelledException expected) { checks++; }
                require(program.getModificationNumber() == before, "cancelled classification changed program");
                observe(program, function, "");
                if (id.equals("x86:LE:64:default")) {
                    // The pinned GCC model has six integer registers and a finite
                    // 500-byte stack input region with eight-byte alignment.
                    for (int count : new int[] {68, 69, 4096, 4097}) {
                        prepare(program, function, IntegerDataType.dataType, IntegerDataType.dataType, count);
                        require(function.getParameterCount() == count, "signature count changed before classification");
                        if (count == 68) {
                            var last = function.getParameter(67).getVariableStorage();
                            require(last.isStackStorage() && last.getStackOffset() == 496 && last.size() == 4,
                                "last fully classified integer must retain its exact stack slot");
                        }
                        else require(function.getParameter(68).getVariableStorage().isUnassignedStorage(),
                            "exhausted compiler-model input region must remain unassigned");
                        observe(program, function, count == 68 ? "" : count <= 4096 ?
                            "custom parameter 68 storage differs from or cannot be proved equivalent to the default prototype" :
                            "custom signature exceeds the parameter classification budget");
                    }
                }
            }
            finally {
                try { program.endTransaction(transaction, false); }
                finally { program.release(owner); }
            }
        }
        System.out.println("custom-scalar-call-storage=PASS checks=" + checks);
    }

    private static void prepare(ProgramDB program, Function function, DataType returned, DataType parameter, int count)
            throws Exception {
        function.setCustomVariableStorage(false);
        var parameters = new ArrayList<ParameterImpl>();
        for (int index = 0; index < count; index++) parameters.add(new ParameterImpl("arg" + index, parameter, program));
        function.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(),
            new ReturnParameterImpl(returned, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true, SourceType.USER_DEFINED, parameters.toArray(ParameterImpl[]::new));
        function.setCustomVariableStorage(true);
    }

    private static void observe(ProgramDB program, Function function, String expected) throws Exception {
        require(function.hasCustomVariableStorage(), "fixture must use explicit saved storage");
        var parameters = function.getParameters();
        var storage = Arrays.stream(parameters).map(p -> p.getVariableStorage()).toList();
        var types = Arrays.stream(parameters).map(p -> p.getFormalDataType()).toList();
        var returned = function.getReturn().getFormalDataType();
        var returnStorage = function.getReturn().getVariableStorage();
        long modification = program.getModificationNumber();
        String actual = GhidraCustomCallStorage.restriction(program, function, TaskMonitor.DUMMY);
        require(actual.equals(expected), "unexpected custom scalar policy for " + program.getLanguageID() + ": " +
            actual + " expected=" + expected);
        require(actual.equals(GhidraCustomCallStorage.restriction(program, function, TaskMonitor.DUMMY)),
            "custom scalar restriction changed on repeat");
        require(modification == program.getModificationNumber() &&
            storage.equals(Arrays.stream(function.getParameters()).map(p -> p.getVariableStorage()).toList()) &&
            types.equals(Arrays.stream(function.getParameters()).map(p -> p.getFormalDataType()).toList()) &&
            returned.equals(function.getReturn().getFormalDataType()) &&
            returnStorage.equals(function.getReturn().getVariableStorage()), "classification modified saved signature");
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}

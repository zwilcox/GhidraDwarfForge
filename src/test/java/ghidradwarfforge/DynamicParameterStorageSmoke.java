package ghidradwarfforge;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import db.DBHandle;
import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.OpenMode;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.DynamicVariableStorage;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.OmissionReason;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;
import ghidradwarfforge.locations.VariableStorageModel.Storage;
import ghidradwarfforge.locations.VariableStorageModel.UnavailableStorage;
import ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol;

/** Actual computed parameter storage before/after immutable reopen; no native producer. */
public final class DynamicParameterStorageSmoke {
    private record Target(String language, String map, String code,
            List<String> incoming) {
    }

    private static int checks;

    private DynamicParameterStorageSmoke() {
    }

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (Target target : List.of(
                new Target("x86:LE:64:default", "x86_64", "90c3", List.of("EDI", "ESI")),
                new Target("AARCH64:LE:64:v8A", "aarch64", "1f2003d5c0035fd6", List.of("w0", "w1")),
                new Target("ARM:LE:32:v8", "arm", "00f020e31eff2fe1", List.of("r0", "r1")),
                new Target("MIPS:BE:32:default", "mips", "0000000003e0000800000000", List.of("a0", "a1")),
                new Target("MIPS:LE:32:default", "mipsel", "000000000800e00300000000", List.of("a0", "a1")))) {
            check(target);
        }
        System.out.println("dynamic-parameter-storage-smoke=PASS checks=" + checks);
    }

    private static void check(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        Object owner = new Object();
        var compiler = target.map().equals("x86_64")
            ? language.getCompilerSpecByID(new CompilerSpecID("gcc"))
            : language.getDefaultCompilerSpec();
        var program = new ProgramDB("dynamic-parameters", language, compiler, owner);
        var directory = Files.createTempDirectory("forge-dynamic-parameters-");
        var saved = directory.resolve("program.db");
        try {
            int transaction = program.startTransaction("dynamic parameter controls");
            try {
                Function function = create(program, target, 0x1000, "integer_arguments", false, null);
                observe(program, function, target, target.incoming());
                rejectionControls(program, function, target);
                if (target.map().equals("arm")) {
                    observe(program, create(program, target, 0x1100, "base_float_arguments", true,
                        "__stdcall_softfp"), target, List.of("r0", "r1"));
                    observe(program, create(program, target, 0x1200, "vfp_float_arguments", true,
                        "__stdcall"), target, List.of("s0", "s1"));
                }
            }
            finally {
                program.endTransaction(transaction, true);
            }
            program.getDBHandle().saveAs(saved.toFile(), false, TaskMonitor.DUMMY);
            byte[] before = sha(Files.readAllBytes(saved));
            var mtime = Files.getLastModifiedTime(saved);
            Object reopenedOwner = new Object();
            DBHandle handle = new DBHandle(saved.toFile());
            ProgramDB reopened = null;
            try {
                reopened = new ProgramDB(handle, OpenMode.IMMUTABLE, TaskMonitor.DUMMY, reopenedOwner);
                observe(reopened, at(reopened, 0x1000), target, target.incoming());
                if (target.map().equals("arm")) {
                    observe(reopened, at(reopened, 0x1100), target, List.of("r0", "r1"));
                    observe(reopened, at(reopened, 0x1200), target, List.of("s0", "s1"));
                }
            }
            finally {
                if (reopened != null) {
                    reopened.release(reopenedOwner);
                }
                else {
                    handle.close();
                }
            }
            require(Arrays.equals(before, sha(Files.readAllBytes(saved))) &&
                mtime.equals(Files.getLastModifiedTime(saved)), "immutable reopen modified database");
            System.out.println("dynamic-parameter-storage-target=PASS " + target.language());
        }
        finally {
            program.release(owner);
            Files.deleteIfExists(saved);
            Files.deleteIfExists(directory);
        }
    }

    private static Function create(ProgramDB program, Target target, long entry,
            String name, boolean floating, String convention) throws Exception {
        byte[] code = HexFormat.of().parseHex(target.code());
        var start = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry);
        var body = new AddressSet(start, start.add(code.length - 1));
        var block = program.getMemory().createInitializedBlock(name, start, code.length,
            (byte) 0, TaskMonitor.DUMMY, false);
        block.setExecute(true);
        program.getMemory().setBytes(start, code);
        if (target.map().equals("arm")) {
            program.getProgramContext().setValue(program.getRegister("TMode"), start,
                body.getMaxAddress(), BigInteger.ZERO);
        }
        require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY),
            "fixture did not decode");
        var function = program.getFunctionManager().createFunction(name, start, body, SourceType.USER_DEFINED);
        function.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
        var type = floating ? new FloatDataType(program.getDataTypeManager())
            : new IntegerDataType(program.getDataTypeManager());
        function.updateFunction(convention, function.getReturn(),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            new ParameterImpl("first", type, program, SourceType.USER_DEFINED),
            new ParameterImpl("second", type, program, SourceType.USER_DEFINED));
        return function;
    }

    private static Function at(ProgramDB program, long address) {
        return program.getFunctionManager().getFunctionAt(
            program.getAddressFactory().getDefaultAddressSpace().getAddress(address));
    }

    private static void observe(ProgramDB program, Function function, Target target,
            List<String> expectedRegisters) throws Exception {
        require(function != null && !function.hasCustomVariableStorage() &&
            function.getSignatureSource() == SourceType.USER_DEFINED && function.getParameterCount() == 2,
            "dynamic signature did not persist");
        for (int ordinal = 0; ordinal < 2; ordinal++) {
            Parameter parameter = function.getParameter(ordinal);
            var effective = parameter.getVariableStorage();
            require(!parameter.hasAssignedStorage() && effective != null && effective.isValid() &&
                !effective.isBadStorage() && !effective.isUnassignedStorage() &&
                !effective.isForcedIndirect() && effective.isRegisterStorage() &&
                effective.getVarnodeCount() == 1 && effective.size() == 4 &&
                parameter.getRegister().getName().equals(expectedRegisters.get(ordinal)),
                "computed storage premise differs: " + parameter.getName() + " " + effective);
            Storage translated = GhidraVariableStorage.stableParameter(program, function,
                parameter, TargetRegisterMap.forTarget(target.map()), TaskMonitor.DUMMY);
            require(translated instanceof RegisterStorage register && register.bitSize() == 32,
                "valid computed storage was omitted: " + translated);
            // The persisted-assignment rule for locals is deliberately independent.
            omitted(GhidraVariableStorage.stableLocal(program, function, parameter,
                TargetRegisterMap.forTarget(target.map()), TaskMonitor.DUMMY), OmissionReason.UNASSIGNED);
        }
        var model = GhidraTypeGraph.extract(program, List.of(new FunctionSymbol(function.getName(),
            function.getEntryPoint().getOffset(), function.getBody().getNumAddresses())), target.map(),
            0, TaskMonitor.DUMMY, ignored -> { });
        require(model.functions().size() == 1 && model.functions().get(0).parameters().size() == 2 &&
            model.functions().get(0).callingConvention().equals(function.getCallingConventionName()) &&
            model.variableStorage().variables().size() == 2 &&
            model.variableStorage().variables().stream().allMatch(variable -> variable.hasDefensibleLocation()),
            "computed parameter declaration/location was lost in the public type extractor");
    }

    private static void rejectionControls(ProgramDB program, Function function, Target target) throws Exception {
        Parameter parameter = function.getParameter(0);
        for (VariableStorage storage : new VariableStorage[] { null, VariableStorage.UNASSIGNED_STORAGE,
                DynamicVariableStorage.getUnassignedDynamicStorage(false) }) {
            omitted(GhidraVariableStorage.stableParameter(program, function, withStorage(parameter, storage),
                TargetRegisterMap.forTarget(target.map()), TaskMonitor.DUMMY), OmissionReason.UNASSIGNED);
        }
        for (VariableStorage storage : List.of(VariableStorage.BAD_STORAGE,
                new DynamicVariableStorage(program, true, parameter.getVariableStorage().getVarnodes()))) {
            omitted(GhidraVariableStorage.stableParameter(program, function, withStorage(parameter, storage),
                TargetRegisterMap.forTarget(target.map()), TaskMonitor.DUMMY), OmissionReason.UNSUPPORTED_STORAGE);
        }
        var marker = new CancelledException("dynamic parameter cancellation");
        var polls = new AtomicInteger();
        var monitor = new TaskMonitorAdapter(true) {
            @Override
            public void checkCancelled() throws CancelledException {
                polls.incrementAndGet();
                throw marker;
            }
        };
        try {
            GhidraVariableStorage.stableParameter(program, function, parameter,
                TargetRegisterMap.forTarget(target.map()), monitor);
            throw new AssertionError("computed register scan ignored cancellation");
        }
        catch (CancelledException expected) {
            require(expected == marker && polls.get() == 1, "cancellation identity or phase changed");
        }
    }

    private static Parameter withStorage(Parameter original, VariableStorage storage) {
        return (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
            new Class<?>[] { Parameter.class }, (proxy, method, arguments) -> {
                if (method.getName().equals("getVariableStorage")) {
                    return storage;
                }
                try {
                    return method.invoke(original, arguments);
                }
                catch (InvocationTargetException failure) {
                    throw failure.getCause();
                }
            });
    }

    private static void omitted(Storage storage, OmissionReason reason) {
        require(storage instanceof UnavailableStorage unavailable && unavailable.reason() == reason,
            "unexpected omission: " + storage + "; expected " + reason);
    }

    private static byte[] sha(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(bytes);
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}

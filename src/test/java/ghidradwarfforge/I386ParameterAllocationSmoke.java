package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.I386ParameterAllocation;

/** Exercise the real compiler model, including explicit storage and unsupported profile controls. */
public final class I386ParameterAllocationSmoke {
    private static int checks;
    private static long nextAddress = 0x1000;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var path = Files.createTempFile("forge-i386-allocation-", ".elf");
        try {
            var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:32:default"));
            for (String compiler : List.of("gcc", "windows")) {
                Object owner = new Object();
                var program = new ProgramDB("allocation", language,
                    language.getCompilerSpecByID(new CompilerSpecID(compiler)), owner);
                try {
                    int tx = program.startTransaction("fixtures");
                    try {
                        var manager = program.getDataTypeManager();
                        var extended = new LongDoubleDataType(manager);
                        var pair = new StructureDataType("Pair", 0, manager);
                        pair.add(new IntegerDataType(manager)); pair.add(new IntegerDataType(manager));
                        for (DataType returned : List.of(extended, new TypedefDataType(CategoryPath.ROOT, "ExtendedAlias", extended, manager),
                                new DoubleDataType(manager), new FloatDataType(manager), pair)) {
                            for (int count : List.of(0, 2, 9)) {
                                var parameters = new ArrayList<Parameter>();
                                for (int i = 0; i < count; i++) parameters.add(new ParameterImpl("arg" + i, extended, program));
                                var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(nextAddress);
                                nextAddress += 0x100;
                                var function = program.getFunctionManager().createFunction("allocation_" + nextAddress,
                                    entry, new AddressSet(entry, entry), SourceType.USER_DEFINED);
                                function.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(),
                                    new ReturnParameterImpl(returned, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                    true, SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
                                var callSignature = new FunctionDefinitionDataType("CallSignature", manager);
                                callSignature.setReturnType(returned);
                                callSignature.setArguments(parameters.stream().map(p ->
                                    new ParameterDefinitionImpl(p.getName(), p.getFormalDataType(), null)).toArray(ParameterDefinition[]::new));
                                callSignature.setCallingConvention("__cdecl");
                                String before = snapshot(function);
                                for (int osAbi : List.of(0, 3, 9)) {
                                    for (int flags : List.of(0, 1)) {
                                        Files.write(path, header(osAbi, flags));
                                        var policy = I386ParameterAllocation.forProgram(program, ElfImage.read(path),
                                            TaskMonitor.DUMMY, ignored -> { });
                                        var result = policy.resolve(function, TaskMonitor.DUMMY, ignored -> { });
                                        boolean correct = compiler.equals("gcc") && osAbi != 9 && flags == 0 &&
                                            (returned == extended || returned instanceof TypeDef);
                                        var call = policy.resolveSignature(callSignature, TaskMonitor.DUMMY);
                                        require((call != null) == correct, "call override profile selection");
                                        if (call != null) {
                                            require(call.returnStorage().getRegister().getName().equals("ST0") &&
                                                call.returnStorage().size() == 10, "call override result carrier");
                                            require(call.parameters().size() == count, "call override argument count");
                                            for (int i = 0; i < count; i++) require(call.parameters().get(i).getStackOffset() == 4 + 12 * i &&
                                                call.parameters().get(i).size() == 10, "call override argument carrier");
                                            require(callSignature.getReturnType().isEquivalent(returned), "call override changed formal return type");
                                        }
                                        require(result.omittedAutomaticParameters().size() == (correct ? 1 : 0), "hidden parameter classification");
                                        require(result.storage().size() == (correct ? count : 0), "parameter count");
                                        if (correct) {
                                            require(result.omittedAutomaticParameters().contains(0), "wrong automatic ordinal");
                                            for (int i = 0; i < count; i++) {
                                                var storage = result.storage().get(i + 1);
                                                require(storage.size() == 10 && storage.getStackOffset() == 4 + 12 * i,
                                                    "extended argument stride or offset");
                                            }
                                        }
                                        require(snapshot(function).equals(before), "saved program changed");
                                        require(result.equals(policy.resolve(function, TaskMonitor.DUMMY, ignored -> { })), "nondeterminism");
                                        if (policy != GhidraParameterAllocation.UNCHANGED) {
                                            var monitor = new TaskMonitorAdapter(true); monitor.cancel();
                                            try { policy.resolve(function, monitor, ignored -> { }); throw new AssertionError("ignored cancellation"); }
                                            catch (CancelledException expected) { checks++; }
                                        }
                                    }
                                }
                                Files.write(path, header(0, 0));
                                var policy = I386ParameterAllocation.forProgram(program, ElfImage.read(path), TaskMonitor.DUMMY, ignored -> { });
                                callSignature.setCallingConvention("__stdcall");
                                require(policy.resolveSignature(callSignature, TaskMonitor.DUMMY) == null, "nondefault override corrected");
                                callSignature.setCallingConvention("__cdecl");
                                callSignature.setVarArgs(true);
                                require((policy.resolveSignature(callSignature, TaskMonitor.DUMMY) != null) ==
                                    (compiler.equals("gcc") && (returned == extended || returned instanceof TypeDef)), "variadic call override");
                                function.setVarArgs(true);
                                var variadic = policy.resolve(function, TaskMonitor.DUMMY, ignored -> { });
                                require(variadic.omittedAutomaticParameters().size() ==
                                    (compiler.equals("gcc") && (returned == extended || returned instanceof TypeDef) ? 1 : 0),
                                    "named variadic allocation");
                                function.setCustomVariableStorage(true);
                                before = snapshot(function);
                                require(policy.resolve(function, TaskMonitor.DUMMY, ignored -> { }).storage().isEmpty(), "custom storage replaced");
                                require(policy.resolve(function, TaskMonitor.DUMMY, ignored -> { }).omittedAutomaticParameters().isEmpty(), "custom parameter omitted");
                                require(snapshot(function).equals(before), "custom signature changed");
                            }
                        }
                    }
                    finally { program.endTransaction(tx, true); }
                }
                finally { program.release(owner); }
            }
        }
        finally { Files.deleteIfExists(path); }
        System.out.println("i386-parameter-allocation-smoke=PASS checks=" + checks);
    }

    private static byte[] header(int osAbi, int flags) {
        var bytes = ByteBuffer.allocate(52).order(ByteOrder.LITTLE_ENDIAN);
        bytes.putInt(0, 0x464c457f);
        bytes.put(4, (byte)1); bytes.put(5, (byte)1); bytes.put(6, (byte)1); bytes.put(7, (byte)osAbi);
        bytes.putShort(16, (short)2); bytes.putShort(18, (short)3); bytes.putInt(20, 1);
        bytes.putInt(36, flags); bytes.putShort(40, (short)52); bytes.putShort(42, (short)32); bytes.putShort(46, (short)40);
        return bytes.array();
    }

    private static String snapshot(Function function) {
        return function.getPrototypeString(false, false) + ":" + function.getReturn().getVariableStorage() + ":" +
            Arrays.stream(function.getParameters()).map(p -> p.getName() + "=" + p.getVariableStorage()).toList();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

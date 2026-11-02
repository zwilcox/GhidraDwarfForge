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
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.Aarch64ParameterAllocation;

/** Actual pinned compiler models: exhaust registers, preserve explicit storage and bound corrections. */
public final class Aarch64ParameterAllocationSmoke {
    private static int checks;
    private static long nextAddress = 0x1000;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var path = Files.createTempFile("forge-allocation-", ".elf");
        try {
            for (String language : List.of("AARCH64:LE:64:v8A", "AARCH64:LE:64:AppleSilicon")) {
                for (String compiler : List.of("default", "windows")) {
                    if (language.contains("AppleSilicon") && compiler.equals("windows")) continue;
                    var lang = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(language));
                    Object owner = new Object();
                    var program = new ProgramDB("allocation", lang,
                        lang.getCompilerSpecByID(new CompilerSpecID(compiler)), owner);
                    try {
                        boolean baseline = language.endsWith(":v8A") && compiler.equals("default");
                        int tx = program.startTransaction("allocation fixtures");
                        try {
                            for (int count = 0; count <= 8; count++) {
                                var function = fixture(program, count, false);
                                String before = snapshot(function);
                                for (int osAbi : List.of(0, 3, 9)) {
                                    for (int flags : List.of(0, 1)) {
                                        Files.write(path, header(osAbi, flags));
                                        var diagnostics = new ArrayList<String>();
                                        var policy = Aarch64ParameterAllocation.forProgram(program, ElfImage.read(path),
                                            TaskMonitor.DUMMY, diagnostics::add);
                                        var changes = policy.corrections(function, TaskMonitor.DUMMY, diagnostics::add);
                                        boolean corrected = baseline && count == 7 && osAbi != 9 && flags == 0;
                                        require(changes.size() == (corrected ? 2 : 0), "incorrect profile or register boundary");
                                        if (corrected) {
                                            require(changes.get(7).isStackStorage() && changes.get(7).getStackOffset() == 0 &&
                                                changes.get(7).size() == 16, "aggregate not wholly on stack");
                                            require(changes.get(8).getStackOffset() == 16, "following parameter not shifted");
                                            require(diagnostics.size() == 2, "missing correction diagnostics");
                                        }
                                        require(snapshot(function).equals(before), "saved signature/storage changed");
                                        require(changes.equals(policy.corrections(function, TaskMonitor.DUMMY, ignored -> { })),
                                            "allocation nondeterministic");
                                        var monitor = new TaskMonitorAdapter(true);
                                        monitor.cancel();
                                        try {
                                            policy.corrections(function, monitor, ignored -> { });
                                            // The no-op policy performs no work; supported policies must cancel.
                                            require(policy == GhidraParameterAllocation.UNCHANGED, "allocation ignored cancellation");
                                        }
                                        catch (CancelledException expected) { checks++; }
                                    }
                                }
                            }
                            if (baseline) extended(program, path);
                        }
                        finally { program.endTransaction(tx, true); }
                    }
                    finally { program.release(owner); }
                }
            }
        }
        finally { Files.deleteIfExists(path); }
        System.out.println("aarch64-parameter-allocation-smoke=PASS checks=" + checks);
    }

    private static void extended(ProgramDB program, java.nio.file.Path path) throws Exception {
        Files.write(path, header(0, 0));
        var policy = Aarch64ParameterAllocation.forProgram(program, ElfImage.read(path), TaskMonitor.DUMMY, ignored -> { });
        var function = fixture(program, 7, true);
        var parameters = function.getParameters();
        String before = snapshot(function);
        var changes = policy.corrections(function, TaskMonitor.DUMMY, ignored -> { });
        require(changes.get(7).getStackOffset() == 0, "pair slot");
        require(changes.get(8).getStackOffset() == 16, "tail slot");
        require(changes.get(9).getStackOffset() == 32, "following 128-bit alignment");
        require(changes.get(10).getStackOffset() == 48 && changes.get(10).isForcedIndirect(), "indirect pointer shifted incorrectly");
        require(!changes.containsKey(11) && parameters[11].getVariableStorage().isRegisterStorage(), "independent FP allocation changed");
        require(snapshot(function).equals(before), "extended signature changed");
        function.setVarArgs(true);
        before = snapshot(function);
        require(changes.equals(policy.corrections(function, TaskMonitor.DUMMY, ignored -> { })),
            "named variadic parameters lost allocation correction");
        require(snapshot(function).equals(before), "variadic signature changed");
        function.setCustomVariableStorage(true);
        before = snapshot(function);
        require(policy.corrections(function, TaskMonitor.DUMMY, ignored -> { }).isEmpty(), "explicit analyst storage overridden");
        require(snapshot(function).equals(before), "custom signature changed");
        var unknown = fixture(program, 7, false);
        unknown.getParameter(7).setDataType(Undefined.getUndefinedDataType(12), SourceType.USER_DEFINED);
        before = snapshot(unknown);
        require(policy.corrections(unknown, TaskMonitor.DUMMY, ignored -> { }).isEmpty(), "unknown type acquired an invented ABI class");
        require(snapshot(unknown).equals(before), "unknown signature changed");
        var hidden = fixture(program, 7, false);
        var largeReturn = new StructureDataType("HiddenReturn", 0, program.getDataTypeManager());
        for (int index = 0; index < 3; index++) largeReturn.add(new LongLongDataType(program.getDataTypeManager()), "field" + index, null);
        hidden.setReturnType(largeReturn, SourceType.USER_DEFINED);
        before = snapshot(hidden);
        var hiddenChanges = policy.corrections(hidden, TaskMonitor.DUMMY, ignored -> { });
        require(hidden.getParameter(0).isAutoParameter() && hiddenChanges.size() == 2, "hidden return parameter changed");
        require(hiddenChanges.get(8).getStackOffset() == 0 && hiddenChanges.get(9).getStackOffset() == 16, "automatic parameter ordinal shift");
        require(snapshot(hidden).equals(before), "hidden-return signature changed");
        var monitor = new TaskMonitorAdapter(true);
        monitor.cancel();
        try {
            Aarch64ParameterAllocation.forProgram(program, ElfImage.read(path), monitor, ignored -> { });
            throw new AssertionError("factory ignored cancellation");
        }
        catch (CancelledException expected) { checks++; }
    }

    private static Function fixture(ProgramDB program, int count, boolean extended) throws Exception {
        var manager = program.getDataTypeManager();
        var word = new LongLongDataType(manager);
        var pair = new StructureDataType("AllocationPair" + nextAddress, 0, manager);
        pair.add(word, "first", null);
        pair.add(word, "second", null);
        var parameters = new ArrayList<Parameter>();
        for (int i = 0; i < count; i++) parameters.add(new ParameterImpl("arg" + i, word, program));
        parameters.add(new ParameterImpl("value", pair, program));
        parameters.add(new ParameterImpl("tail", word, program));
        if (extended) {
            var large = new StructureDataType("AllocationLarge" + nextAddress, 0, manager);
            for (int i = 0; i < 3; i++) large.add(word, "field" + i, null);
            parameters.add(new ParameterImpl("wide", new Integer16DataType(manager), program));
            parameters.add(new ParameterImpl("indirect", large, program));
            parameters.add(new ParameterImpl("floating", new DoubleDataType(manager), program));
        }
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(nextAddress);
        nextAddress += 0x100;
        var function = program.getFunctionManager().createFunction("allocation_" + nextAddress, entry,
            new AddressSet(entry, entry), SourceType.USER_DEFINED);
        function.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(),
            new ReturnParameterImpl(word, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            true, SourceType.USER_DEFINED, parameters.toArray(Parameter[]::new));
        return function;
    }

    private static String snapshot(Function function) {
        return function.getPrototypeString(false, false) + ":" + function.getReturn().getVariableStorage() + ":" +
            Arrays.stream(function.getParameters()).map(p -> p.getName() + "=" + p.getVariableStorage()).toList();
    }

    private static byte[] header(int osAbi, int flags) {
        var out = ByteBuffer.allocate(64).order(ByteOrder.LITTLE_ENDIAN);
        out.putInt(0, 0x464c457f);
        out.put(4, (byte)2); out.put(5, (byte)1); out.put(6, (byte)1); out.put(7, (byte)osAbi);
        out.putShort(16, (short)2); out.putShort(18, (short)183); out.putInt(20, 1);
        out.putInt(48, flags); out.putShort(52, (short)64); out.putShort(54, (short)56); out.putShort(58, (short)64);
        return out.array();
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

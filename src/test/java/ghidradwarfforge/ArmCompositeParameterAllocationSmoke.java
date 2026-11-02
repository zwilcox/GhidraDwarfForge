package ghidradwarfforge;

import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.TargetParameterAllocation;

/** Independently lays object bytes into allocated words, including short final words. */
public final class ArmCompositeParameterAllocationSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean big : new boolean[] {false, true}) {
            for (String convention : List.of("__stdcall", "__stdcall_softfp")) {
                for (int leading = 0; leading <= 5; leading++) {
                    for (int size : new int[] {1, 2, 3, 4, 5, 7, 8, 9, 13, 17, 19, 20}) {
                        check(big, convention, leading, size);
                    }
                }
            }
        }
        System.out.println("arm-composite-parameter-allocation=PASS checks=" + checks);
    }

    private static void check(boolean big, String convention, int leading, int size) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            big ? "ARM:LEBE:32:v8LEInstruction" : "ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("aggregate", language, language.getDefaultCompilerSpec(), owner);
        var file = Files.createTempFile("arm-composite", ".elf");
        try {
            var header = ByteBuffer.allocate(52).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
            header.put(new byte[] {0x7f, 'E', 'L', 'F', 1, (byte) (big ? 2 : 1), 1});
            header.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
            header.putInt(36, big ? 0x05800400 : 0x05000400).putShort(40, (short) 52);
            Files.write(file, header.array());
            var policy = TargetParameterAllocation.forProgram(program, ElfImage.read(file), TaskMonitor.DUMMY,
                message -> { throw new AssertionError(message); });
            int transaction = program.startTransaction("aggregate allocation");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var function = program.getFunctionManager().createFunction("aggregate", entry,
                    new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
                var type = new StructureDataType("Bytes", 0, program.getDataTypeManager());
                type.add(new ArrayDataType(ByteDataType.dataType, size, 1, program.getDataTypeManager()), "bytes", null);
                var parameters = new ArrayList<ParameterImpl>();
                for (int index = 0; index < leading; index++) {
                    parameters.add(new ParameterImpl("leading" + index, IntegerDataType.dataType, program));
                }
                parameters.add(new ParameterImpl("value", type, program));
                parameters.add(new ParameterImpl("tail", IntegerDataType.dataType, program));
                function.updateFunction(convention, new ReturnParameterImpl(VoidDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    parameters.toArray(ParameterImpl[]::new));
                var parameter = function.getParameter(leading);
                var before = parameter.getVariableStorage();
                var corrections = policy.corrections(function, TaskMonitor.DUMMY, ignored -> {});
                var storage = corrections.getOrDefault(leading, before);
                String context = big + "/" + convention + "/" + leading + "/" + size + " original=" + before + " corrected=" + storage;
                require(corrections.keySet().stream().allMatch(ordinal -> ordinal == leading), "unrelated parameter changed " + context);
                require(parameter.getVariableStorage().equals(before) && !function.hasCustomVariableStorage(), "program storage changed");
                List<Varnode> actual = List.of(storage.getVarnodes());
                if (!big) actual = actual.reversed();
                var expected = new ArrayList<Varnode>();
                int remaining = size;
                for (int register = leading; register < 4 && remaining > 0; register++) {
                    int width = Math.min(4, remaining);
                    expected.add(new Varnode(program.getRegister("r" + register).getAddress().add(big ? 4 - width : 0), width));
                    remaining -= width;
                }
                if (remaining > 0) expected.add(new Varnode(program.getAddressFactory().getStackSpace()
                    .getAddress(Math.max(0, leading - 4) * 4L), remaining));
                require(actual.equals(expected), "memory-order allocation differs " + context + " actual=" + actual + " expected=" + expected);
                function.setCustomVariableStorage(true);
                require(policy.corrections(function, TaskMonitor.DUMMY, ignored -> {}).isEmpty(), "analyst storage rewritten");
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); Files.delete(file); }
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }
}

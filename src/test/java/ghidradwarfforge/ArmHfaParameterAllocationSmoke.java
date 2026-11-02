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
import ghidra.program.model.data.*;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.ArmHfaParameterAllocation;

/** Actual dynamic HFA joins, exhausted banks, analyst storage and rejected type shapes. */
public final class ArmHfaParameterAllocationSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean big : new boolean[] {false, true}) {
            for (int width : new int[] {4, 8}) {
                for (int count : new int[] {2, 3, 4}) {
                    for (int leading : new int[] {0, 1, 8}) {
                        for (String shape : List.of("flat", "array", "nested", "alias")) {
                            check(big, width, count, leading, shape);
                        }
                    }
                }
                for (String shape : List.of("mixed", "padded", "union", "custom", "base", "variadic")) {
                    check(big, width, 2, 0, shape);
                }
            }
        }
        System.out.println("arm-hfa-parameter-allocation=PASS checks=" + checks);
    }

    private static void check(boolean big, int width, int count, int leading, String shape) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            big ? "ARM:LEBE:32:v8LEInstruction" : "ARM:LE:32:v8"));
        Object owner = new Object();
        var program = new ProgramDB("HFA", language, language.getDefaultCompilerSpec(), owner);
        var file = Files.createTempFile("arm-hfa-profile", ".elf");
        try {
            var header = ByteBuffer.allocate(52).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
            header.put(new byte[] {0x7f, 'E', 'L', 'F', 1, (byte) (big ? 2 : 1), 1});
            header.putShort(16, (short) 2).putShort(18, (short) 40).putInt(20, 1);
            header.putInt(36, big ? 0x05800400 : 0x05000400).putShort(40, (short) 52);
            Files.write(file, header.array());
            var policy = ArmHfaParameterAllocation.forProgram(program, ElfImage.read(file), TaskMonitor.DUMMY, ignored -> {});
            int tx = program.startTransaction("fixture");
            try {
                var entry = language.getDefaultSpace().getAddress(0x1000);
                var function = program.getFunctionManager().createFunction("hfa", entry,
                    new AddressSet(entry, entry.add(3)), SourceType.USER_DEFINED);
                DataType element = width == 4 ? FloatDataType.dataType : DoubleDataType.dataType;
                var structure = new StructureDataType("Hfa", 0, program.getDataTypeManager());
                for (int index = 0; index < count; index++) {
                    if (shape.equals("padded") && index == 1) structure.add(Undefined4DataType.dataType);
                    structure.add(shape.equals("mixed") && index == 1 ? IntegerDataType.dataType : element,
                        "field" + index, null);
                }
                DataType type = structure;
                if (shape.equals("array")) type = new ArrayDataType(element, count, width, program.getDataTypeManager());
                if (shape.equals("nested")) {
                    var outer = new StructureDataType("Outer", 0, program.getDataTypeManager());
                    outer.add(structure, "inner", null);
                    type = outer;
                }
                if (shape.equals("alias")) type = new TypedefDataType(CategoryPath.ROOT, "Alias", structure, program.getDataTypeManager());
                if (shape.equals("union")) {
                    var union = new UnionDataType(CategoryPath.ROOT, "Union", program.getDataTypeManager());
                    union.add(structure);
                    type = union;
                }
                var parameters = new ArrayList<ParameterImpl>();
                for (int index = 0; index < leading; index++) {
                    parameters.add(new ParameterImpl("leading" + index, DoubleDataType.dataType, program));
                }
                parameters.add(new ParameterImpl("value", type, program));
                function.updateFunction(shape.equals("base") ? "__stdcall_softfp" : "__stdcall",
                    new ReturnParameterImpl(VoidDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
                    parameters.toArray(ParameterImpl[]::new));
                if (shape.equals("custom")) function.setCustomVariableStorage(true);
                if (shape.equals("variadic")) function.setVarArgs(true);
                var parameter = function.getParameter(leading);
                String before = parameter.getVariableStorage().toString();
                var actual = policy.corrections(function, TaskMonitor.DUMMY, ignored -> {});
                boolean positive = leading < 8 && List.of("flat", "array", "nested", "alias").contains(shape);
                if (positive) {
                    var storage = actual.getOrDefault(leading, parameter.getVariableStorage());
                    require(storage.size() == width * count && storage.getVarnodeCount() == count,
                        "HFA member representation " + big + "/" + width + "/" + count + "/" + leading + "/" + shape + " " + storage);
                    var nodes = storage.getVarnodes();
                    for (int member = 0; member < count; member++) {
                        int ordinal = big ? member : count - member - 1;
                        String name = (width == 4 ? "s" : "d") + (leading * (8 / width) + member);
                        require(program.getRegister(nodes[ordinal]) == program.getRegister(name), "member order " + name);
                    }
                }
                else require(actual.isEmpty(), "rejected profile changed " + shape);
                require(before.equals(parameter.getVariableStorage().toString()), "saved parameter mutated");
                var cancelled = new TaskMonitorAdapter(true);
                cancelled.cancel();
                try {
                    policy.corrections(function, cancelled, ignored -> {});
                    throw new AssertionError("ignored cancellation");
                }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(tx, false); }
        }
        finally { program.release(owner); Files.deleteIfExists(file); }
    }

    private static void require(boolean value, String message) {
        if (!value) throw new AssertionError(message);
        checks++;
    }
}

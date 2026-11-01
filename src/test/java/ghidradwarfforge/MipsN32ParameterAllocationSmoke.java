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
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.elf.ElfImage;
import ghidradwarfforge.targets.MipsWideParameterAllocation;

/** Real N32 prototype: positional floats, composite splits, hidden pointers and immutable signatures. */
public final class MipsN32ParameterAllocationSmoke {
    private static int checks;
    private static long nextAddress = 0x1000;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        var path = Files.createTempFile("forge-n32-allocation-", ".elf");
        try {
            for (boolean big : List.of(true, false)) {
                for (String compiler : List.of("n32", "default", "o32")) {
                    var language = DefaultLanguageService.getLanguageService().getLanguage(
                        new LanguageID("MIPS:" + (big ? "BE" : "LE") + ":64:64-32addr"));
                    Object owner = new Object();
                    var program = new ProgramDB("allocation", language,
                        language.getCompilerSpecByID(new CompilerSpecID(compiler)), owner);
                    int transaction = program.startTransaction("fixtures");
                    try {
                        var manager = program.getDataTypeManager();
                        var word = new LongLongDataType(manager);
                        var real = new DoubleDataType(manager);
                        var scalar = new FloatDataType(manager);
                        var integer = new IntegerDataType(manager);
                        var pair = new StructureDataType("Pair", 0, manager);
                        pair.add(word, "first", null);
                        pair.add(word, "second", null);
                        var mixed = function(program, word, word, real, integer, scalar, pair, word, real, word, integer);
                        String before = snapshot(mixed);
                        for (boolean matchingEndian : List.of(true, false)) {
                            for (int flags : List.of(0x80000025, 0x70001005)) {
                                for (int fpr : List.of(2, 1)) {
                                    Files.write(path, image(matchingEndian ? big : !big, flags, fpr));
                                    var diagnostics = new ArrayList<String>();
                                    var policy = MipsWideParameterAllocation.forProgram(program, ElfImage.read(path),
                                        TaskMonitor.DUMMY, diagnostics::add);
                                    var changes = policy.corrections(mixed, TaskMonitor.DUMMY, diagnostics::add);
                                    boolean accepted = compiler.equals("n32") && matchingEndian && flags == 0x80000025 && fpr == 2;
                                    require(changes.size() == (accepted ? 8 : 0), "profile classification");
                                    if (accepted) {
                                        require(changes.get(1).toString().equals("f13:8"), "positional double");
                                        require(changes.get(2).toString().equals("a2_lo:4"), "integer slot after double");
                                        require(changes.get(3).toString().equals("f15:4"), "positional float");
                                        require(changes.get(4).toString().equals(big ? "t0:8,t1:8" : "t1:8,t0:8"), "aggregate order");
                                        require(changes.get(5).toString().equals("t2:8"), "following word");
                                        require(changes.get(6).toString().equals("f19:8"), "last floating slot");
                                        require(changes.get(7).getStackOffset() == 0, "first stack slot");
                                        require(changes.get(8).getStackOffset() == (big ? 12 : 8), "narrow stack justification");
                                    }
                                    require(before.equals(snapshot(mixed)), "saved signature changed");
                                    require(changes.equals(policy.corrections(mixed, TaskMonitor.DUMMY, ignored -> { })), "nondeterminism");
                                }
                            }
                        }
                        if (compiler.equals("n32")) {
                            Files.write(path, image(big, 0x80000025, 2));
                            var policy = MipsWideParameterAllocation.forProgram(program, ElfImage.read(path), TaskMonitor.DUMMY, ignored -> { });
                            var pairFunction = function(program, pair, pair);
                            var changed = policy.corrections(pairFunction, TaskMonitor.DUMMY, ignored -> { });
                            require(changed.get(0).toString().equals(big ? "a0:8,a1:8" : "a1:8,a0:8"), "pair input");
                            var large = new StructureDataType("Large", 0, manager);
                            for (int index = 0; index < 3; index++) large.add(word, "f" + index, null);
                            var hidden = function(program, large, large);
                            changed = policy.corrections(hidden, TaskMonitor.DUMMY, ignored -> { });
                            require(changed.size() == 1 && changed.get(1).size() == 24, "hidden pointer count");
                            require(hidden.getParameter(0).isAutoParameter() && hidden.getParameter(0).getLength() == 4,
                                "N32 hidden pointer width");
                            for (int count = 0; count <= 9; count++) {
                                var inputs = new ArrayList<DataType>();
                                for (int index = 0; index < count; index++) inputs.add(word);
                                inputs.add(pair);
                                inputs.add(integer);
                                var split = function(program, word, inputs.toArray(DataType[]::new));
                                var corrections = policy.corrections(split, TaskMonitor.DUMMY, ignored -> { });
                                if (count == 7) {
                                    require(corrections.get(count).toString().equals(big ? "t3:8,Stack[0x0]:8" : "Stack[0x0]:8,t3:8"),
                                        "aggregate must split at the eighth argument slot");
                                    require(corrections.get(count + 1).getStackOffset() == (big ? 12 : 8), "tail after split");
                                }
                                require(corrections.values().stream().allMatch(storage -> storage.isValid()), "invalid correction");
                            }
                            mixed.setVarArgs(true);
                            require(policy.corrections(mixed, TaskMonitor.DUMMY, ignored -> { }).size() == 8, "named variadic allocation");
                            mixed.setCustomVariableStorage(true);
                            before = snapshot(mixed);
                            require(policy.corrections(mixed, TaskMonitor.DUMMY, ignored -> { }).isEmpty(), "custom storage overwritten");
                            require(before.equals(snapshot(mixed)), "custom signature changed");
                            var cancelled = new TaskMonitorAdapter(true);
                            cancelled.cancel();
                            try {
                                policy.corrections(pairFunction, cancelled, ignored -> { });
                                throw new AssertionError("cancellation ignored");
                            }
                            catch (CancelledException expected) { checks++; }
                        }
                    }
                    finally {
                        program.endTransaction(transaction, true);
                        program.release(owner);
                    }
                }
            }
        }
        finally { Files.deleteIfExists(path); }
        checkLayouts();
        System.out.println("mips-n32-parameter-allocation-smoke=PASS checks=" + checks);
    }

    private static void checkLayouts() throws Exception {
        var path = Files.createTempFile("forge-wide-layout-", ".elf");
        try {
            for (boolean n64 : List.of(false, true)) {
                for (boolean big : List.of(false, true)) {
                    var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
                        "MIPS:" + (big ? "BE" : "LE") + (n64 ? ":64:default" : ":64:64-32addr")));
                    var owner = new Object();
                    var program = new ProgramDB("wide-layout", language,
                        language.getCompilerSpecByID(new CompilerSpecID(n64 ? "default" : "n32")), owner);
                    int transaction = program.startTransaction("owned layouts");
                    try {
                        Files.write(path, n64 ? wideImage(big) : image(big, 0x80000025, 2));
                        var policy = MipsWideParameterAllocation.forProgram(program, ElfImage.read(path),
                            TaskMonitor.DUMMY, ignored -> { });
                        var manager = program.getDataTypeManager();
                        var word = new LongLongDataType(manager);
                        var real = new DoubleDataType(manager);
                        var array = new StructureDataType("ArrayDoubles", 0, manager);
                        array.add(new ghidra.program.model.data.ArrayDataType(real, 2, 8, manager), "elements", null);
                        var choice = new ghidra.program.model.data.UnionDataType(
                            ghidra.program.model.data.CategoryPath.ROOT, "DoubleChoice", manager);
                        choice.add(real, "value", null);
                        var union = new StructureDataType("UnionDouble", 0, manager);
                        union.add(choice, "first", null); union.add(real, "second", null);
                        var box = new StructureDataType("DoubleBox", 0, manager);
                        box.add(real, "value", null);
                        var nested = new StructureDataType("NestedDouble", 0, manager);
                        nested.add(box, "first", null); nested.add(real, "second", null);
                        for (var type : List.of(array, union, nested)) {
                            var function = function(program, word, type, word);
                            String before = snapshot(function);
                            var changes = policy.corrections(function, TaskMonitor.DUMMY, ignored -> { });
                            var storage = changes.getOrDefault(0, function.getParameter(0).getVariableStorage());
                            String first = "a0:8", second = type == array ? "a1:8" : "f13:8";
                            require(storage.toString().equals(big ? first + "," + second : second + "," + first),
                                "wrong direct-field classification: " + type.getName() + " " + storage);
                            require(changes.getOrDefault(1, function.getParameter(1).getVariableStorage()).toString().equals("a2:8"),
                                "tail slot after aggregate");
                            require(before.equals(snapshot(function)), "classification mutated original type/storage");
                        }
                        for (int count : List.of(1, 3, 7, 9)) {
                            var inputs = new ArrayList<DataType>();
                            for (int i = 0; i < count; i++) inputs.add(word);
                            inputs.add(new ghidra.program.model.data.Integer16DataType(manager));
                            inputs.add(word);
                            var function = function(program, word, inputs.toArray(DataType[]::new));
                            String before = snapshot(function);
                            var changes = policy.corrections(function, TaskMonitor.DUMMY, ignored -> { });
                            var value = changes.getOrDefault(count, function.getParameter(count).getVariableStorage());
                            var tail = changes.getOrDefault(count + 1, function.getParameter(count + 1).getVariableStorage());
                            if (count == 1 || count == 3) {
                                String first = count == 1 ? "a2:8" : "t0:8";
                                String second = count == 1 ? "a3:8" : "t1:8";
                                require(value.toString().equals(big ? first + "," + second : second + "," + first), "aligned integer register pair: " + value);
                                require(tail.toString().equals(count == 1 ? "t0:8" : "t2:8"), "tail after aligned integer");
                            }
                            else {
                                require(value.isStackStorage() && value.getStackOffset() == (count == 7 ? 0 : 16),
                                    "aligned integer stack offset: " + value);
                                require(tail.isStackStorage() && tail.getStackOffset() == (count == 7 ? 16 : 32),
                                    "tail after aligned stack integer: " + tail);
                            }
                            require(before.equals(snapshot(function)), "alignment mutated saved signature");
                        }
                    }
                    finally {
                        program.endTransaction(transaction, true);
                        program.release(owner);
                    }
                }
            }
        }
        finally { Files.deleteIfExists(path); }
    }

    private static byte[] wideImage(boolean big) {
        var bytes = ByteBuffer.allocate(152).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        bytes.put(new byte[] { 0x7f, 'E', 'L', 'F', 2, (byte) (big ? 2 : 1), 1, 0, 1 });
        bytes.position(16);
        bytes.putShort((short) 2).putShort((short) 8).putInt(1).putLong(0).putLong(64).putLong(0).putInt(0x80000005);
        bytes.putShort((short) 64).putShort((short) 56).putShort((short) 1);
        bytes.position(64);
        bytes.putInt(0x70000003).putInt(4).putLong(128).putLong(0).putLong(0).putLong(24).putLong(24).putLong(8);
        bytes.position(128);
        bytes.putShort((short) 0).put((byte) 64).put((byte) 2).put((byte) 2).put((byte) 2).put((byte) 0).put((byte) 1);
        bytes.putInt(0).putInt(0).putInt(1).putInt(0);
        return bytes.array();
    }

    private static Function function(ProgramDB program, DataType result, DataType... inputs) throws Exception {
        var address = program.getAddressFactory().getDefaultAddressSpace().getAddress(nextAddress);
        nextAddress += 0x100;
        var function = program.getFunctionManager().createFunction("fixture_" + nextAddress, address,
            new AddressSet(address, address.add(15)), SourceType.USER_DEFINED);
        function.setReturnType(result, SourceType.USER_DEFINED);
        var parameters = new ArrayList<Parameter>();
        for (int index = 0; index < inputs.length; index++) parameters.add(new ParameterImpl("arg" + index,
            inputs[index], program, SourceType.USER_DEFINED));
        function.updateFunction(program.getCompilerSpec().getDefaultCallingConvention().getName(), function.getReturn(),
            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
            parameters.toArray(Parameter[]::new));
        return function;
    }

    private static String snapshot(Function function) {
        return function.getPrototypeString(false, false) + " " + function.getReturn() + " " +
            Arrays.toString(function.getParameters()) + " " + function.hasCustomVariableStorage();
    }

    private static byte[] image(boolean big, int flags, int fpr) {
        var bytes = ByteBuffer.allocate(152).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
        bytes.put(new byte[] { 0x7f, 'E', 'L', 'F', 1, (byte) (big ? 2 : 1), 1, 0, 1 });
        bytes.position(16);
        bytes.putShort((short) 2).putShort((short) 8).putInt(1).putInt(0).putInt(52).putInt(0).putInt(flags);
        bytes.putShort((short) 52).putShort((short) 32).putShort((short) 1);
        bytes.position(52);
        bytes.putInt(0x70000003).putInt(128).putInt(0).putInt(0).putInt(24).putInt(24).putInt(4).putInt(8);
        bytes.position(128);
        bytes.putShort((short) 0).put((byte) 64).put((byte) 2).put((byte) 2).put((byte) fpr).put((byte) 0).put((byte) 1);
        bytes.putInt(0).putInt(0).putInt(1).putInt(0);
        return bytes.array();
    }

    private static void require(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
}

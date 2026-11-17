package ghidradwarfforge;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.CompositeStorage;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Real decoded holes and saved parameter provenance, with isolated contradictory API claims. */
final class CompositeValueFlowBoundarySmoke {
    private static int checks;

    private record Target(String language, String map, int width, String first, String second,
            int firstDwarf, int secondDwarf, String jump, String tail) { }

    static void run() throws Exception {
        for (var target : List.of(
                new Target("x86:LE:64:default", "x86_64", 8, "RDI", "RSI", 5, 4, "eb0e", "90ebfd"),
                new Target("AARCH64:LE:64:v8A", "aarch64", 8, "x0", "x1", 0, 1, "04000014", "1f2003d5ffffff17"),
                new Target("ARM:LE:32:v8", "arm", 4, "r0", "r1", 0, 1, "020000ea", "0000a0e1fdffffea"),
                new Target("ARM:BE:32:v8", "arm", 4, "r0", "r1", 0, 1, "ea000002", "e1a00000eafffffd"))) {
            exercise(target);
        }
        System.out.println("composite-value-boundaries=PASS profiles=4 checks=" + checks);
    }

    private static void exercise(Target target) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(target.language()));
        Object owner = new Object();
        var program = new ProgramDB("composite-holes", language, language.getDefaultCompilerSpec(), owner);
        var foreign = new ProgramDB("foreign-composite", language, language.getDefaultCompilerSpec(), owner);
        try {
            int transaction = program.startTransaction("decoded composite body with a hole");
            try {
                byte[] jump = HexFormat.of().parseHex(target.jump());
                byte[] tail = HexFormat.of().parseHex(target.tail());
                byte[] bytes = new byte[16 + tail.length];
                System.arraycopy(jump, 0, bytes, 0, jump.length);
                System.arraycopy(tail, 0, bytes, 16, tail.length);
                var start = language.getDefaultSpace().getAddress(0x1000);
                var body = new AddressSet(start, start.add(jump.length - 1));
                body.add(start.add(16), start.add(bytes.length - 1));
                var block = program.getMemory().createInitializedBlock("code", start, bytes.length,
                    (byte) 0, TaskMonitor.DUMMY, false);
                block.setExecute(true);
                program.getMemory().setBytes(start, bytes);
                require(new DisassembleCommand(start, body, true).applyTo(program, TaskMonitor.DUMMY), "decode");
                var function = program.getFunctionManager().createFunction("pair", start, body, SourceType.USER_DEFINED);
                var type = new StructureDataType("Pair", 0, program.getDataTypeManager());
                type.add(target.width() == 4 ? IntegerDataType.dataType : LongLongDataType.dataType, "first", null);
                type.add(target.width() == 4 ? IntegerDataType.dataType : LongLongDataType.dataType, "second", null);
                var first = new Varnode(program.getRegister(target.first()).getAddress(), target.width());
                var second = new Varnode(program.getRegister(target.second()).getAddress(), target.width());
                var storage = new VariableStorage(program, language.isBigEndian() ? first : second,
                    language.isBigEndian() ? second : first);
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", type, storage, program, SourceType.USER_DEFINED));
                var parameter = function.getParameter(0);
                var registers = TargetRegisterMap.forTarget(target.map());
                var expected = CompositeValueFlow.prove(program, function, parameter, registers, TaskMonitor.DUMMY);
                metadata(program, function, parameter, registers, expected);
                require(expected.size() == 2, "discontiguous body must retain two intervals: " + expected);
                require(expected.get(0).start() == 0x1000 && expected.get(0).end() == 0x1000 + jump.length &&
                    expected.get(1).start() == 0x1010 && expected.get(1).end() == 0x1000 + bytes.length,
                    "composite proof filled a body hole: " + expected);
                require(expected.get(0).storage().equals(expected.get(1).storage()), "unchanged pieces differ across hole");
                for (var interval : expected) {
                    require(interval.storage() instanceof CompositeStorage, "complete composite unavailable");
                    var value = (CompositeStorage) interval.storage();
                    require(value.totalBitSize() == target.width() * 16L && value.pieces().size() == 2, "piece widths");
                    require(value.pieces().get(0).storage() instanceof RegisterStorage a && a.register().dwarfNumber() == target.firstDwarf() &&
                        value.pieces().get(1).storage() instanceof RegisterStorage b && b.register().dwarfNumber() == target.secondDwarf(),
                        "memory piece order changed: " + target.language());
                }
                require(CompositeValueFlow.prove(foreign, function, parameter, registers, TaskMonitor.DUMMY).isEmpty(),
                    "foreign program accepted");
                var other = program.getFunctionManager().createFunction("other", start.add(0x100),
                    new AddressSet(start.add(0x100)), SourceType.USER_DEFINED);
                require(CompositeValueFlow.prove(program, other, parameter, registers, TaskMonitor.DUMMY).isEmpty(),
                    "parameter from another function accepted");
                var unknown = new TargetRegisterMap("unknown", "explicit unmapped test target", Map.of("no_such_register", 99));
                require(CompositeValueFlow.prove(program, function, parameter, unknown, TaskMonitor.DUMMY).isEmpty(),
                    "unmapped pieces accepted");
                var pointer = new Varnode(program.getCompilerSpec().getStackPointer().getAddress(), target.width());
                for (VariableStorage rejected : new VariableStorage[] {null, VariableStorage.BAD_STORAGE,
                        VariableStorage.UNASSIGNED_STORAGE, new VariableStorage(foreign, storage.getVarnodes()),
                        new VariableStorage(program, first),
                        new VariableStorage(program, new Varnode(start.add(0x200), target.width() * 2)),
                        new VariableStorage(program, second, pointer)}) {
                    require(CompositeValueFlow.prove(program, function, parameter, rejected, registers, TaskMonitor.DUMMY).isEmpty(),
                        "unsupported composite storage accepted: " + rejected);
                }
                var counter = new TaskMonitorAdapter(true) {
                    private int count;
                    @Override public void checkCancelled() throws CancelledException { count++; super.checkCancelled(); }
                };
                require(CompositeValueFlow.prove(program, function, parameter, registers, counter).equals(expected), "repeat differs");
                int cancellationPoints = counter.count;
                require(cancellationPoints > 20, "fixture did not exercise composite proof");
                // Visit every cancellation checkpoint from the successful proof, including
                // intersection and coalescing; repeat after each refusal to detect leaked state.
                for (int checkpoint = 1; checkpoint <= cancellationPoints; checkpoint++) {
                    final int stop = checkpoint;
                    var monitor = new TaskMonitorAdapter(true) {
                        private int count;
                        @Override public void checkCancelled() throws CancelledException {
                            if (++count == stop) cancel();
                            super.checkCancelled();
                        }
                    };
                    try {
                        CompositeValueFlow.prove(program, function, parameter, registers, monitor);
                        throw new AssertionError("composite proof ignored cancellation at " + stop);
                    }
                    catch (CancelledException correct) { checks++; }
                    require(CompositeValueFlow.prove(program, function, parameter, registers, TaskMonitor.DUMMY).equals(expected),
                        "cancelled composite proof poisoned retry");
                }
                byte[] after = new byte[bytes.length];
                program.getMemory().getBytes(start, after);
                require(Arrays.equals(bytes, after) && function.getBody().equals(body) &&
                    function.getParameter(0).getVariableStorage().equals(storage), "proof changed analyzed input");
                System.out.println("composite-hole-profile=PASS " + target.language() + " cancellationPoints=" + cancellationPoints);
            }
            finally { program.endTransaction(transaction, false); }
        }
        finally {
            foreign.flushEvents();
            program.flushEvents();
            foreign.release(owner);
            program.release(owner);
        }
    }

    /** Keep the decoded program real while varying one saved API claim at a time. */
    private static void metadata(ProgramDB program, Function original, Parameter saved,
            TargetRegisterMap registers, List<GhidraVariableStorage.StorageInterval> expected) throws Exception {
        long modification = program.getModificationNumber();
        var originalStorage = saved.getVariableStorage();
        var originalType = saved.getFormalDataType();
        for (String defect : List.of("transparent", "foreign-owner", "negative-ordinal", "detached",
                "late-first-use", "zero-width", "negative-width", "short-width", "missing-type", "short-type")) {
            Function[] function = new Function[1];
            Parameter[] parameter = new Parameter[1];
            function[0] = (Function) Proxy.newProxyInstance(Function.class.getClassLoader(),
                new Class<?>[] { Function.class }, (proxy, method, args) -> {
                    if (method.getName().equals("getParameter")) {
                        return defect.equals("detached") ? saved : parameter[0];
                    }
                    if (method.getName().equals("getParameters")) return new Parameter[] { parameter[0] };
                    try { return method.invoke(original, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            parameter[0] = (Parameter) Proxy.newProxyInstance(Parameter.class.getClassLoader(),
                new Class<?>[] { Parameter.class }, (proxy, method, args) -> {
                    String name = method.getName();
                    if (name.equals("getFunction")) return defect.equals("foreign-owner") ? original : function[0];
                    if (name.equals("getOrdinal") && defect.equals("negative-ordinal")) return -1;
                    if (name.equals("getFirstUseOffset") && defect.equals("late-first-use")) return 1;
                    if (name.equals("getLength")) {
                        if (defect.equals("zero-width")) return 0;
                        if (defect.equals("negative-width")) return -1;
                        if (defect.equals("short-width")) return saved.getLength() - 1;
                    }
                    if (name.equals("getFormalDataType")) {
                        if (defect.equals("missing-type")) return null;
                        if (defect.equals("short-type")) return IntegerDataType.dataType;
                    }
                    try { return method.invoke(saved, args); }
                    catch (InvocationTargetException failure) { throw failure.getCause(); }
                });
            var result = CompositeValueFlow.prove(program, function[0], parameter[0], registers, TaskMonitor.DUMMY);
            require(defect.equals("transparent") ? result.equals(expected) : result.isEmpty(),
                "unproven composite metadata acquired a location: " + defect + " " + result);
            require(CompositeValueFlow.prove(program, original, saved, registers, TaskMonitor.DUMMY).equals(expected),
                "metadata refusal changed subsequent proof: " + defect);
            require(program.getModificationNumber() == modification && original.getParameter(0) == saved &&
                saved.getVariableStorage().equals(originalStorage) && saved.getFormalDataType().equals(originalType),
                "metadata inspection changed the saved program: " + defect);
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
        checks++;
    }
}

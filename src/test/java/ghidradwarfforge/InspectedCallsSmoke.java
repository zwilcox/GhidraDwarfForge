package ghidradwarfforge;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.GhidraApplicationLayout;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidradwarfforge.locations.TargetRegisterMap;
import ghidradwarfforge.locations.VariableStorageModel.RegisterStorage;

/** Decoded call graphs and actual ABI registers, including hostile nested effects. */
public final class InspectedCallsSmoke {
    private static int checks;

    public static void main(String[] args) throws Exception {
        Application.initializeApplication(new GhidraApplicationLayout(new File(args[0])),
            new HeadlessGhidraApplicationConfiguration());
        for (boolean x86 : new boolean[] { true, false }) {
            for (int bytes : new int[] { 4, 8 }) {
                for (String shape : List.of("branch", "loop", "split", "nested", "recursive",
                        "clobber", "nested-clobber", "undecoded", "alternate", "indirect", "unknown-abi",
                        "caller-branch", "caller-loop", "caller-split", "stack-retirement")) {
                    check(x86, bytes, shape);
                }
            }
        }
        System.out.println("inspected-calls-smoke=PASS checks=" + checks);
    }

    private static void check(boolean x86, int bytes, String shape) throws Exception {
        var language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(
            x86 ? "x86:LE:64:default" : "AARCH64:LE:64:v8A"));
        Object owner = new Object();
        var program = new ProgramDB("inspected-calls", language, language.getDefaultCompilerSpec(), owner);
        String context = (x86 ? "x86" : "arm") + "/" + bytes + "/" + shape;
        try {
            int transaction = program.startTransaction("machine call graph");
            try {
                String nop = x86 ? "90" : "1f2003d5";
                String ret = x86 ? "c3" : "c0035fd6";
                String compare = x86 ? "85f6" : "3f000071";
                String decrement = x86 ? "83ee01" : "21040071";
                String killFirst = x86 ? "4831db" : "f3031faa";
                var caller = new Code(x86, 0x1000);
                caller.emit(x86 ? (bytes == 4 ? "89fb" : "4889fb") : (bytes == 4 ? "f303002a" : "f30300aa"));
                caller.emit(x86 ? "31ff" : "e0031faa");
                caller.label("first"); caller.emit(nop);
                if (shape.equals("caller-branch")) { caller.emit(compare); caller.branch("afterCall", true); }
                // A temporary argument copy dies before the later real backup.
                // Retain the original carrier and do not select only that first copy.
                caller.emit(x86 ? "89df83e703" : "e003132a00040012");
                caller.call(0x2000); caller.label("afterCall");
                if (shape.equals("caller-loop")) { caller.emit(decrement); caller.branch("first", true); }
                if (shape.equals("caller-split")) {
                    caller.branch("right", false); caller.label("hole");
                    caller.emit(x86 ? "cccccc" : "000020d4"); caller.label("right");
                }
                caller.emit(nop + (x86 ? (bytes == 4 ? "4189dc" : "4989dc") : (bytes == 4 ? "f403132a" : "f40313aa")) + killFirst);
                caller.label("second"); caller.emit(nop); caller.call(0x2000);
                caller.emit(nop + (x86 ? (bytes == 4 ? "4589e5" : "4d89e5") : (bytes == 4 ? "f503142a" : "f50314aa")));
                caller.emit(x86 ? "4d31e4" : "f4031faa"); caller.label("third");
                caller.emit(nop); caller.call(0x2000); caller.emit(nop + (x86 ? "4d31ed" : "f5031faa"));
                caller.label("lost"); caller.emit(nop + ret);
                if (shape.equals("stack-retirement")) {
                    caller = new Code(x86, 0x1000);
                    caller.emit(x86 ? "4883ec20" : "ff8300d1");
                    caller.emit(x86 ? (bytes == 4 ? "897c2408" : "48897c2408") : (bytes == 4 ? "e00b00b9" : "e00700f9"));
                    caller.emit(x86 ? "31ff" : "e0031faa");
                    caller.label("first"); caller.emit(nop); caller.call(0x2000); caller.label("afterCall");
                    caller.emit(nop + (x86 ? (bytes == 4 ? "8b442408" : "488b442408") : (bytes == 4 ? "e00b40b9" : "e00740f9")));
                    caller.label("loaded"); caller.emit(nop + (x86 ? "4883c420" : "ff830091") + ret);
                }
                Function function = install(program, "caller", caller, shape.equals("caller-split"));
                var root = new Code(x86, 0x2000);
                root.emit(compare); root.branch("right", true);
                root.label("left"); root.emit(nop);
                if (shape.equals("clobber")) root.emit(killFirst);
                if (shape.equals("indirect")) root.emit(x86 ? "ffd0" : "00003fd6");
                if (shape.startsWith("nested")) root.call(0x3000);
                if (shape.equals("recursive")) root.call(0x2000);
                if (shape.equals("loop")) { root.emit(decrement); root.branch("left", true); }
                root.branch("join", false);
                root.label("hole");
                if (shape.equals("split") || shape.equals("undecoded")) root.emit(x86 ? "cccccc" : "000020d4");
                root.label("right"); root.emit(nop);
                root.label("join"); root.emit(nop + ret);
                Function callee = install(program, "root", root, shape.equals("split"));
                if (shape.startsWith("nested")) {
                    var nested = new Code(x86, 0x3000);
                    nested.emit(compare); nested.branch("end", true);
                    nested.emit(shape.equals("nested-clobber") ? killFirst : nop);
                    nested.label("end"); nested.emit(ret);
                    install(program, "nested", nested, false);
                }
                if (shape.equals("alternate")) program.getReferenceManager().addMemoryReference(
                    language.getDefaultSpace().getAddress(0x5000), language.getDefaultSpace().getAddress(0x2000 + root.at("left")),
                    RefType.UNCONDITIONAL_JUMP, SourceType.USER_DEFINED, 0);
                if (shape.equals("unknown-abi")) callee.setCallingConvention("unknown");
                var type = bytes == 4 ? IntegerDataType.dataType : LongLongDataType.dataType;
                function.replaceParameters(Function.FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED,
                    new ParameterImpl("value", type, program.getRegister(x86 ? (bytes == 4 ? "EDI" : "RDI") :
                        (bytes == 4 ? "w0" : "x0")), program, SourceType.USER_DEFINED));
                var instructions = new ArrayList<ghidra.program.model.listing.Instruction>();
                program.getListing().getInstructions(function.getBody(), true).forEach(instructions::add);
                var calls = DirectLeafCalls.inspect(program, instructions, TaskMonitor.DUMMY);
                boolean rejected = List.of("undecoded", "alternate", "indirect", "unknown-abi").contains(shape);
                require((calls == null) == rejected, "graph rejection " + context);
                var registers = TargetRegisterMap.forTarget(x86 ? "x86_64" : "aarch64");
                var parameter = function.getParameter(0);
                var original = GhidraVariableStorage.stableParameter(program, function, parameter, registers, TaskMonitor.DUMMY);
                var intervals = shape.startsWith("caller-") || shape.equals("stack-retirement") ? StackValueFlow.prove(program, function, parameter, registers, TaskMonitor.DUMMY) :
                    GhidraVariableStorage.parameterPrefix(program, function, parameter, registers, original, TaskMonitor.DUMMY);
                if (shape.equals("stack-retirement")) {
                    require(calls != null && calls.size() == 1, "stack call graph");
                    long before = 0x1000 + caller.at("first");
                    require(intervals.stream().anyMatch(i -> i.start() <= before && before < i.end() &&
                        i.storage() instanceof ghidradwarfforge.locations.VariableStorageModel.RegisterRelativeStorage), "pre-call stack fact " + context);
                    long after = 0x1000 + caller.at("afterCall");
                    require(intervals.stream().noneMatch(i -> i.end() > after && i.storage().available()),
                        "callee memory was assumed unchanged " + context + intervals);
                    return;
                }
                if (rejected) require(intervals.isEmpty(), "rejected graph escaped " + context);
                else {
                    boolean clobbered = shape.endsWith("clobber");
                    require(calls.size() == 3, "all calls " + context);
                    long lost = 0x1000 + caller.at(clobbered ? "afterCall" : "lost");
                    require(intervals.getLast().start() == lost && !intervals.getLast().storage().available(),
                        "loss boundary " + context + intervals);
                    int[] numbers = x86 ? new int[] { 3, 12, 13 } : new int[] { 19, 20, 21 };
                    for (int index = 0; index < (clobbered ? 1 : 3); index++) {
                        long address = 0x1000 + caller.at(List.of("first", "second", "third").get(index));
                        var interval = intervals.stream().filter(i -> i.start() <= address && address < i.end()).findFirst().orElseThrow();
                        require(interval.storage() instanceof RegisterStorage r && r.register().dwarfNumber() == numbers[index],
                            "handoff " + context + intervals);
                    }
                }
                var ranges = new ArrayList<ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange>();
                for (var range : function.getBody()) ranges.add(new ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionRange(
                    range.getMinAddress().getOffset(), range.getLength()));
                var model = GhidraTypeGraph.extract(program, List.of(new ghidradwarfforge.nativeapi.MinimalDwarfSidecarExporter.FunctionSymbol(
                    "caller", 0x1000, ranges)), x86 ? "x86_64" : "aarch64", 0, TaskMonitor.DUMMY, message -> { });
                var variable = model.variableStorage().variables().stream().filter(v -> v.name().equals("value")).findFirst().orElseThrow();
                long third = 0x1000 + caller.at("third");
                require(variable.locations().stream().anyMatch(r -> r.start() <= third && third < r.end() && r.storage().available()) ==
                    (!rejected && !shape.endsWith("clobber")), "public extraction " + context);
                var cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
                try { DirectLeafCalls.inspect(program, instructions, cancelled); throw new AssertionError("ignored cancellation"); }
                catch (CancelledException expected) { checks++; }
            }
            finally { program.endTransaction(transaction, true); }
        }
        finally { program.release(owner); }
    }

    private static Function install(ProgramDB program, String name, Code code, boolean split) throws Exception {
        byte[] bytes = code.bytes();
        var entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(code.base);
        var body = new AddressSet(entry, entry.add(bytes.length - 1));
        if (split) body.delete(entry.add(code.at("hole")), entry.add(code.at("right") - 1));
        var block = program.getMemory().createInitializedBlock(name, entry, bytes.length, (byte) 0, TaskMonitor.DUMMY, false);
        block.setExecute(true); program.getMemory().setBytes(entry, bytes);
        require(new DisassembleCommand(entry, body, true).applyTo(program, TaskMonitor.DUMMY), "decode " + name);
        var function = program.getFunctionManager().createFunction(name, entry, body, SourceType.USER_DEFINED);
        function.setCallingConvention(program.getCompilerSpec().getDefaultCallingConvention().getName());
        return function;
    }

    private static void require(boolean condition, String message) {
        checks++;
        if (!condition) throw new AssertionError(message);
    }

    private static final class Code {
        private record Branch(int start, String target, boolean conditional) {}
        private final boolean x86;
        private final long base;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final Map<String, Integer> labels = new LinkedHashMap<>();
        private final List<Branch> branches = new ArrayList<>();
        Code(boolean x86, long base) { this.x86 = x86; this.base = base; }
        void emit(String hex) { output.writeBytes(HexFormat.of().parseHex(hex)); }
        void label(String name) { if (labels.put(name, output.size()) != null) throw new AssertionError(name); }
        int at(String name) { return labels.get(name); }
        void call(long target) {
            int delta = Math.toIntExact(target - base - output.size());
            if (x86) { emit("e8"); output.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(delta - 5).array()); }
            else output.writeBytes(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(0x94000000 | ((delta >> 2) & 0x3ffffff)).array());
        }
        void branch(String target, boolean conditional) {
            branches.add(new Branch(output.size(), target, conditional));
            emit(x86 ? (conditional ? "0f8500000000" : "e900000000") : "00000000");
        }
        byte[] bytes() {
            byte[] result = output.toByteArray(); var buffer = ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN);
            for (var branch : branches) {
                int delta = at(branch.target()) - branch.start();
                if (x86) { int length = branch.conditional() ? 6 : 5; buffer.putInt(branch.start() + length - 4, delta - length); }
                else buffer.putInt(branch.start(), branch.conditional() ? 0x54000001 | (((delta >> 2) & 0x7ffff) << 5) : 0x14000000 | ((delta >> 2) & 0x3ffffff));
            }
            return result;
        }
    }
}
